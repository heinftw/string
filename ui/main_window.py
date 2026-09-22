"""PySide6 main window: mockup-matched dark UI over the string-wiper engine.

Layout (top to bottom): custom title bar, KEYWORDS / PROCESS / STATUS / OPTIONS
rows as cards, action buttons, PROGRESS row, VERIFICATION card (colored live
log), footer status strip.  The window is frameless with native-style move via
the title bar and edge resize via WM_NCHITTEST on Windows.
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import List, Optional

from PySide6.QtCore import QPoint, QSize, Qt, QThread, Slot
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import persistence, privileges
from core.matching import parse_keywords, short_keyword_notes
from core.persistence import PendingAction
from core.processes import ProcessInfo, enumerate_processes, get_process_path, pids_for_name
from core.wiper import ScrubSummary
from ui import icons, theme
from ui.chrome import TitleBar
from ui.workers import CleanupWorker, MemoryWorker

_MAX_ACTION_PREVIEW = 30
_LOG_MAX_BLOCKS = 20000
_LABEL_WIDTH = 96

_TAG_COLORS = {
    "info": theme.GREEN,
    "summary": theme.GREEN,
    "warning": theme.YELLOW,
    "warn": theme.YELLOW,
    "note": theme.YELLOW,
    "error": theme.RED,
}


def _row_label(text: str) -> QLabel:
    label = QLabel(
        f"{text} <span style='color:{theme.ACCENT}'>»</span>"
    )
    label.setObjectName("rowLabel")
    label.setTextFormat(Qt.TextFormat.RichText)
    label.setFixedWidth(_LABEL_WIDTH)
    label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    return label


def _card_row(label_text: str, *widgets: QWidget) -> QFrame:
    card = QFrame()
    card.setObjectName("card")
    row = QHBoxLayout(card)
    row.setContentsMargins(12, 8, 12, 8)
    row.setSpacing(8)
    row.addWidget(_row_label(label_text))
    for widget in widgets:
        row.addWidget(widget, 1)
    return card


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("string-wiper")
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setWindowIcon(icons.chip_logo(30))
        self._fit_screen()

        self._processes: List[ProcessInfo] = []
        self._thread: Optional[QThread] = None
        self._worker = None
        self._last_keywords: List[str] = []
        self._last_name: str = ""
        self._last_paths: List[str] = []
        self._running = False

        self._build_ui()
        self._startup_checks()
        self.refresh_processes()

    def _fit_screen(self) -> None:
        """Size the window as a compact desktop panel, never filling the screen.

        The default 860x700 (min 600x520) is clamped to 80%/85% of the
        available work area, so DPI-scaled or small displays still show the
        desktop around the app and every control stays visible.
        """
        screen = QApplication.primaryScreen()
        if screen is None:
            self.setMinimumSize(600, 520)
            self.resize(860, 700)
            return
        avail = screen.availableGeometry()
        self.resize(min(860, int(avail.width() * 0.80)),
                    min(700, int(avail.height() * 0.85)))
        self.setMinimumSize(min(600, int(avail.width() * 0.50)),
                            min(520, int(avail.height() * 0.55)))

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        frame = QFrame()
        frame.setObjectName("windowFrame")
        self.setCentralWidget(frame)
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)

        self.title_bar = TitleBar()
        self.title_bar.request_minimize.connect(self.showMinimized)
        self.title_bar.request_maximize.connect(self._toggle_maximize)
        self.title_bar.request_close.connect(self.close)
        outer.addWidget(self.title_bar)

        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(12, 4, 12, 8)
        root.setSpacing(7)
        outer.addWidget(content, 1)

        # banner (hidden unless the process is not elevated)
        self.banner = QLabel()
        self.banner.setObjectName("bannerCard")
        self.banner.setWordWrap(True)
        self.banner.setTextFormat(Qt.TextFormat.RichText)
        self.banner.setContentsMargins(10, 8, 10, 8)
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        # KEYWORDS
        self.keywords_edit = QLineEdit()
        self.keywords_edit.setPlaceholderText(
            "Comma-separated keywords, e.g. madium, secret project"
        )
        root.addWidget(_card_row("KEYWORDS", self.keywords_edit))

        # PROCESS
        self.process_combo = QComboBox()
        self.process_combo.setMinimumWidth(220)
        self.refresh_btn = QPushButton("REFRESH")
        self.refresh_btn.setObjectName("refreshBtn")
        self.refresh_btn.setIcon(icons.refresh())
        self.refresh_btn.setIconSize(QSize(14, 14))
        self.refresh_btn.clicked.connect(self.refresh_processes)
        self.process_combo.currentIndexChanged.connect(self._on_selection_changed)
        proc_row = QWidget()
        proc_layout = QHBoxLayout(proc_row)
        proc_layout.setContentsMargins(0, 0, 0, 0)
        proc_layout.setSpacing(12)
        proc_layout.addWidget(self.process_combo, 1)
        proc_layout.addWidget(self.refresh_btn, 0)
        root.addWidget(_card_row("PROCESS", proc_row))

        # STATUS
        self.arch_label = QLabel("")
        self.arch_label.setTextFormat(Qt.TextFormat.RichText)
        self.arch_label.setWordWrap(True)
        root.addWidget(_card_row("STATUS", self.arch_label))

        # OPTIONS
        self.chk_utf8 = QCheckBox("UTF-8 TOO")
        self.chk_utf8.setChecked(True)
        self.chk_utf8.setToolTip("Also match UTF-8 (multi-byte) encodings.")
        self.chk_mapped = QCheckBox("MEM_MAPPED/MEM_IMAGE")
        self.chk_mapped.setObjectName("dangerCheck")
        self.chk_mapped.setToolTip(
            "DANGER: also scan MEM_MAPPED and MEM_IMAGE regions. Overwriting "
            "mapped files, constants or code can crash the target process."
        )
        self.chk_mapped.toggled.connect(self._update_footer_mode)
        self.chk_restart = QCheckBox("RESTART AFTER CLEAN")
        self.chk_restart.setToolTip(
            "Restart the target process after cleaning (taskkill /f /im + relaunch). "
            "A freshly started process can only reload from the already-cleaned "
            "sources, so wiped strings cannot reappear."
        )
        options_row = QWidget()
        options_layout = QHBoxLayout(options_row)
        options_layout.setContentsMargins(0, 0, 0, 0)
        options_layout.setSpacing(24)
        options_layout.addWidget(self.chk_utf8)
        options_layout.addWidget(self.chk_mapped)
        options_layout.addWidget(self.chk_restart)
        options_layout.addStretch(1)
        root.addWidget(_card_row("OPTIONS", options_row))

        # action buttons
        buttons = QHBoxLayout()
        buttons.setSpacing(12)
        self.clean_btn = QPushButton("CLEAN MEMORY")
        self.clean_btn.setObjectName("cleanBtn")
        self.clean_btn.setIcon(icons.broom())
        self.clean_btn.setIconSize(QSize(16, 16))
        self.clean_btn.setMinimumHeight(40)
        self.clean_btn.setDefault(True)
        self.clean_btn.clicked.connect(self._on_clean_clicked)
        buttons.addWidget(self.clean_btn, 4)
        self.persist_btn = QPushButton("CLEAN PERSISTENCE...")
        self.persist_btn.setIcon(icons.database())
        self.persist_btn.setIconSize(QSize(16, 16))
        self.persist_btn.setMinimumHeight(40)
        self.persist_btn.setToolTip(
            "ShellBags, TypedPaths, RunMRU, RecentDocs, ComDlg32 MRUs, "
            "WordWheelQuery, Recent Items and jump lists: identify keyword-matching "
            "entries and re-injection sources, then delete only what you confirm."
        )
        self.persist_btn.clicked.connect(self._on_persist_clicked)
        buttons.addWidget(self.persist_btn, 4)
        self.cancel_btn = QPushButton("CANCEL")
        self.cancel_btn.setIcon(icons.x_circle())
        self.cancel_btn.setIconSize(QSize(16, 16))
        self.cancel_btn.setMinimumHeight(40)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        buttons.addWidget(self.cancel_btn, 3)
        root.addLayout(buttons)

        # PROGRESS row
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_pct = QLabel("0%")
        self.progress_pct.setObjectName("progressPct")
        self.progress_pct.setFixedWidth(42)
        self.progress_pct.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        prog_row = QWidget()
        prog_layout = QHBoxLayout(prog_row)
        prog_layout.setContentsMargins(0, 2, 0, 2)
        prog_layout.setSpacing(8)
        prog_layout.addWidget(self.progress_bar, 1)
        prog_layout.addWidget(self.progress_pct)
        root.addWidget(_card_row("PROGRESS", prog_row))

        # VERIFICATION card (summary + live log)
        verify = QFrame()
        verify.setObjectName("card")
        verify_layout = QVBoxLayout(verify)
        verify_layout.setContentsMargins(12, 8, 12, 10)
        verify_layout.setSpacing(6)
        verify_header = QHBoxLayout()
        verify_header.setSpacing(6)
        shield_label = QLabel()
        shield_label.setPixmap(icons.shield().pixmap(14, 14))
        shield_label.setFixedSize(14, 14)
        verify_header.addWidget(shield_label)
        self.summary_label = QLabel("VERIFICATION (NO RUN YET)")
        self.summary_label.setObjectName("verifyHeader")
        self.summary_label.setTextFormat(Qt.TextFormat.RichText)
        verify_header.addWidget(self.summary_label)
        verify_header.addStretch(1)
        self.clear_log_btn = QPushButton("CLEAR LOG")
        self.clear_log_btn.setObjectName("clearLogBtn")
        self.clear_log_btn.setIcon(icons.trash())
        self.clear_log_btn.setIconSize(QSize(12, 12))
        self.clear_log_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_log_btn.clicked.connect(self._on_clear_log)
        verify_header.addWidget(self.clear_log_btn)
        verify_layout.addLayout(verify_header)
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("logView")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(_LOG_MAX_BLOCKS)
        self.log_view.setPlaceholderText("live log...")
        verify_layout.addWidget(self.log_view, 1)
        root.addWidget(verify, 1)

        # footer strip
        rule = QFrame()
        rule.setObjectName("footerRule")
        rule.setFixedHeight(1)
        outer.addWidget(rule)
        footer = QWidget()
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(12, 5, 12, 7)
        footer_layout.setSpacing(6)

        mode_wrap = QHBoxLayout()
        mode_wrap.setSpacing(6)
        self.footer_mode_icon = QLabel()
        self.footer_mode_icon.setPixmap(icons.shield(theme.ACCENT_SOFT, 13).pixmap(13, 13))
        self.footer_mode_icon.setFixedSize(13, 13)
        self.footer_mode = QLabel("SAFE MODE")
        self.footer_mode.setObjectName("footerLabel")
        mode_wrap.addWidget(self.footer_mode_icon)
        mode_wrap.addWidget(self.footer_mode)
        footer_layout.addLayout(mode_wrap)
        footer_layout.addStretch(1)

        arch_wrap = QHBoxLayout()
        arch_wrap.setSpacing(6)
        self.footer_arch_icon = QLabel()
        self.footer_arch_icon.setPixmap(icons.memory_chip(theme.TEXT_DIM, 13).pixmap(13, 13))
        self.footer_arch_icon.setFixedSize(13, 13)
        self.footer_arch = QLabel("X64 ARCHITECTURE")
        self.footer_arch.setObjectName("footerLabel")
        arch_wrap.addWidget(self.footer_arch_icon)
        arch_wrap.addWidget(self.footer_arch)
        footer_layout.addLayout(arch_wrap)
        footer_layout.addStretch(1)

        access_wrap = QHBoxLayout()
        access_wrap.setSpacing(6)
        self.footer_access_icon = QLabel()
        self.footer_access_icon.setPixmap(icons.memory_chip(theme.GREEN, 13).pixmap(13, 13))
        self.footer_access_icon.setFixedSize(13, 13)
        self.footer_access_prefix = QLabel("MEMORY ACCESS:")
        self.footer_access_prefix.setObjectName("footerLabel")
        self.footer_access = QLabel("ENABLED")
        self.footer_access.setObjectName("footerValueOk")
        access_wrap.addWidget(self.footer_access_icon)
        access_wrap.addWidget(self.footer_access_prefix)
        access_wrap.addWidget(self.footer_access)
        footer_layout.addLayout(access_wrap)
        outer.addWidget(footer)

    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        self.title_bar.sync_maximize_icon(self.isMaximized())

    def _on_clear_log(self) -> None:
        self.log_view.clear()

    def _update_footer_mode(self, checked: bool) -> None:
        if checked:
            self.footer_mode.setText("DANGER MODE")
            self.footer_mode.setStyleSheet(f"color: {theme.RED}; font-size: 9px; font-weight: 700; letter-spacing: 1px;")
            self.footer_mode_icon.setPixmap(icons.shield(theme.RED, 13).pixmap(13, 13))
        else:
            self.footer_mode.setText("SAFE MODE")
            self.footer_mode.setStyleSheet("")
            self.footer_mode_icon.setPixmap(icons.shield(theme.ACCENT_SOFT, 13).pixmap(13, 13))

    # ---------------------------------------------- frameless window handling

    def nativeEvent(self, event_type, message):  # noqa: N802 - Qt API
        """WM_NCHITTEST: edge resize + caption drag outside interactive widgets."""
        if sys.platform != "win32":
            return super().nativeEvent(event_type, message)
        try:
            import ctypes.wintypes

            msg = ctypes.wintypes.MSG.from_address(int(message))
            x, y = msg.pt.x, msg.pt.y
        except Exception:
            return super().nativeEvent(event_type, message)
        try:
            local = self.mapFromGlobal(QPoint(x, y))
        except Exception:
            return super().nativeEvent(event_type, message)

        if self.isMaximized():
            in_title = local.y() < self.title_bar.height()
            if in_title and self._is_interactive(self.childAt(local)):
                return False, 0
            return (True, 2) if in_title else (False, 0)  # HTCAPTION=2

        edge = 8
        left = local.x() < edge
        right = local.x() > self.width() - edge
        top = local.y() < edge
        bottom = local.y() > self.height() - edge
        ht = 0
        if left and top:
            ht = 13  # HTTOPLEFT
        elif right and top:
            ht = 14  # HTTOPRIGHT
        elif left and bottom:
            ht = 16  # HTBOTTOMLEFT
        elif right and bottom:
            ht = 17  # HTBOTTOMRIGHT
        elif left:
            ht = 10  # HTLEFT
        elif right:
            ht = 11  # HTRIGHT
        elif top:
            ht = 12  # HTTOP
        elif bottom:
            ht = 15  # HTBOTTOM
        if ht:
            return True, ht
        if local.y() < self.title_bar.height() and not self._is_interactive(self.childAt(local)):
            return True, 2  # HTCAPTION
        return False, 0

    @staticmethod
    def _is_interactive(widget) -> bool:
        from PySide6.QtWidgets import QAbstractButton, QComboBox, QLineEdit, QPlainTextEdit

        return isinstance(widget, (QAbstractButton, QComboBox, QLineEdit, QPlainTextEdit))

    # ------------------------------------------------------- startup checks

    def _append_log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        text = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        tag_text = ""
        body = text
        if text.startswith("[") and "]" in text:
            close = text.index("]")
            tag_text = text[: close + 1]
            body = text[close + 1 :]
            tag_name = tag_text.strip("[]").split()[0].casefold() if tag_text != "[]" else ""
            tag_color = _TAG_COLORS.get(tag_name, theme.ACCENT_SOFT)
            tag_html = f"<span style='color:{tag_color}'>{tag_text}</span>"
        else:
            tag_html = ""
        html = (
            f"<p style='margin:0; text-indent:-62px; margin-left:62px'>"
            f"<span style='color:{theme.TEXT_MUTED}'>[{stamp}]</span> {tag_html}"
            f"<span style='color:{theme.TEXT}'>{body}</span></p>"
        )
        self.log_view.appendHtml(html)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)

    def _startup_checks(self) -> None:
        self._append_log(f"[info] {privileges.architecture_summary()}")
        native = privileges.native_arch()
        self.footer_arch.setText(f"{native} ARCHITECTURE")
        if not privileges.is_elevated():
            self.banner.setText(
                f"<b style='color:{theme.RED_SOFT}'>Not running as Administrator.</b> "
                "SeDebugPrivilege cannot be enabled and OpenProcess/WriteProcessMemory "
                "on protected processes will fail with access denied. Close this app "
                "and relaunch from an elevated terminal."
            )
            self.banner.setVisible(True)
            self._append_log(
                "[warning] process is not elevated - run as Administrator for full access."
            )
        ok, message = privileges.enable_debug_privilege()
        level = "[info]" if ok else "[warning]"
        self._append_log(f"{level} {message}")
        access_ok = ok and privileges.is_elevated()
        self.footer_access.setText("ENABLED" if access_ok else "LIMITED")
        self.footer_access.setObjectName("footerValueOk" if access_ok else "footerValueBad")
        self.footer_access.setStyleSheet("")

    # -------------------------------------------------------- process picker

    @Slot()
    def refresh_processes(self) -> None:
        previous = self._current_name()
        self.process_combo.blockSignals(True)
        self.process_combo.clear()
        try:
            self._processes = enumerate_processes()
        except OSError as exc:
            self.process_combo.blockSignals(False)
            self._append_log(f"[error] process enumeration failed: {exc}")
            QMessageBox.critical(self, "Process enumeration failed", str(exc))
            return
        self._processes.sort(key=lambda p: (p.name.casefold(), p.pid))
        for proc in self._processes:
            self.process_combo.addItem(
                f"{proc.name} (PID {proc.pid}, {proc.arch})", proc
            )
        select = 0
        want = previous or "explorer.exe"
        for idx, proc in enumerate(self._processes):
            if proc.name.casefold() == want.casefold():
                select = idx
                break
        if self._processes:
            self.process_combo.setCurrentIndex(select)
        self.process_combo.blockSignals(False)
        self._on_selection_changed()
        self._append_log(f"[info] process list refreshed: {len(self._processes)} process(es).")

    def _current_info(self) -> Optional[ProcessInfo]:
        data = self.process_combo.currentData()
        return data if isinstance(data, ProcessInfo) else None

    def _current_name(self) -> str:
        info = self._current_info()
        return info.name if info else ""

    @Slot()
    def _on_selection_changed(self) -> None:
        info = self._current_info()
        if info is None:
            self.arch_label.setText("")
            self.clean_btn.setEnabled(not self._running)
            return
        pids = pids_for_name(info.name, self._processes)
        ok, note = privileges.arch_compatibility(info.arch)
        text = (
            f"<span style='color:#ffffff; font-weight:600'>{info.name}</span>"
            f"<span style='color:{theme.TEXT_MUTED}'> | </span>"
            f"<span style='color:{theme.ACCENT_SOFT}'>PID(s) {pids}</span>"
            f"<span style='color:{theme.TEXT_MUTED}'> | </span>"
            f"<span style='color:{theme.ACCENT_SOFT}'>architecture {info.arch}.</span>"
        )
        if note:
            color = theme.RED_SOFT if not ok else theme.YELLOW
            text += f" <span style='color:{color}'>{note}</span>"
        self.arch_label.setText(text)
        self.clean_btn.setEnabled(not self._running and ok)
        if not ok:
            self._append_log(f"[warning] {note}")

    # ------------------------------------------------------- button handlers

    @Slot()
    def _on_clean_clicked(self) -> None:
        keywords = parse_keywords(self.keywords_edit.text())
        if not keywords:
            QMessageBox.warning(
                self,
                "No keywords",
                "Enter at least one non-empty keyword (comma-separated). "
                "Whitespace-only segments are rejected.",
            )
            return
        info = self._current_info()
        if info is None:
            QMessageBox.warning(self, "No target", "Select a target process first.")
            return
        pids = pids_for_name(info.name, self._processes)
        if not pids:
            QMessageBox.warning(
                self,
                "Target gone",
                f"No running process named '{info.name}'. Refresh the list and try again.",
            )
            return
        for proc in self._processes:
            if proc.pid in pids:
                ok, note = privileges.arch_compatibility(proc.arch)
                if not ok:
                    QMessageBox.critical(self, "Architecture mismatch", note or "")
                    return

        option_bits = [
            f"encodings: ANSI + UTF-16LE{' + UTF-8' if self.chk_utf8.isChecked() else ''}"
        ]
        if self.chk_mapped.isChecked():
            option_bits.append("regions: MEM_PRIVATE + MEM_MAPPED + MEM_IMAGE (DANGER)")
        else:
            option_bits.append("regions: MEM_PRIVATE (heaps) only")
        if self.chk_restart.isChecked():
            option_bits.append("restart after cleaning: yes (taskkill /f + relaunch)")
        danger = (
            "\n\nWARNING: MEM_MAPPED/MEM_IMAGE is enabled. Overwriting mapped files, "
            "image constants or code can crash the target process."
            if self.chk_mapped.isChecked()
            else ""
        )
        answer = QMessageBox.question(
            self,
            "Confirm memory writes",
            "This will overwrite bytes IN PLACE inside the target process memory "
            "(null bytes, exact same length; no free/resize). Heap data containing "
            "the keywords becomes unrecoverable in that process.\n\n"
            f"Keywords: {', '.join(keywords)}\n"
            f"Target:   {info.name}  PIDs: {pids}\n"
            f"{' | '.join(option_bits)}"
            f"{danger}\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self._append_log("[info] memory wipe cancelled at confirmation dialog.")
            return

        self._last_keywords = keywords
        self._last_name = info.name
        self._last_paths = [p for p in (get_process_path(pid) for pid in pids) if p]
        for note in short_keyword_notes(keywords):
            self._append_log(f"[note] {note}")

        self._append_log(
            f"[start] memory scrub: keywords={keywords} target={info.name} pids={pids}"
        )
        self._start_memory_worker(pids, keywords)

    @Slot()
    def _on_persist_clicked(self) -> None:
        keywords = parse_keywords(self.keywords_edit.text())
        if not keywords:
            QMessageBox.warning(
                self,
                "No keywords",
                "Enter at least one non-empty keyword (comma-separated).",
            )
            return
        self._last_keywords = keywords
        if not self._last_name:
            info = self._current_info()
            if info is not None:
                self._last_name = info.name
                self._last_paths = [
                    p
                    for p in (get_process_path(pid) for pid in pids_for_name(info.name, self._processes))
                    if p
                ]
        self._start_persistence_flow()

    @Slot()
    def _on_cancel_clicked(self) -> None:
        self._append_log("[cancel] cancel requested from UI...")
        if self._worker is not None and hasattr(self._worker, "request_cancel"):
            self._worker.request_cancel()
        self.cancel_btn.setEnabled(False)

    # ---------------------------------------------------------- worker glue

    def _set_running(self, running: bool) -> None:
        self._running = running
        self.clean_btn.setEnabled(not running)
        self.persist_btn.setEnabled(not running)
        self.refresh_btn.setEnabled(not running)
        self.process_combo.setEnabled(not running)
        self.keywords_edit.setEnabled(not running)
        self.chk_mapped.setEnabled(not running)
        self.chk_utf8.setEnabled(not running)
        self.chk_restart.setEnabled(not running)
        self.cancel_btn.setEnabled(running)
        if not running:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(0)
            self.progress_pct.setText("0%")

    def _launch_worker(self, thread: QThread, worker, done_slot) -> None:
        """Common QThread wiring: run on start, quit on done/fail, teardown-safe.

        The finished handler only releases UI state when *this* thread is still
        the active one, so a follow-up worker started inside a done slot is
        never clobbered by the previous thread's late teardown.
        """
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.log.connect(self._append_log)
        worker.progress.connect(self._on_progress)
        worker.completed.connect(done_slot)
        worker.failed.connect(self._on_scrub_failed)
        worker.completed.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        def _finished(thread=thread):
            if self._thread is thread:
                self._worker = None
                self._thread = None
                self._set_running(False)

        thread.finished.connect(_finished)
        self._thread = thread
        self._worker = worker
        self._set_running(True)
        thread.start()

    def _start_memory_worker(self, pids: List[int], keywords: List[str]) -> None:
        thread = QThread(self)
        worker = MemoryWorker(
            pids,
            keywords,
            self.chk_mapped.isChecked(),
            self.chk_utf8.isChecked(),
        )
        worker.pass_update.connect(self._on_pass_update)
        self._launch_worker(thread, worker, self._on_scrub_done)

    def _start_cleanup_worker(
        self,
        actions: List[PendingAction],
        restart_name: Optional[str],
        restart_paths: List[str],
    ) -> None:
        thread = QThread(self)
        worker = CleanupWorker(actions, restart_name, restart_paths)
        self._launch_worker(thread, worker, self._on_cleanup_done)

    @Slot(int, int)
    def _on_progress(self, done: int, total: int) -> None:
        if total <= 0:
            self.progress_bar.setRange(0, 0)
            self.progress_pct.setText("...")
            return
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(min(done, total))
        pct = int(min(done, total) * 100 / total) if total else 0
        self.progress_pct.setText(f"{pct}%")

    @Slot(int, int)
    def _on_pass_update(self, pass_no: int, matches: int) -> None:
        self.summary_label.setText(
            f"VERIFICATION (SCAN {pass_no}: {matches} MATCHES)"
        )

    @Slot(object)
    def _on_scrub_done(self, summary: object) -> None:
        if not isinstance(summary, ScrubSummary):
            self._append_log(f"[error] unexpected result type: {summary!r}")
            return
        self.summary_label.setText(
            f"VERIFICATION ({summary.matches_found} FOUND &#8594; "
            f"{summary.matches_remaining} REMAINING)"
        )
        self._append_log(
            f"[summary] matches found -> matches remaining: "
            f"{summary.matches_found} -> {summary.matches_remaining}"
        )
        self._append_log(
            f"[summary] passes run: {summary.passes_run}; matches per pass: "
            f"{summary.matches_per_pass}; spans wiped and verified: {summary.spans_wiped}"
        )
        if summary.wipe_failures:
            self._append_log(
                f"[warning] {len(summary.wipe_failures)} wipe span(s) failed and were "
                f"skipped: {summary.wipe_failures}"
            )
        if summary.process_died:
            self._append_log(
                f"[warning] target PID(s) {summary.process_died} exited mid-scrub - "
                "results are partial. Use the persistence cleanup + restart flow to "
                "finish the job."
            )
        if summary.open_failures:
            self._append_log(
                f"[warning] {len(summary.open_failures)} process(es) could not be opened."
            )
        if summary.cancelled:
            self._append_log("[summary] run cancelled - partial results shown above.")
            return
        if not summary.opened:
            self._append_log("[summary] no process was opened - nothing to clean.")
            return
        self._start_persistence_flow()

    @Slot(object)
    def _on_cleanup_done(self, results: object) -> None:
        results = list(results or [])
        ok_count = sum(1 for r in results if r.ok)
        fail_count = len(results) - ok_count
        self._append_log(
            f"[summary] persistence cleanup: {ok_count} item(s) removed/updated, "
            f"{fail_count} failure(s)."
        )

    @Slot(str)
    def _on_scrub_failed(self, message: str) -> None:
        self._append_log(f"[error] {message}")

    # ----------------------------------------------------- persistence flow

    def _start_persistence_flow(self) -> None:
        keywords = self._last_keywords
        if not keywords:
            self._append_log("[persistence] no keywords in effect - scan skipped.")
            return
        self._append_log(
            "[persistence] scanning ShellBags (BagMRU/Bags), TypedPaths, RunMRU, "
            "RecentDocs, ComDlg32 MRUs, WordWheelQuery, Recent Items, jump lists, "
            "shell-visible files and window titles (read-only)..."
        )
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            scan = persistence.scan_persistence(
                keywords, include_utf8=self.chk_utf8.isChecked()
            )
        except OSError as exc:
            QApplication.restoreOverrideCursor()
            self._append_log(f"[persistence] scan failed: {exc}")
            return
        except Exception as exc:  # surface everything
            QApplication.restoreOverrideCursor()
            self._append_log(f"[persistence] scan failed: {type(exc).__name__}: {exc}")
            return
        QApplication.restoreOverrideCursor()

        actions = list(scan.actions)
        reports = list(scan.reports)
        deletable = [rep for rep in reports if rep.deletable and rep.action is not None]
        for rep in reports:
            self._append_log(f"[reinject] {rep.source} at {rep.location}: {rep.detail}")

        if not actions and not deletable and not reports:
            self._append_log(
                "[persistence] scan: no keyword-matching entries and no re-injection "
                "sources found."
            )
            self._maybe_offer_restart(sources_cleaned=True)
            return

        preview = []
        for action in actions[:_MAX_ACTION_PREVIEW]:
            suffix = f"  [!] {action.warning}" if action.warning else ""
            preview.append(
                f"DELETE {action.kind}: {action.path}\\{action.name}  (matched "
                f"{action.matched_keyword!r}) - {action.detail}{suffix}"
            )
        if len(actions) > _MAX_ACTION_PREVIEW:
            preview.append(
                f"... and {len(actions) - _MAX_ACTION_PREVIEW} more (see details)"
            )
        for rep in deletable:
            preview.append(
                f"OPTIONAL {rep.source}: {rep.location}  (matched {rep.matched_keyword!r}) - {rep.detail}"
            )
        for rep in reports:
            if not (rep.deletable and rep.action is not None):
                preview.append(f"REPORT-ONLY {rep.source}: {rep.location} - {rep.detail}")

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Confirm persistence cleanup")
        box.setText(
            f"Found {len(actions)} keyword-matching persistence item(s) and "
            f"{len(reports)} re-injection source(s). Cleaning is required so the "
            "strings cannot come back after explorer.exe restarts or the PC reboots "
            "(RAM is cleared on reboot; what returns is reloaded from these "
            "registry/disk/window sources).\n\n"
            "Standard cleanup removes ONLY keyword-matching entries:\n"
            "- ShellBags (BagMRU/Bags): matching entry/node/bag - resets folder view "
            "settings for the affected paths.\n"
            "- MRU lists (TypedPaths, RunMRU + MRUList, RecentDocs, ComDlg32, "
            "WordWheelQuery + MRUListEx): matching values only.\n"
            "- Recent Items .lnk: matching shortcuts only.\n"
            "- Jump lists: the whole file is deleted (format cannot be edited per "
            "entry safely), removing that application's OTHER entries too.\n"
            "\nRe-injection sources (listed below) keep the strings alive: files "
            "Explorer re-parses (name/metadata) and window titles the taskbar "
            "re-imports on every start. Tick the box to delete the on-disk items "
            "too; window titles require closing the owning application.\n"
        )
        if self.chk_restart.isChecked():
            box.setText(
                box.text()
                + f"\nAfter cleanup, {self._last_name or 'the target'} would be killed "
                "(taskkill /f /im) and relaunched - skipped automatically while any "
                "re-injection source remains."
            )
        box.setInformativeText("Delete the standard cleanup entries now?")
        box.setDetailedText("\n".join(preview))
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        deletable_box = None
        if deletable:
            deletable_box = QCheckBox(
                f"Also DELETE the {len(deletable)} reported on-disk item(s) "
                "(real files/shortcuts!)"
            )
            box.setCheckBox(deletable_box)
        if box.exec() != QMessageBox.StandardButton.Yes:
            self._append_log(
                "[persistence] cleanup declined by user. NOTE: restart is skipped too "
                "- restarting without cleaning the sources would reload the original "
                "strings from disk/registry into the new process."
            )
            return

        checked = deletable_box is not None and deletable_box.isChecked()
        extra = [rep.action for rep in deletable] if checked else []
        remaining_reports = [
            rep for rep in reports if not (checked and rep.deletable and rep.action is not None)
        ]
        final_actions = actions + extra
        if not final_actions:
            self._append_log("[persistence] nothing selected for deletion.")
            if remaining_reports:
                self._append_log(
                    "[restart] skipped: re-injection source(s) remain (see [reinject] "
                    "lines) - a restart would reload the original strings."
                )
            else:
                self._maybe_offer_restart(sources_cleaned=True)
            return

        restart_name = None
        if self.chk_restart.isChecked():
            if remaining_reports:
                self._append_log(
                    f"[restart] skipped: {len(remaining_reports)} re-injection "
                    "source(s) remain (see [reinject] lines) - close/delete them, then "
                    "re-run so the restarted process cannot reload the strings."
                )
            else:
                restart_name = self._last_name
        for action in final_actions:
            self._append_log(f"[persistence] confirmed: {action.detail}")
        self._append_log(f"[persistence] executing {len(final_actions)} action(s)...")
        self._start_cleanup_worker(final_actions, restart_name, self._last_paths)

    def _maybe_offer_restart(self, sources_cleaned: bool) -> None:
        if not self.chk_restart.isChecked():
            return
        name = self._last_name
        if not name:
            return
        if not sources_cleaned:
            self._append_log(
                "[restart] skipped: persistence sources were not cleaned, so a restart "
                "would reload the original strings from disk/registry."
            )
            return
        answer = QMessageBox.question(
            self,
            "Restart target process",
            f"Restart {name} now (taskkill /f /im + relaunch)?\n\n"
            "A freshly started process can only rebuild its strings from the "
            "already-cleaned registry/disk sources, so the wiped strings cannot "
            "reappear. Verify afterwards with Process Hacker (Properties > Memory > "
            "Strings).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._append_log(f"[restart] restarting {name}...")
            self._start_cleanup_worker([], name, self._last_paths)
        else:
            self._append_log("[restart] declined by user.")
