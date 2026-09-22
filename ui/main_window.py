"""PySide6 main window: keyword box, process picker, Clean / persistence flows,
live log, progress bar, verification summary, cancel control.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
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
from ui.workers import CleanupWorker, MemoryWorker

_MAX_ACTION_PREVIEW = 30


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("string-wiper - live memory string scrubber")
        self.resize(620, 540)
        self.setMinimumSize(540, 430)

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

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        self.banner = QLabel()
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(
            "background-color:#fff3cd; border:1px solid #d4a017; padding:3px;"
        )
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        top = QFormLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setHorizontalSpacing(6)
        top.setVerticalSpacing(3)

        self.keywords_edit = QLineEdit()
        self.keywords_edit.setPlaceholderText(
            'comma-separated keywords, e.g.  madium, secret project'
        )
        top.addRow("Keywords:", self.keywords_edit)

        picker_row = QHBoxLayout()
        picker_row.setSpacing(4)
        self.process_combo = QComboBox()
        self.process_combo.setMinimumWidth(280)
        picker_row.addWidget(self.process_combo, 1)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setFixedWidth(64)
        self.refresh_btn.clicked.connect(self.refresh_processes)
        picker_row.addWidget(self.refresh_btn)
        top.addRow("Process:", picker_row)

        self.arch_label = QLabel("")
        self.arch_label.setWordWrap(True)
        self.arch_label.setStyleSheet("color:#444; font-size:11px;")
        top.addRow("Status:", self.arch_label)
        self.process_combo.currentIndexChanged.connect(self._on_selection_changed)
        root.addLayout(top)

        opts = QHBoxLayout()
        opts.setSpacing(10)
        self.chk_utf8 = QCheckBox("UTF-8 too")
        self.chk_utf8.setChecked(True)
        self.chk_utf8.setToolTip("Also match UTF-8 (multi-byte) encodings.")
        opts.addWidget(self.chk_utf8)
        self.chk_mapped = QCheckBox("MEM_MAPPED/MEM_IMAGE")
        self.chk_mapped.setToolTip(
            "DANGER: also scan MEM_MAPPED and MEM_IMAGE regions. Overwriting "
            "mapped files, constants or code can crash the target process."
        )
        self.chk_mapped.setStyleSheet("color:#a33;")
        opts.addWidget(self.chk_mapped)
        self.chk_restart = QCheckBox("Restart after clean")
        self.chk_restart.setToolTip(
            "Restart the target process after cleaning (taskkill /f /im + relaunch). "
            "A freshly started process can only reload from the already-cleaned "
            "registry/disk sources, so wiped strings cannot reappear."
        )
        opts.addWidget(self.chk_restart)
        opts.addStretch(1)
        root.addLayout(opts)

        buttons = QHBoxLayout()
        buttons.setSpacing(4)
        self.clean_btn = QPushButton("Clean memory")
        self.clean_btn.setDefault(True)
        self.clean_btn.clicked.connect(self._on_clean_clicked)
        buttons.addWidget(self.clean_btn)
        self.persist_btn = QPushButton("Clean persistence...")
        self.persist_btn.setToolTip(
            "ShellBags (BagMRU/Bags), TypedPaths, RunMRU, Recent Items and jump "
            "lists: identify keyword-matching entries, then delete only those "
            "after you confirm."
        )
        self.persist_btn.clicked.connect(self._on_persist_clicked)
        buttons.addWidget(self.persist_btn)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        buttons.addWidget(self.cancel_btn)
        root.addLayout(buttons)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        root.addWidget(self.progress_bar)

        self.summary_label = QLabel("Verification: (no run yet)")
        self.summary_label.setStyleSheet("font-weight: bold; font-size:11px;")
        root.addWidget(self.summary_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(50000)
        self.log_view.setPlaceholderText("live log...")
        self.log_view.setStyleSheet(
            "font-family: Consolas, 'Courier New', monospace; font-size:9px;"
        )
        root.addWidget(self.log_view, 1)

    # ------------------------------------------------------- startup checks

    def _append_log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{stamp}] {message}")

    def _startup_checks(self) -> None:
        self._append_log(f"[info] {privileges.architecture_summary()}")
        if not privileges.is_elevated():
            self.banner.setText(
                "Not running as Administrator. SeDebugPrivilege cannot be enabled and "
                "OpenProcess/WriteProcessMemory on protected processes will fail with "
                "access denied. Close this app and relaunch from an elevated terminal."
            )
            self.banner.setVisible(True)
            self._append_log(
                "[warning] process is not elevated - run as Administrator for full access."
            )
        ok, message = privileges.enable_debug_privilege()
        level = "[info]" if ok else "[warning]"
        self._append_log(f"{level} {message}")

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
            self.process_combo.addItem(f"{proc.name}  (PID {proc.pid}, {proc.arch})", proc)
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
            f"{info.name}: {len(pids)} PID(s) {pids}; architecture {info.arch}."
        )
        if note:
            text += f" {note}"
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

        option_bits = [f"encodings: ANSI + UTF-16LE{' + UTF-8' if self.chk_utf8.isChecked() else ''}"]
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
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
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
                    p for p in (get_process_path(pid) for pid in pids_for_name(info.name, self._processes)) if p
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
            return
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(min(done, total))

    @Slot(int, int)
    def _on_pass_update(self, pass_no: int, matches: int) -> None:
        self.statusBar().showMessage(f"pass {pass_no}: {matches} match(es)")

    @Slot(object)
    def _on_scrub_done(self, summary: object) -> None:
        if not isinstance(summary, ScrubSummary):
            self._append_log(f"[error] unexpected result type: {summary!r}")
            return
        self.summary_label.setText(
            f"Verification: {summary.matches_found} matches found -> "
            f"{summary.matches_remaining} matches remaining"
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
        QApplication.setOverrideCursor(Qt.WaitCursor)
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
        box.setIcon(QMessageBox.Warning)
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
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        deletable_box = None
        if deletable:
            deletable_box = QCheckBox(
                f"Also DELETE the {len(deletable)} reported on-disk item(s) "
                "(real files/shortcuts!)"
            )
            box.setCheckBox(deletable_box)
        if box.exec() != QMessageBox.Yes:
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
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if answer == QMessageBox.Yes:
            self._append_log(f"[restart] restarting {name}...")
            self._start_cleanup_worker([], name, self._last_paths)
        else:
            self._append_log("[restart] declined by user.")
