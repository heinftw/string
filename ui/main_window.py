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
    QGroupBox,
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
        self.resize(900, 720)

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

        self.banner = QLabel()
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(
            "background-color:#fff3cd; border:1px solid #d4a017; padding:6px;"
        )
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        targets = QGroupBox("Target")
        form = QFormLayout(targets)

        self.keywords_edit = QLineEdit()
        self.keywords_edit.setPlaceholderText(
            'comma-separated keywords, e.g.  madium, secret project'
        )
        form.addRow("Keywords:", self.keywords_edit)

        picker_row = QHBoxLayout()
        self.process_combo = QComboBox()
        self.process_combo.setMinimumWidth(420)
        picker_row.addWidget(self.process_combo, 1)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        picker_row.addWidget(self.refresh_btn)
        form.addRow("Process:", picker_row)

        self.arch_label = QLabel("")
        self.arch_label.setWordWrap(True)
        form.addRow("Status:", self.arch_label)
        self.process_combo.currentIndexChanged.connect(self._on_selection_changed)

        root.addWidget(targets)

        options = QGroupBox("Options")
        opt_layout = QVBoxLayout(options)
        self.chk_mapped = QCheckBox(
            "Include MEM_MAPPED / MEM_IMAGE regions (DANGER: overwriting mapped "
            "files, constants or code can crash the target process)"
        )
        opt_layout.addWidget(self.chk_mapped)
        self.chk_utf8 = QCheckBox("Also match UTF-8 (multi-byte) encodings")
        self.chk_utf8.setChecked(True)
        opt_layout.addWidget(self.chk_utf8)
        self.chk_restart = QCheckBox(
            "Restart target process after cleaning (taskkill /f /im + relaunch). "
            "A freshly started process can only reload from the already-cleaned "
            "registry/disk sources, so wiped strings cannot reappear."
        )
        self.chk_restart.setToolTip(
            "taskkill /f /im <name> followed by relaunch. For explorer.exe this starts "
            "a fresh shell which rebuilds its strings from the cleaned sources."
        )
        opt_layout.addWidget(self.chk_restart)
        root.addWidget(options)

        buttons = QHBoxLayout()
        self.clean_btn = QPushButton("Clean memory")
        self.clean_btn.setDefault(True)
        self.clean_btn.clicked.connect(self._on_clean_clicked)
        buttons.addWidget(self.clean_btn)
        self.persist_btn = QPushButton("Clean persistence sources...")
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
        root.addWidget(self.progress_bar)

        self.summary_label = QLabel("Verification: (no run yet)")
        self.summary_label.setStyleSheet("font-weight: bold;")
        root.addWidget(self.summary_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(50000)
        self.log_view.setPlaceholderText("live log...")
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
            "Recent Items and jump lists for keyword matches (read-only)..."
        )
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            actions = persistence.scan_persistence(
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

        if not actions:
            self._append_log(
                "[persistence] scan: no keyword-matching entries found in ShellBags, "
                "TypedPaths, RunMRU, Recent Items or jump lists."
            )
            self._maybe_offer_restart(sources_cleaned=True)
            return

        preview = []
        for action in actions[:_MAX_ACTION_PREVIEW]:
            suffix = f"  [!] {action.warning}" if action.warning else ""
            preview.append(
                f"{action.kind}: {action.path}\\{action.name}  (matched "
                f"{action.matched_keyword!r}) - {action.detail}{suffix}"
            )
        if len(actions) > _MAX_ACTION_PREVIEW:
            preview.append(f"... and {len(actions) - _MAX_ACTION_PREVIEW} more (see details)")

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Confirm persistence cleanup")
        box.setText(
            f"Found {len(actions)} keyword-matching persistence item(s). Deleting them "
            "is required so the strings cannot come back after explorer.exe restarts "
            "or the PC reboots (RAM is cleared on reboot; what returns is reloaded "
            "from these registry/disk sources).\n\n"
            "ONLY keyword-matching entries are removed, with these granularities:\n"
            "- ShellBags: matching BagMRU entry (+ its node) or matching bag under "
            "Bags - resets folder view settings for the affected paths.\n"
            "- TypedPaths / RunMRU: matching values only (RunMRU MRUList is rewritten).\n"
            "- Recent Items .lnk: matching shortcuts only.\n"
            "- Jump lists: the whole .automaticDestinations-ms/.customDestinations-ms "
            "file is deleted (the format cannot be edited per entry safely), which "
            "removes that application's OTHER jump-list entries too.\n"
        )
        if self.chk_restart.isChecked():
            box.setText(
                box.text()
                + f"\nAfter cleanup, {self._last_name or 'the target'} will be killed "
                "(taskkill /f /im) and relaunched so a fresh process reloads only the "
                "cleaned sources."
            )
        box.setInformativeText("Delete these entries now?")
        box.setDetailedText("\n".join(preview))
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            self._append_log(
                "[persistence] cleanup declined by user. NOTE: restart is skipped too "
                "- restarting without cleaning the sources would reload the original "
                "strings from disk/registry into the new process."
            )
            return

        restart_name = self._last_name if self.chk_restart.isChecked() else None
        for action in actions:
            self._append_log(f"[persistence] confirmed: {action.detail}")
        self._append_log(f"[persistence] executing {len(actions)} action(s)...")
        self._start_cleanup_worker(actions, restart_name, self._last_paths)

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
