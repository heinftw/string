"""QThread workers for string-wiper.

Signal contract (cross-thread, queued to the UI):
* ``log(str)``          - one human-readable line for the live log
* ``progress(int,int)`` - (done, total) for the progress bar
* ``pass_update(int,int)`` - (pass number, matches found in that pass)
* ``completed(object)`` - result object (ScrubSummary / list[CleanupResult])
* ``failed(str)``       - fatal error message

Cancellation: ``MemoryWorker.request_cancel()`` is a thread-safe entry point
(it only sets a ``threading.Event``) that the scrub engine polls between
regions, chunks and wipe spans, so the UI stays responsive and the worker
aborts cleanly.
"""

from __future__ import annotations

import threading
from typing import List, Optional, Sequence

from PySide6.QtCore import QObject, Signal, Slot

from core import persistence
from core.persistence import CleanupResult, PendingAction
from core.wiper import ScrubSummary, scrub_processes


class MemoryWorker(QObject):
    """Runs the memory scrub off the UI thread."""

    log = Signal(str)
    progress = Signal(int, int)
    pass_update = Signal(int, int)
    completed = Signal(object)  # ScrubSummary
    failed = Signal(str)

    def __init__(
        self,
        pids: Sequence[int],
        keywords: Sequence[str],
        include_mapped_image: bool,
        include_utf8: bool,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._pids = list(pids)
        self._keywords = list(keywords)
        self._include_mapped_image = include_mapped_image
        self._include_utf8 = include_utf8
        self._cancel = threading.Event()

    @Slot()
    def request_cancel(self) -> None:
        """Thread-safe: set the cancel event polled by the scrub engine."""
        self._cancel.set()
        self.log.emit("[cancel] abort requested - stopping cleanly between regions...")

    @Slot()
    def run(self) -> None:
        try:
            summary: ScrubSummary = scrub_processes(
                self._pids,
                self._keywords,
                include_mapped_image=self._include_mapped_image,
                include_utf8=self._include_utf8,
                on_log=self.log.emit,
                on_progress=self.progress.emit,
                on_pass=self.pass_update.emit,
                cancel=self._cancel,
            )
        except Exception as exc:  # every failure must surface, never crash silently
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.completed.emit(summary)


class CleanupWorker(QObject):
    """Executes confirmed persistence actions (and optional restart) off-thread."""

    log = Signal(str)
    progress = Signal(int, int)
    completed = Signal(object)  # List[CleanupResult]
    failed = Signal(str)

    def __init__(
        self,
        actions: Sequence[PendingAction],
        restart_name: Optional[str] = None,
        restart_paths: Optional[Sequence[str]] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._actions = list(actions)
        self._restart_name = restart_name
        self._restart_paths = list(restart_paths or ())

    @Slot()
    def run(self) -> None:
        try:
            results: List[CleanupResult] = []
            total = len(self._actions)
            for i, action in enumerate(self._actions):
                result = persistence.execute_action(action)
                results.append(result)
                level = "[cleanup]" if result.ok else "[error]"
                self.log.emit(f"{level} {result.message}")
                self.progress.emit(i + 1, max(total, 1))
            if self._restart_name:
                self.log.emit(
                    f"[restart] restarting target process ({self._restart_name}) so a fresh "
                    "instance reloads only the cleaned persistence sources..."
                )
                for line in persistence.restart_processes(
                    self._restart_name, self._restart_paths
                ):
                    self.log.emit(line)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.completed.emit(results)
