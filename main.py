#!/usr/bin/env python3
"""string-wiper entry point: wires the PySide6 UI to the engine workers.

Run from an elevated (Administrator) terminal with 64-bit Python 3.10+:

    python main.py
"""

from __future__ import annotations

import sys


def main() -> int:
    import sys as _sys

    if _sys.platform == "win32":
        # Before any Qt DLL loads: detect "compatibility mode" version lies
        # that make native libraries abort with "Windows 7 is the minimum
        # supported platform" and explain the fix instead (core/preflight).
        from core import preflight

        if not preflight.run_preflight():
            return 1

    from PySide6.QtWidgets import QApplication

    if _sys.platform == "win32":
        # Probe the Qt platform plugin before QApplication() aborts with the
        # bare "Could not load the Qt platform plugin 'windows'" message.
        if not preflight.check_qt_platform():
            return 1

    from ui import theme
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    theme.apply_theme(app)
    app.setApplicationName("string-wiper")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
