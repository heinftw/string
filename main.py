#!/usr/bin/env python3
"""string-wiper entry point: wires the PySide6 UI to the engine workers.

Run from an elevated (Administrator) terminal with 64-bit Python 3.10+:

    python main.py
"""

from __future__ import annotations

import sys


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("string-wiper")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
