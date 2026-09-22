"""Frameless window chrome: draggable body + custom title bar (min/max/close)."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QPoint, QSize, Qt, Signal
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QWidget

from ui import icons


class WindowDragMixin:
    """Left-drag moves the window from ANY non-interactive surface.

    Primary path is the native ``QWindow.startSystemMove()`` (the OS runs the
    move with correct multi-monitor/DPI behavior); when it is unavailable the
    handler falls back to manual offset moves.  Interactive widgets (buttons,
    inputs, combo, log) accept their own mouse events, so they never start a
    drag; clicks on plain labels and empty chrome propagate here.
    """

    _drag_offset: Optional[QPoint] = None

    def mousePressEvent(self, event: QMouseEvent) -> None:
        window = self.window()
        if event.button() == Qt.MouseButton.LeftButton and not window.isMaximized():
            handle = window.windowHandle()
            if handle is not None and handle.startSystemMove():
                event.accept()
                return
            self._drag_offset = (
                event.globalPosition().toPoint() - window.frameGeometry().topLeft()
            )
            event.accept()
            return
        super().mousePressEvent(event)  # type: ignore[misc]

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.window().move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()
            return
        super().mouseMoveEvent(event)  # type: ignore[misc]

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag_offset = None
        super().mouseReleaseEvent(event)  # type: ignore[misc]


class TitleBar(WindowDragMixin, QWidget):
    """Dark title bar: logo + name + subtitle on the left, – □ ✕ on the right.

    Every part of the window (including this bar) drags via WindowDragMixin;
    double-clicking the bar toggles maximization.
    """

    request_minimize = Signal()
    request_maximize = Signal()
    request_close = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("titleBar")
        self.setFixedHeight(44)

        root = QHBoxLayout(self)
        root.setContentsMargins(10, 4, 8, 4)
        root.setSpacing(6)

        self.logo = QLabel()
        self.logo.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.logo.setPixmap(icons.chip_logo(30).pixmap(30, 30))
        self.logo.setFixedSize(30, 30)
        root.addWidget(self.logo)

        self.title = QLabel("string-wiper")
        self.title.setObjectName("titleLabel")
        self.title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        root.addWidget(self.title)

        self.subtitle = QLabel("LIVE MEMORY STRING SCRUBBER")
        self.subtitle.setObjectName("subtitleLabel")
        self.subtitle.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        root.addWidget(self.subtitle)
        root.addStretch(1)

        self.btn_min = QToolButton()
        self.btn_min.setObjectName("titleBtn")
        self.btn_min.setIcon(icons.minimize())
        self.btn_min.setIconSize(QSize(20, 20))
        self.btn_min.clicked.connect(self.request_minimize.emit)

        self.btn_max = QToolButton()
        self.btn_max.setObjectName("titleBtn")
        self.btn_max.setIcon(icons.maximize())
        self.btn_max.setIconSize(QSize(20, 20))
        self.btn_max.clicked.connect(self.request_maximize.emit)

        self.btn_close = QToolButton()
        self.btn_close.setObjectName("titleBtnClose")
        self.btn_close.setIcon(icons.close_x())
        self.btn_close.setIconSize(QSize(20, 20))
        self.btn_close.clicked.connect(self.request_close.emit)

        for button in (self.btn_min, self.btn_max, self.btn_close):
            button.setFixedSize(34, 24)
            root.addWidget(button)

    # ----------------------------------------- double-click (drag: mixin)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.request_maximize.emit()
        super().mouseDoubleClickEvent(event)

    def sync_maximize_icon(self, maximized: bool) -> None:
        self.btn_max.setIcon(icons.restore() if maximized else icons.maximize())
