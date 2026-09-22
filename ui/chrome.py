"""Frameless window chrome: custom title bar (drag, double-click, min/max/close)."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QPoint, QSize, Qt, Signal
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QWidget

from ui import icons


class TitleBar(QWidget):
    """Dark title bar: logo + name + subtitle on the left, – □ ✕ on the right.

    Dragging moves the window; double-clicking toggles maximization.
    """

    request_minimize = Signal()
    request_maximize = Signal()
    request_close = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("titleBar")
        self.setFixedHeight(44)
        self._drag_offset: Optional[QPoint] = None

        root = QHBoxLayout(self)
        root.setContentsMargins(10, 4, 8, 4)
        root.setSpacing(6)

        self.logo = QLabel()
        self.logo.setPixmap(icons.chip_logo(30).pixmap(30, 30))
        self.logo.setFixedSize(30, 30)
        root.addWidget(self.logo)

        self.title = QLabel("string-wiper")
        self.title.setObjectName("titleLabel")
        root.addWidget(self.title)

        self.subtitle = QLabel("LIVE MEMORY STRING SCRUBBER")
        self.subtitle.setObjectName("subtitleLabel")
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

    # -------------------------------------------------------------- drag/move

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and not self.window().isMaximized():
            self._drag_offset = (
                event.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
            )
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if (
            self._drag_offset is not None
            and event.buttons() & Qt.MouseButton.LeftButton
            and not self.window().isMaximized()
        ):
            self.window().move(event.globalPosition().toPoint() - self._drag_offset)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag_offset = None
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.request_maximize.emit()
        super().mouseDoubleClickEvent(event)

    def sync_maximize_icon(self, maximized: bool) -> None:
        self.btn_max.setIcon(icons.restore() if maximized else icons.maximize())
