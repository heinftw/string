"""QPainter-drawn monochrome icon set (no icon-font or image dependencies)."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

from ui.theme import ACCENT


def _pixmap(size: int, draw, bg: str = "transparent") -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    if bg != "transparent":
        painter.setBrush(QBrush(QColor(bg)))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(0, 0, size, size, size * 0.22, size * 0.22)
    draw(painter, size)
    painter.end()
    return pm


def _pen(color: str, width: float, cap=Qt.PenCapStyle.RoundCap):
    pen = QPen(QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(cap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    return pen


# ---------------------------------------------------------------------------
# Title-bar controls
# ---------------------------------------------------------------------------


def minimize(color: str = "#c9d1d9", size: int = 28) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, 1.6))
        p.drawLine(QPointF(s * 0.3, s * 0.5), QPointF(s * 0.7, s * 0.5))

    return QIcon(_pixmap(size, draw))


def maximize(color: str = "#c9d1d9", size: int = 28) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, 1.6))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(QRectF(s * 0.3, s * 0.3, s * 0.4, s * 0.4), 1.5, 1.5)

    return QIcon(_pixmap(size, draw))


def restore(color: str = "#c9d1d9", size: int = 28) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, 1.6))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(QRectF(s * 0.36, s * 0.24, s * 0.36, s * 0.36), 1.5, 1.5)
        p.drawRoundedRect(QRectF(s * 0.26, s * 0.38, s * 0.36, s * 0.36), 1.5, 1.5)

    return QIcon(_pixmap(size, draw))


def close_x(color: str = "#c9d1d9", size: int = 28) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, 1.6))
        p.drawLine(QPointF(s * 0.32, s * 0.32), QPointF(s * 0.68, s * 0.68))
        p.drawLine(QPointF(s * 0.68, s * 0.32), QPointF(s * 0.32, s * 0.68))

    return QIcon(_pixmap(size, draw))


# ---------------------------------------------------------------------------
# App + content icons
# ---------------------------------------------------------------------------


def chip_logo(size: int = 46) -> QIcon:
    """Blue rounded chip (app logo)."""

    def draw(p, s):
        grad = QLinearGradient(0, 0, s, s)
        grad.setColorAt(0, QColor("#2f81f7"))
        grad.setColorAt(1, QColor("#1553b6"))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(grad))
        p.drawRoundedRect(QRectF(s * 0.14, s * 0.14, s * 0.72, s * 0.72), s * 0.18, s * 0.18)
        white = QColor("#ffffff")
        p.setPen(_pen("#ffffff", s * 0.05, Qt.PenCapStyle.FlatCap))
        # pins
        for i in range(3):
            o = s * (0.32 + 0.18 * i)
            p.drawLine(QPointF(o, s * 0.05), QPointF(o, s * 0.14))
            p.drawLine(QPointF(o, s * 0.86), QPointF(o, s * 0.95))
            p.drawLine(QPointF(s * 0.05, o), QPointF(s * 0.14, o))
            p.drawLine(QPointF(s * 0.86, o), QPointF(s * 0.95, o))
        # die
        p.setPen(_pen("#ffffff", s * 0.045))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(QRectF(s * 0.3, s * 0.3, s * 0.4, s * 0.4), s * 0.06, s * 0.06)
        p.setBrush(QBrush(white))
        p.setPen(Qt.PenStyle.NoPen)
        for dx in (0.37, 0.55):
            for dy in (0.37, 0.55):
                p.drawEllipse(QRectF(s * dx, s * dy, s * 0.08, s * 0.08))

    return QIcon(_pixmap(size, draw))


def broom(color: str = ACCENT, size: int = 22) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, s * 0.08))
        # handle
        p.drawLine(QPointF(s * 0.62, s * 0.18), QPointF(s * 0.38, s * 0.48))
        # brush head
        path = QPainterPath()
        path.moveTo(s * 0.2, s * 0.52)
        path.lineTo(s * 0.46, s * 0.42)
        path.lineTo(s * 0.6, s * 0.68)
        path.lineTo(s * 0.32, s * 0.8)
        path.closeSubpath()
        p.setBrush(QBrush(QColor(color)))
        p.drawPath(path)
        # bristles
        p.setPen(_pen(color, s * 0.06))
        p.drawLine(QPointF(s * 0.3, s * 0.8), QPointF(s * 0.26, s * 0.92))
        p.drawLine(QPointF(s * 0.4, s * 0.77), QPointF(s * 0.38, s * 0.9))
        p.drawLine(QPointF(s * 0.5, s * 0.73), QPointF(s * 0.5, s * 0.86))

    return QIcon(_pixmap(size, draw))


def database(color: str = "#c9d1d9", size: int = 22) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, s * 0.08))
        p.setBrush(Qt.BrushStyle.NoBrush)
        # top ellipse
        p.drawEllipse(QRectF(s * 0.2, s * 0.16, s * 0.6, s * 0.2))
        # sides
        p.drawLine(QPointF(s * 0.2, s * 0.26), QPointF(s * 0.2, s * 0.7))
        p.drawLine(QPointF(s * 0.8, s * 0.26), QPointF(s * 0.8, s * 0.7))
        # middle arcs
        p.drawArc(QRectF(s * 0.2, s * 0.36, s * 0.6, s * 0.2), 0 * 16, -180 * 16)
        p.drawArc(QRectF(s * 0.2, s * 0.54, s * 0.6, s * 0.2), 0 * 16, -180 * 16)
        # bottom
        p.drawArc(QRectF(s * 0.2, s * 0.6, s * 0.6, s * 0.2), 0 * 16, -180 * 16)

    return QIcon(_pixmap(size, draw))


def x_circle(color: str = "#6e7681", size: int = 22) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, s * 0.08))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QRectF(s * 0.16, s * 0.16, s * 0.68, s * 0.68))
        p.drawLine(QPointF(s * 0.36, s * 0.36), QPointF(s * 0.64, s * 0.64))
        p.drawLine(QPointF(s * 0.64, s * 0.36), QPointF(s * 0.36, s * 0.64))

    return QIcon(_pixmap(size, draw))


def refresh(color: str = ACCENT, size: int = 18) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, s * 0.1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(QRectF(s * 0.2, s * 0.2, s * 0.6, s * 0.6), 60 * 16, 280 * 16)
        # arrow head
        path = QPainterPath()
        path.moveTo(s * 0.72, s * 0.1)
        path.lineTo(s * 0.88, s * 0.26)
        path.lineTo(s * 0.68, s * 0.32)
        path.closeSubpath()
        p.setBrush(QBrush(QColor(color)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawPath(path)

    return QIcon(_pixmap(size, draw))


def shield(color: str = ACCENT, size: int = 18) -> QIcon:
    def draw(p, s):
        path = QPainterPath()
        path.moveTo(s * 0.5, s * 0.12)
        path.lineTo(s * 0.82, s * 0.24)
        path.lineTo(s * 0.82, s * 0.5)
        path.cubicTo(s * 0.82, s * 0.72, s * 0.66, s * 0.84, s * 0.5, s * 0.9)
        path.cubicTo(s * 0.34, s * 0.84, s * 0.18, s * 0.72, s * 0.18, s * 0.5)
        path.lineTo(s * 0.18, s * 0.24)
        path.closeSubpath()
        p.setPen(_pen(color, s * 0.07))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)
        p.setPen(_pen(color, s * 0.08))
        p.drawLine(QPointF(s * 0.36, s * 0.48), QPointF(s * 0.47, s * 0.6))
        p.drawLine(QPointF(s * 0.47, s * 0.6), QPointF(s * 0.66, s * 0.36))

    return QIcon(_pixmap(size, draw))


def trash(color: str = ACCENT, size: int = 16) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, s * 0.08))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(s * 0.2, s * 0.28), QPointF(s * 0.8, s * 0.28))
        p.drawLine(QPointF(s * 0.4, s * 0.28), QPointF(s * 0.43, s * 0.14))
        p.drawLine(QPointF(s * 0.6, s * 0.28), QPointF(s * 0.57, s * 0.14))
        p.drawLine(QPointF(s * 0.43, s * 0.14), QPointF(s * 0.57, s * 0.14))
        p.drawRoundedRect(QRectF(s * 0.28, s * 0.32, s * 0.44, s * 0.52), 2, 2)
        p.drawLine(QPointF(s * 0.42, s * 0.42), QPointF(s * 0.44, s * 0.72))
        p.drawLine(QPointF(s * 0.58, s * 0.42), QPointF(s * 0.56, s * 0.72))

    return QIcon(_pixmap(size, draw))


def memory_chip(color: str = "#3fb950", size: int = 16) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, s * 0.08))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(QRectF(s * 0.24, s * 0.3, s * 0.52, s * 0.4), 2, 2)
        for i in range(3):
            o = s * (0.34 + 0.13 * i)
            p.drawLine(QPointF(o, s * 0.18), QPointF(o, s * 0.3))
            p.drawLine(QPointF(o, s * 0.7), QPointF(o, s * 0.82))
        p.drawLine(QPointF(s * 0.4, s * 0.42), QPointF(s * 0.6, s * 0.42))
        p.drawLine(QPointF(s * 0.4, s * 0.56), QPointF(s * 0.54, s * 0.56))

    return QIcon(_pixmap(size, draw))


def dot(color: str = "#3fb950", size: int = 10) -> QIcon:
    def draw(p, s):
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(color)))
        p.drawEllipse(QRectF(s * 0.15, s * 0.15, s * 0.7, s * 0.7))

    return QIcon(_pixmap(size, draw))


def chevron(color: str = ACCENT, size: int = 12) -> QIcon:
    def draw(p, s):
        p.setPen(_pen(color, 1.6))
        p.drawLine(QPointF(s * 0.25, s * 0.2), QPointF(s * 0.55, s * 0.5))
        p.drawLine(QPointF(s * 0.55, s * 0.5), QPointF(s * 0.25, s * 0.8))
        p.drawLine(QPointF(s * 0.5, s * 0.2), QPointF(s * 0.8, s * 0.5))
        p.drawLine(QPointF(s * 0.8, s * 0.5), QPointF(s * 0.5, s * 0.8))

    return QIcon(_pixmap(size, draw))
