"""Dark UI theme (colors + stylesheet) for the string-wiper window chrome."""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette

# Palette (single source of truth for UI colors)
BG = "#05080d"
CARD = "#0b0f15"
CARD_BORDER = "#1c2430"
FIELD_BG = "#0d1117"
FIELD_BORDER = "#30363d"
FIELD_BORDER_FOCUS = "#3b82f6"
TEXT = "#c9d1d9"
TEXT_DIM = "#8b949e"
TEXT_MUTED = "#6e7681"
ACCENT = "#3b82f6"
ACCENT_SOFT = "#58a6ff"
GREEN = "#3fb950"
YELLOW = "#d29922"
RED = "#f85149"
RED_SOFT = "#ff7b72"

THEME_QSS = f"""
* {{
    outline: none;
}}
QMainWindow, QDialog {{
    background: {BG};
}}
#windowFrame {{
    background: {BG};
    border: 1px solid {CARD_BORDER};
    border-radius: 10px;
}}
QLabel {{
    background: transparent;
    color: {TEXT};
    border: none;
}}
#titleLabel {{
    color: #ffffff;
    font-size: 15px;
    font-weight: 700;
}}
#subtitleLabel {{
    color: {TEXT_DIM};
    font-size: 8px;
    font-weight: 600;
    letter-spacing: 3px;
}}
#rowLabel {{
    color: {TEXT_DIM};
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 2px;
    padding-right: 2px;
}}
#card, #bannerCard {{
    background: {CARD};
    border: 1px solid {CARD_BORDER};
    border-radius: 10px;
}}
#bannerCard {{
    border-color: #5a3a12;
    background: #1a1408;
}}
#titleBtn, #titleBtnClose {{
    background: transparent;
    border: none;
    border-radius: 6px;
    min-width: 34px;
    max-width: 34px;
    min-height: 24px;
    max-height: 24px;
}}
#titleBtn:hover {{
    background: #1c2430;
}}
#titleBtnClose:hover {{
    background: {RED};
}}
QLineEdit, QComboBox {{
    background: {FIELD_BG};
    border: 1px solid {FIELD_BORDER};
    border-radius: 8px;
    color: {TEXT};
    padding: 6px 8px;
    font-size: 12px;
    selection-background-color: {ACCENT};
    selection-color: #ffffff;
}}
QLineEdit:focus, QComboBox:focus {{
    border: 2px solid {FIELD_BORDER_FOCUS};
    padding: 5px 7px;
}}
QLineEdit::placeholder {{
    color: {TEXT_MUTED};
}}
QComboBox::drop-down {{
    border: none;
    width: 26px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {TEXT_DIM};
    margin-right: 10px;
}}
QComboBox QAbstractItemView {{
    background: {FIELD_BG};
    border: 1px solid {FIELD_BORDER};
    border-radius: 8px;
    color: {TEXT};
    selection-background-color: #1f3a63;
    selection-color: #ffffff;
    outline: none;
    padding: 4px;
}}
QCheckBox {{
    color: {TEXT_DIM};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 2px;
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 1px solid {FIELD_BORDER};
    background: {FIELD_BG};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border: 1px solid {ACCENT};
    image: none;
}}
QCheckBox::indicator:hover {{
    border: 1px solid {ACCENT_SOFT};
}}
#dangerCheck {{
    color: {RED_SOFT};
}}
QPushButton {{
    background: {FIELD_BG};
    border: 1px solid {FIELD_BORDER};
    border-radius: 8px;
    color: {TEXT};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 8px 12px;
}}
QPushButton:hover {{
    border: 1px solid {ACCENT_SOFT};
}}
QPushButton:disabled {{
    color: {TEXT_MUTED};
    border: 1px solid #21262d;
    background: transparent;
}}
#cleanBtn {{
    background: #0b1c3d;
    border: 1px solid {ACCENT};
    color: #ffffff;
}}
#cleanBtn:hover {{
    background: #10223f;
}}
#cleanBtn:disabled {{
    background: transparent;
    border: 1px solid #21262d;
    color: {TEXT_MUTED};
}}
#refreshBtn {{
    background: transparent;
    color: {ACCENT_SOFT};
    padding: 6px 10px;
    letter-spacing: 1px;
}}
#refreshBtn:hover {{
    border: 1px solid {ACCENT_SOFT};
}}
#progressPct {{
    color: {ACCENT_SOFT};
    font-size: 11px;
    font-weight: 700;
    background: transparent;
}}
QProgressBar {{
    background: #12181f;
    border: none;
    border-radius: 2px;
    min-height: 4px;
    max-height: 4px;
}}
QProgressBar::chunk {{
    background: {ACCENT};
    border-radius: 2px;
}}
#verifyHeader {{
    color: #ffffff;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    background: transparent;
}}
#clearLogBtn {{
    background: transparent;
    border: none;
    color: {ACCENT_SOFT};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    padding: 4px 6px;
}}
#clearLogBtn:hover {{
    color: #ffffff;
}}
#logView {{
    background: #070b10;
    border: 1px solid #161c24;
    border-radius: 8px;
    padding: 6px;
    color: {TEXT};
    font-family: 'Consolas', 'Cascadia Mono', 'Courier New', monospace;
    font-size: 9pt;
}}
#footerLabel {{
    color: {TEXT_DIM};
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 2px;
    background: transparent;
}}
#footerValueOk {{
    color: {GREEN};
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 2px;
}}
#footerValueBad {{
    color: {RED};
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 2px;
}}
#footerRule {{
    background: {CARD_BORDER};
    max-height: 1px;
    border: none;
}}
QMessageBox {{
    background: {CARD};
}}
QMessageBox QLabel {{
    color: {TEXT};
}}
QMessageBox QPushButton {{
    min-width: 90px;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: #21262d;
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: #21262d;
    border-radius: 5px;
    min-width: 30px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}
"""


def apply_theme(app) -> None:
    """Apply the dark stylesheet + palette application-wide."""
    app.setStyleSheet(THEME_QSS)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(BG))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Base, QColor(FIELD_BG))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(CARD))
    palette.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Button, QColor(CARD))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(CARD))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(TEXT_MUTED))
    app.setPalette(palette)
