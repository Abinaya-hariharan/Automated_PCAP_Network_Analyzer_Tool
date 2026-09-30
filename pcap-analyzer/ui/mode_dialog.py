"""Startup mode selection dialog — Offline file analysis or Live capture."""
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame, QWidget,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

_BG      = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD    = "#16213e"
_BORDER  = "#2a2a4a"
_ACCENT  = "#7c6af7"
_ACCENT2 = "#a78bfa"
_GREEN   = "#22c55e"
_TEXT    = "#e2e8f0"
_SUBTEXT = "#64748b"


class ModeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mode: str = "offline"
        self.setWindowTitle("PCAP Analyzer — Select Mode")
        self.setFixedSize(620, 380)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setStyleSheet(f"background:{_BG};color:{_TEXT};font-family:'Segoe UI',sans-serif;")
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(20)

        # ── header ────────────────────────────────────────────────────────────
        hdr = QLabel("🦈  PCAP Analyzer")
        hdr.setStyleSheet(
            f"color:{_TEXT};font-size:22px;font-weight:800;letter-spacing:-0.5px;"
        )
        sub = QLabel("Choose your analysis mode to get started")
        sub.setStyleSheet(f"color:{_SUBTEXT};font-size:13px;margin-top:-6px;")
        root.addWidget(hdr)
        root.addWidget(sub)

        # ── mode cards ────────────────────────────────────────────────────────
        cards_row = QWidget()
        cards_row.setStyleSheet("background:transparent;")
        ch = QHBoxLayout(cards_row)
        ch.setContentsMargins(0, 0, 0, 0)
        ch.setSpacing(16)
        ch.addWidget(self._mode_card(
            "📂", "Offline Analysis",
            "Upload a .pcap or .pcapng file\nand analyze pre-captured traffic.\n\nPerfect for post-incident\ninvestigation and reporting.",
            "Open File…", _ACCENT, "offline",
        ))
        ch.addWidget(self._mode_card(
            "📡", "Live Capture",
            "Capture packets from a network\ninterface in real-time.\n\nInstant anomaly alerts with\n±20 packet context extraction.",
            "Start Live…", _GREEN, "live",
        ))
        root.addWidget(cards_row, 1)

        # ── footer ────────────────────────────────────────────────────────────
        footer = QLabel("Requires Npcap (Windows) for live capture  ·  Press Esc to exit")
        footer.setStyleSheet(f"color:{_SUBTEXT};font-size:11px;")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(footer)

    def _mode_card(self, icon, title, desc, btn_text, color, mode_val) -> QFrame:
        card = QFrame()
        card.setStyleSheet(
            f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            f"stop:0 #1e1e38,stop:1 {_CARD});"
            f"border:1px solid {_BORDER};border-top:3px solid {color};"
            f"border-radius:12px;}}"
        )
        v = QVBoxLayout(card)
        v.setContentsMargins(22, 20, 22, 20)
        v.setSpacing(10)

        ico = QLabel(icon)
        ico.setStyleSheet("font-size:36px;background:transparent;border:none;")
        ttl = QLabel(title)
        ttl.setStyleSheet(
            f"color:{_TEXT};font-size:16px;font-weight:800;"
            f"background:transparent;border:none;"
        )
        dsc = QLabel(desc)
        dsc.setStyleSheet(
            f"color:{_SUBTEXT};font-size:12px;line-height:1.5;"
            f"background:transparent;border:none;"
        )
        dsc.setWordWrap(True)

        btn = QPushButton(btn_text)
        btn.setFixedHeight(38)
        btn.setStyleSheet(
            f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {color},stop:1 {color}cc);"
            f"color:white;border:none;border-radius:8px;"
            f"font-weight:700;font-size:13px;padding:0 20px;}}"
            f"QPushButton:hover{{background:{color};}}"
        )
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda _, m=mode_val: self._select(m))

        v.addWidget(ico)
        v.addWidget(ttl)
        v.addWidget(dsc, 1)
        v.addWidget(btn)
        return card

    def _select(self, mode: str):
        self.mode = mode
        self.accept()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)
