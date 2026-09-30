"""Dialog to add or edit an anomaly detection rule."""
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QDoubleSpinBox,
    QSpinBox, QWidget,
)
from PyQt6.QtCore import Qt

from analyzer.live_capture import AnomalyRule, RULE_TYPES

_BG      = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD    = "#16213e"
_BORDER  = "#2a2a4a"
_ACCENT  = "#7c6af7"
_TEXT    = "#e2e8f0"
_SUBTEXT = "#64748b"

_QSS = f"""
QDialog, QWidget {{ background:{_BG}; color:{_TEXT}; font-family:'Segoe UI',sans-serif; font-size:13px; }}
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background:{_CARD}; color:{_TEXT}; border:1px solid {_BORDER};
    border-radius:6px; padding:6px 10px; font-size:13px;
}}
QLineEdit:focus, QComboBox:focus {{ border:1px solid {_ACCENT}; }}
QComboBox::drop-down {{ border:none; }}
QComboBox QAbstractItemView {{ background:{_CARD}; color:{_TEXT}; border:1px solid {_BORDER}; }}
QPushButton {{
    background:{_ACCENT}; color:white; border:none; border-radius:7px;
    padding:8px 18px; font-weight:700;
}}
QPushButton:hover {{ background:#9580ff; }}
QPushButton#btn_cancel {{
    background:{_CARD}; color:{_TEXT}; border:1px solid {_BORDER};
}}
QPushButton#btn_cancel:hover {{ border-color:{_ACCENT}; color:{_ACCENT}; }}
"""


class RuleDialog(QDialog):
    def __init__(self, rule: AnomalyRule | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Anomaly Rule" if rule is None else "Edit Rule")
        self.setFixedSize(480, 400)
        self.setStyleSheet(_QSS)
        self._rule = rule
        self._build()
        if rule:
            self._populate(rule)

    def get_rule(self) -> AnomalyRule:
        return AnomalyRule(
            name      = self._name.text().strip() or "Rule",
            severity  = "error" if self._severity.currentIndex() == 0 else "warn",
            rule_type = RULE_TYPES[self._type.currentIndex()][0],
            ip        = self._ip.text().strip(),
            protocol  = self._protocol.currentText().strip(),
            threshold = self._threshold.value(),
            window    = self._window.value(),
        )

    def _build(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(24, 20, 24, 20)
        vbox.setSpacing(16)

        title = QLabel(self.windowTitle())
        title.setStyleSheet(
            f"color:{_TEXT};font-size:15px;font-weight:800;"
            f"border-bottom:1px solid {_BORDER};padding-bottom:8px;"
        )
        vbox.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        def lbl(t):
            l = QLabel(t)
            l.setStyleSheet(f"color:{_SUBTEXT};font-size:12px;font-weight:600;")
            return l

        # Name
        self._name = QLineEdit()
        self._name.setPlaceholderText("e.g.  TCP Reset Alert")
        form.addRow(lbl("Name"), self._name)

        # Severity
        self._severity = QComboBox()
        self._severity.addItems(["🔴  Error (immediate action)", "🟠  Warning (investigate)"])
        form.addRow(lbl("Severity"), self._severity)

        # Rule type
        self._type = QComboBox()
        for _, label in RULE_TYPES:
            self._type.addItem(label)
        self._type.currentIndexChanged.connect(self._on_type_change)
        form.addRow(lbl("Rule Type"), self._type)

        # Source IP filter
        self._ip = QLineEdit()
        self._ip.setPlaceholderText("Leave blank = match any IP")
        form.addRow(lbl("Source IP"), self._ip)

        # Protocol
        self._protocol = QComboBox()
        self._protocol.addItems(["Any", "TCP", "UDP", "ARP", "ICMP"])
        self._protocol.setEditable(True)
        form.addRow(lbl("Protocol"), self._protocol)

        # Threshold
        self._threshold = QSpinBox()
        self._threshold.setRange(1, 10000)
        self._threshold.setValue(50)
        self._threshold.setSuffix("  packets")
        form.addRow(lbl("Threshold"), self._threshold)

        # Time window
        self._window = QDoubleSpinBox()
        self._window.setRange(0.1, 60.0)
        self._window.setSingleStep(0.5)
        self._window.setValue(1.0)
        self._window.setSuffix("  seconds")
        form.addRow(lbl("Time Window"), self._window)

        vbox.addLayout(form)
        vbox.addStretch(1)

        # ── buttons ───────────────────────────────────────────────────────────
        btn_row = QWidget()
        bh = QHBoxLayout(btn_row)
        bh.setContentsMargins(0, 0, 0, 0)
        bh.setSpacing(10)
        bh.addStretch(1)

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setObjectName("btn_cancel")
        btn_cancel.setFixedHeight(36)
        btn_cancel.clicked.connect(self.reject)

        btn_save = QPushButton("  ✓  Save Rule")
        btn_save.setFixedHeight(36)
        btn_save.clicked.connect(self._save)

        bh.addWidget(btn_cancel)
        bh.addWidget(btn_save)
        vbox.addWidget(btn_row)

        self._on_type_change(0)

    def _on_type_change(self, idx: int):
        rule_type = RULE_TYPES[idx][0]
        # threshold/window only relevant for flood/storm/scan
        needs_threshold = rule_type in ("ip_flood", "arp_storm", "port_scan")
        self._threshold.setEnabled(needs_threshold)
        self._window.setEnabled(needs_threshold)

    def _populate(self, rule: AnomalyRule):
        self._name.setText(rule.name)
        self._severity.setCurrentIndex(0 if rule.severity == "error" else 1)
        keys = [r[0] for r in RULE_TYPES]
        if rule.rule_type in keys:
            self._type.setCurrentIndex(keys.index(rule.rule_type))
        self._ip.setText(rule.ip)
        proto_map = {"": 0, "TCP": 1, "UDP": 2, "ARP": 3, "ICMP": 4}
        self._protocol.setCurrentIndex(proto_map.get(rule.protocol.upper(), 0))
        self._threshold.setValue(rule.threshold)
        self._window.setValue(rule.window)

    def _save(self):
        if not self._name.text().strip():
            self._name.setPlaceholderText("⚠  Name is required")
            self._name.setStyleSheet(
                f"background:{_CARD};color:{_TEXT};"
                f"border:1px solid #f87171;border-radius:6px;padding:6px 10px;"
            )
            return
        self.accept()
