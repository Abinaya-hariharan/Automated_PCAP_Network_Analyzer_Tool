"""Live capture panel — real-time packet sniffing with anomaly alerts."""
from __future__ import annotations
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QTextEdit, QFileDialog, QDialog, QFrame,
    QListWidget, QListWidgetItem, QAbstractItemView,
    QCheckBox, QSpinBox, QLineEdit,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont

from analyzer.live_capture import (
    LiveCapture, AnomalyRule, DEFAULT_RULES, get_interfaces, SCAPY_OK,
)
from ui.rule_dialog import RuleDialog

# ── palette ───────────────────────────────────────────────────────────────────
_BG      = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD    = "#16213e"
_BORDER  = "#2a2a4a"
_ACCENT  = "#7c6af7"
_ACCENT2 = "#a78bfa"
_GREEN   = "#22c55e"
_RED     = "#f87171"
_ORANGE  = "#fb923c"
_TEXT    = "#e2e8f0"
_SUBTEXT = "#64748b"
_SEV_FG  = {"error": _RED, "warn": _ORANGE}

_MAX_TABLE_ROWS = 2000   # keep last N rows in live feed

_CONTEXT_QSS = f"""
QDialog, QWidget {{ background:{_BG}; color:{_TEXT}; font-family:'Segoe UI',sans-serif; }}
QTableWidget {{ background:{_SURFACE}; border:none; color:{_TEXT}; gridline-color:{_BORDER}; }}
QTableWidget::item {{ padding:5px 10px; }}
QHeaderView::section {{ background:{_BG}; color:{_SUBTEXT}; padding:6px 10px;
    border:none; border-bottom:1px solid {_BORDER}; font-weight:700; font-size:11px; }}
QPushButton {{ background:{_ACCENT}; color:white; border:none; border-radius:6px;
    padding:7px 16px; font-weight:700; }}
QPushButton:hover {{ background:#9580ff; }}
"""


class ContextDialog(QDialog):
    """Shows ±20 packets around an anomaly for deep inspection."""

    def __init__(self, anomaly: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Context: {anomaly.get('msg', 'Anomaly')}")
        self.resize(900, 550)
        self.setStyleSheet(_CONTEXT_QSS)
        self._build(anomaly)

    def _build(self, anomaly: dict):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(16, 14, 16, 14)
        vbox.setSpacing(10)

        sev   = anomaly.get("severity", "warn")
        color = _SEV_FG.get(sev, _ORANGE)
        num   = anomaly.get("packet_num", "?")

        hdr = QLabel(
            f"<b style='color:{color}'>{'🔴' if sev=='error' else '🟠'} "
            f"{anomaly.get('rule','?')}</b>  —  {anomaly.get('msg','')}"
            f"<span style='color:{_SUBTEXT};font-size:11px;'>"
            f"  ·  Anomaly at packet #{num}</span>"
        )
        hdr.setTextFormat(Qt.TextFormat.RichText)
        vbox.addWidget(hdr)

        all_pkts = (
            anomaly.get("context_before", [])
            + [anomaly.get("packet", {})]
            + anomaly.get("context_after", [])
        )

        t = QTableWidget(len(all_pkts), 6)
        t.setHorizontalHeaderLabels(["#", "Time", "Source", "Destination", "Protocol", "Info"])
        t.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        t.horizontalHeader().resizeSection(0, 60)
        t.horizontalHeader().resizeSection(1, 110)
        t.horizontalHeader().resizeSection(2, 130)
        t.horizontalHeader().resizeSection(3, 130)
        t.horizontalHeader().resizeSection(4, 80)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)

        anomaly_row = len(anomaly.get("context_before", []))
        for row, pkt in enumerate(all_pkts):
            items = [
                str(pkt.get("num", "")),
                str(pkt.get("time", "")),
                pkt.get("src", ""),
                pkt.get("dst", ""),
                pkt.get("proto", ""),
                pkt.get("info", ""),
            ]
            for col, val in enumerate(items):
                item = QTableWidgetItem(val)
                if row == anomaly_row:
                    # highlight the anomaly row
                    item.setBackground(QColor(
                        "#3d1515" if sev == "error" else "#2d1f10"
                    ))
                    item.setForeground(QColor(color))
                t.setItem(row, col, item)
                t.setRowHeight(row, 28)

        t.scrollToItem(t.item(anomaly_row, 0))
        vbox.addWidget(t, 1)

        close_btn = QPushButton("Close")
        close_btn.setFixedSize(100, 34)
        close_btn.clicked.connect(self.accept)
        bottom = QHBoxLayout()
        bottom.addStretch()
        bottom.addWidget(close_btn)
        vbox.addLayout(bottom)


# ── main live panel ───────────────────────────────────────────────────────────

class LivePanel(QWidget):
    # signals for ComparePanel
    packet_for_compare = pyqtSignal(dict)
    stats_for_compare  = pyqtSignal(dict)
    live_stopped       = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._capture: LiveCapture | None = None
        self._rules: list[AnomalyRule] = list(DEFAULT_RULES)
        self._pkt_count = 0
        self._alert_count = 0
        self._all_packets: list[dict] = []
        self._live_filter: str = ""
        self._stored_anomalies: list[dict] = []
        self._watching = False
        self._capturing = False
        self._pulse_dots = 0

        # create timer before _build_ui so _begin_watch() can use it
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.setInterval(1000)

        self._build_ui()

    # ── build ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(12, 10, 12, 10)
        vbox.setSpacing(8)

        if not SCAPY_OK:
            self._show_install_banner(vbox)
            return

        vbox.addWidget(self._mk_toolbar())
        vbox.addWidget(self._mk_rotation_bar())
        vbox.addWidget(self._mk_filter_bar())
        vbox.addWidget(self._mk_stat_bar())
        vbox.addWidget(self._mk_body(), 1)
        vbox.addWidget(self._mk_statusbar())
        # start watching after all widgets exist
        self._begin_watch()

    def _show_install_banner(self, vbox):
        banner = QLabel(
            "⚠  Scapy is not installed.\n\n"
            "Run in terminal:   pip install scapy\n\n"
            "Then install Npcap (Windows) from:   https://npcap.com\n\n"
            "Restart the application after installing."
        )
        banner.setStyleSheet(
            f"color:{_ORANGE};font-size:14px;font-weight:600;"
            f"background:{_CARD};border:1px solid {_ORANGE}50;"
            f"border-left:3px solid {_ORANGE};"
            f"border-radius:10px;padding:24px;"
        )
        banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(banner)

    def _mk_toolbar(self) -> QWidget:
        bar = QFrame()
        bar.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:10px;}}"
        )
        h = QHBoxLayout(bar)
        h.setContentsMargins(14, 8, 14, 8)
        h.setSpacing(10)

        # Interface selector
        iface_lbl = QLabel("Interface:")
        iface_lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:12px;font-weight:600;background:transparent;")
        self._iface_combo = QComboBox()
        self._iface_combo.setMinimumWidth(200)
        self._iface_combo.setStyleSheet(
            f"QComboBox{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:6px;padding:5px 10px;}}"
            f"QComboBox::drop-down{{border:none;}}"
            f"QComboBox QAbstractItemView{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};}}"
        )
        self._populate_interfaces()

        h.addWidget(iface_lbl)
        h.addWidget(self._iface_combo)
        h.addSpacing(8)

        # Rules button
        self._rules_btn = QPushButton(f"  ⚙  Rules ({len(self._rules)})")
        self._rules_btn.setFixedHeight(34)
        self._rules_btn.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_ACCENT2};"
            f"border:1px solid {_ACCENT}50;border-radius:7px;"
            f"font-weight:600;font-size:12px;padding:0 14px;}}"
            f"QPushButton:hover{{border-color:{_ACCENT};background:#1e1e3a;}}"
        )
        self._rules_btn.clicked.connect(self._open_rules)
        h.addWidget(self._rules_btn)
        h.addStretch(1)

        # Start / Stop / Clear / Save buttons
        self._btn_start = QPushButton("  ▶  Start")
        self._btn_start.setEnabled(True)
        self._btn_start.setFixedHeight(36)
        self._btn_start.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_GREEN};"
            f"border:1px solid {_GREEN}50;border-radius:8px;"
            f"font-weight:700;font-size:13px;padding:0 18px;}}"
            f"QPushButton:hover{{background:#0f2d1a;border-color:{_GREEN};}}"
            f"QPushButton:disabled{{color:{_SUBTEXT};border-color:{_BORDER};}}"
        )
        self._btn_start.clicked.connect(self._begin_watch)

        self._btn_stop = QPushButton("  ■  Stop")
        self._btn_stop.setEnabled(False)
        self._btn_stop.setFixedHeight(36)
        self._btn_stop.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_RED};"
            f"border:1px solid {_RED}50;border-radius:8px;"
            f"font-weight:700;font-size:13px;padding:0 18px;}}"
            f"QPushButton:hover{{background:#2d1515;border-color:{_RED};}}"
            f"QPushButton:disabled{{color:{_SUBTEXT};border-color:{_BORDER};}}"
        )
        self._btn_stop.clicked.connect(self._stop)

        self._btn_clear = QPushButton("  🗑  Clear")
        self._btn_clear.setFixedHeight(36)
        self._btn_clear.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_ORANGE};"
            f"border:1px solid {_ORANGE}50;border-radius:8px;"
            f"font-weight:600;font-size:12px;padding:0 14px;}}"
            f"QPushButton:hover{{background:#2d1f0f;border-color:{_ORANGE};}}"
        )
        self._btn_clear.clicked.connect(self._clear_all)

        self._btn_save = QPushButton("  💾  Save .pcap")
        self._btn_save.setEnabled(False)
        self._btn_save.setFixedHeight(36)
        self._btn_save.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:8px;"
            f"font-weight:600;font-size:12px;padding:0 14px;}}"
            f"QPushButton:hover{{border-color:{_ACCENT};color:{_ACCENT2};}}"
            f"QPushButton:disabled{{color:{_SUBTEXT};}}"
        )
        self._btn_save.clicked.connect(self._save_pcap)

        h.addWidget(self._btn_start)
        h.addWidget(self._btn_stop)
        h.addWidget(self._btn_clear)
        h.addWidget(self._btn_save)
        return bar

    def _mk_rotation_bar(self) -> QWidget:
        """File rotation controls row."""
        bar = QFrame()
        bar.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;}}")
        h = QHBoxLayout(bar)
        h.setContentsMargins(14, 6, 14, 6)
        h.setSpacing(10)

        self._rotation_check = QCheckBox("Auto-save every")
        self._rotation_check.setStyleSheet(f"""
            QCheckBox {{
                color: {_SUBTEXT};
                font-size: 12px;
                font-weight: 600;
                background: transparent;
                padding: 4px 8px;
                border: 1px solid {_BORDER};
                border-radius: 6px;
            }}
            QCheckBox:checked {{
                color: {_GREEN};
                border: 1px solid {_GREEN};
                background: #0f2d1a;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border-radius: 4px;
                border: 2px solid {_SUBTEXT};
                background: transparent;
            }}
            QCheckBox::indicator:checked {{
                background: {_GREEN};
                border: 2px solid {_GREEN};
            }}
        """)
        self._rotation_check.setChecked(False)

        self._rotation_spin = QSpinBox()
        self._rotation_spin.setRange(100, 1_000_000)
        self._rotation_spin.setValue(1000)
        self._rotation_spin.setSingleStep(1000)
        self._rotation_spin.setFixedHeight(30)
        self._rotation_spin.setStyleSheet(
            f"QSpinBox{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:5px;padding:2px 6px;font-size:12px;}}")

        lbl_pkts = QLabel("packets →")
        lbl_pkts.setStyleSheet(f"color:{_SUBTEXT};font-size:12px;background:transparent;")

        self._rotation_dir_input = QLineEdit()
        self._rotation_dir_input.setPlaceholderText("Save folder…")
        self._rotation_dir_input.setFixedHeight(30)
        self._rotation_dir_input.setStyleSheet(
            f"background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:5px;padding:2px 8px;font-size:12px;")

        btn_browse = QPushButton("Browse")
        btn_browse.setFixedHeight(30)
        btn_browse.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:5px;padding:0 10px;font-size:11px;}}"
            f"QPushButton:hover{{border-color:{_ACCENT};color:{_ACCENT2};}}")
        btn_browse.clicked.connect(self._browse_rotation_dir)

        self._rotation_status = QLabel("")
        self._rotation_status.setStyleSheet(
            f"color:#86efac;font-size:11px;font-style:italic;background:transparent;")

        h.addWidget(self._rotation_check)
        h.addWidget(self._rotation_spin)
        h.addWidget(lbl_pkts)
        h.addWidget(self._rotation_dir_input, 1)
        h.addWidget(btn_browse)
        h.addWidget(self._rotation_status)
        return bar

    def _mk_filter_bar(self) -> QWidget:
        bar = QFrame()
        bar.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;}}"
        )
        h = QHBoxLayout(bar)
        h.setContentsMargins(14, 6, 14, 6)
        h.setSpacing(10)

        lbl = QLabel("Live Filter:")
        lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:12px;font-weight:700;background:transparent;"
        )

        self._live_filter_input = QLineEdit()
        self._live_filter_input.setPlaceholderText(
            "Examples: source=192.168.0.10   dst=224.0.0.22   proto=UDP   contains=5355"
        )
        self._live_filter_input.setFixedHeight(30)
        self._live_filter_input.setStyleSheet(
            f"QLineEdit{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:6px;padding:4px 10px;font-size:12px;}}"
            f"QLineEdit:focus{{border:1px solid {_ACCENT};}}"
        )
        self._live_filter_input.returnPressed.connect(self._apply_live_filter)

        btn_apply = QPushButton("Apply")
        btn_apply.setFixedHeight(30)
        btn_apply.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_GREEN};"
            f"border:1px solid {_GREEN}50;border-radius:6px;padding:0 12px;font-size:11px;font-weight:700;}}"
            f"QPushButton:hover{{background:#0f2d1a;border-color:{_GREEN};}}"
        )
        btn_apply.clicked.connect(self._apply_live_filter)

        btn_reset = QPushButton("Reset")
        btn_reset.setFixedHeight(30)
        btn_reset.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_SUBTEXT};"
            f"border:1px solid {_BORDER};border-radius:6px;padding:0 12px;font-size:11px;font-weight:700;}}"
            f"QPushButton:hover{{border-color:{_ACCENT};color:{_ACCENT2};}}"
        )
        btn_reset.clicked.connect(self._reset_live_filter)

        self._live_filter_result = QLabel("Showing all live packets")
        self._live_filter_result.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;background:transparent;"
        )

        h.addWidget(lbl)
        h.addWidget(self._live_filter_input, 1)
        h.addWidget(btn_apply)
        h.addWidget(btn_reset)
        h.addWidget(self._live_filter_result)
        return bar

    def _browse_rotation_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Select Save Folder")
        if path:
            self._rotation_dir_input.setText(path)
            self._rotation_check.setChecked(True)

    def _on_file_rotated(self, path: str):
        import os
        fname = os.path.basename(path)
        size  = os.path.getsize(path) / 1024
        self._rotation_status.setText(f"✅ Saved: {fname}  ({size:.0f} KB)")

    def _mk_stat_bar(self) -> QWidget:
        row = QWidget()
        row.setStyleSheet("background:transparent;")
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)

        def stat(label, color):
            f = QFrame()
            f.setStyleSheet(
                f"QFrame{{background:{_CARD};"
                f"border:1px solid {color}40;border-top:2px solid {color};"
                f"border-radius:8px;}}"
            )
            fv = QVBoxLayout(f)
            fv.setContentsMargins(12, 6, 12, 6)
            fv.setSpacing(2)
            val = QLabel("—")
            val.setStyleSheet(
                f"color:{color};font-size:18px;font-weight:800;border:none;"
            )
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"color:{_SUBTEXT};font-size:9px;font-weight:700;"
                f"letter-spacing:1px;border:none;"
            )
            fv.addWidget(val)
            fv.addWidget(lbl)
            return f, val

        self._stat_total,   sv1 = stat("TOTAL PKTS",  _ACCENT2)
        self._sv_total = sv1
        self._stat_tcp_w,   sv2 = stat("TCP",         "#60a5fa")
        self._sv_tcp = sv2
        self._stat_udp_w,   sv3 = stat("UDP",         "#34d399")
        self._sv_udp = sv3
        self._stat_arp_w,   sv4 = stat("ARP",         "#fbbf24")
        self._sv_arp = sv4
        self._stat_alerts_w, sv5 = stat("🔴 ALERTS",  _RED)
        self._sv_alerts = sv5

        for w in (self._stat_total, self._stat_tcp_w, self._stat_udp_w,
                  self._stat_arp_w, self._stat_alerts_w):
            h.addWidget(w, 1)
        return row

    def _mk_body(self) -> QSplitter:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{_BORDER};width:2px;}}"
        )

        # ── left: alerts panel ────────────────────────────────────────────────
        left = QWidget()
        left.setStyleSheet(f"background:{_SURFACE};border-radius:10px;")
        lv = QVBoxLayout(left)
        lv.setContentsMargins(10, 10, 10, 10)
        lv.setSpacing(6)

        alert_hdr = QLabel("🚨  Live Alerts")
        alert_hdr.setStyleSheet(
            f"color:{_TEXT};font-size:13px;font-weight:700;"
            f"border-bottom:1px solid {_BORDER};padding-bottom:6px;"
        )
        lv.addWidget(alert_hdr)

        self._alert_list = QTextEdit()
        self._alert_list.setReadOnly(True)
        self._alert_list.setStyleSheet(
            f"QTextEdit{{background:transparent;border:none;"
            f"font-size:12px;color:{_TEXT};}}"
        )
        lv.addWidget(self._alert_list, 1)

        # ── right: live packet table ───────────────────────────────────────────
        self._pkt_table = QTableWidget(0, 6)
        self._pkt_table.setHorizontalHeaderLabels(
            ["#", "Time", "Source", "Destination", "Protocol", "Info"]
        )
        self._pkt_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self._pkt_table.horizontalHeader().resizeSection(0, 60)
        self._pkt_table.horizontalHeader().resizeSection(1, 110)
        self._pkt_table.horizontalHeader().resizeSection(2, 130)
        self._pkt_table.horizontalHeader().resizeSection(3, 130)
        self._pkt_table.horizontalHeader().resizeSection(4, 80)
        self._pkt_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._pkt_table.setAlternatingRowColors(True)
        self._pkt_table.verticalHeader().setVisible(False)
        self._pkt_table.setShowGrid(False)
        self._pkt_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._pkt_table.setStyleSheet(
            f"QTableWidget{{background:{_SURFACE};border:none;"
            f"border-radius:10px;color:{_TEXT};}}"
        )

        splitter.addWidget(left)
        splitter.addWidget(self._pkt_table)
        splitter.setSizes([300, 900])
        return splitter

    def _mk_statusbar(self) -> QLabel:
        self._statusbar = QLabel("  Select an interface above — capture starts automatically when packets are detected")
        self._statusbar.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_BORDER};padding:5px 10px;"
        )
        return self._statusbar

    # ── interface helpers ─────────────────────────────────────────────────────

    def _populate_interfaces(self):
        self._iface_combo.clear()
        ifaces = get_interfaces()
        if ifaces:
            for name, ip in ifaces:
                label = f"{name}  ({ip})" if ip and ip != "0.0.0.0" else name
                self._iface_combo.addItem(label, userData=name)
            self._iface_combo.currentIndexChanged.connect(self._on_iface_changed)
            # _begin_watch() is called after full UI is built (end of _build_ui)
        else:
            self._iface_combo.addItem("No interfaces found")

    def _on_iface_changed(self, _idx: int):
        """Re-start watching whenever the user picks a different interface."""
        if self._watching or self._capturing:
            self._stop(silent=True)
        self._begin_watch()

    def _begin_watch(self):
        """Silently start sniffing; auto-transitions to 'capturing' on first packet."""
        iface = self._iface_combo.currentData() or self._iface_combo.currentText()
        if not iface or iface == "No interfaces found":
            return
        self._pkt_count = 0
        self._alert_count = 0
        self._all_packets.clear()
        self._pkt_table.setRowCount(0)
        self._alert_list.clear()
        self._stored_anomalies.clear()
        self._capturing = False
        self._watching = True
        self._pulse_dots = 0

        self._capture = LiveCapture(iface, self._rules,
                                    rotation_dir=self._rotation_dir_input.text().strip(),
                                    rotation_count=self._rotation_spin.value()
                                        if self._rotation_check.isChecked() else 0)
        self._capture.packet_received.connect(self._on_packet)
        self._capture.anomaly_detected.connect(self._on_anomaly)
        self._capture.stats_updated.connect(self._on_stats)
        self._capture.capture_error.connect(self._on_error)
        self._capture.file_rotated.connect(self._on_file_rotated)
        self._capture.start()

        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._btn_save.setEnabled(False)
        self._iface_combo.setEnabled(True)  # allow switching interface anytime
        self._timer.start()
        self._set_status(
            f"  ⏳  Watching {iface} — waiting for packets…",
            "#fbbf24",
        )

    # ── rules manager ─────────────────────────────────────────────────────────

    def _open_rules(self):
        dlg = _RulesManagerDialog(self._rules, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._rules = dlg.rules
            self._rules_btn.setText(f"  ⚙  Rules ({len(self._rules)})")

    def _clear_all(self):
        """Clear packet table, alerts and counters — capture keeps running."""
        self._pkt_count   = 0
        self._alert_count = 0
        self._all_packets.clear()
        self._pkt_table.setRowCount(0)
        self._alert_list.clear()
        self._stored_anomalies.clear()
        # reset stat display labels by emitting zeroed stats
        self._on_stats({"total": 0, "tcp": 0, "udp": 0,
                        "arp": 0, "icmp": 0, "other": 0, "alerts": 0})
        self._set_status("  🗑  Cleared — ready for fresh capture", _ORANGE)

    def _stop(self, silent: bool = False):
        self._watching = False
        self._capturing = False
        if self._capture:
            self._capture.stop()
        self._timer.stop()
        self._btn_stop.setEnabled(False)
        self._btn_start.setEnabled(True)
        self._btn_save.setEnabled(self._pkt_count > 0)
        self._iface_combo.setEnabled(True)
        if not silent:
            self._set_status(
                f"  ■  Stopped  —  {self._pkt_count:,} packets captured, "
                f"{self._alert_count} alerts",
                _SUBTEXT,
            )
            self.live_stopped.emit()   # notify ComparePanel to do final comparison

    def _save_pcap(self):
        if not self._capture:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Capture", "capture.pcap",
            "PCAP files (*.pcap);;All files (*)"
        )
        if path:
            self._capture.save_pcap(path)
            self._set_status(f"  💾  Saved: {os.path.basename(path)}", _GREEN)

    # ── signal handlers ───────────────────────────────────────────────────────

    def _on_packet(self, info: dict):
        self._pkt_count += 1
        self._all_packets.append(info)
        if len(self._all_packets) > 10000:
            self._all_packets = self._all_packets[-10000:]

        # first packet auto-transitions from watching → capturing
        if not self._capturing:
            self._capturing = True
            iface = self._iface_combo.currentData() or self._iface_combo.currentText()
            self._set_status(
                f"  📡  Auto-detected traffic! Capturing on {iface}…",
                _GREEN,
            )

        if self._packet_matches_filter(info):
            self._append_packet_row(info)
        self.packet_for_compare.emit(info)   # feed ComparePanel

    def _append_packet_row(self, info: dict):
        t = self._pkt_table

        if t.rowCount() >= _MAX_TABLE_ROWS:
            t.removeRow(0)

        row = t.rowCount()
        t.insertRow(row)
        vals = [
            str(info.get("num", "")),
            str(info.get("time", "")),
            info.get("src", ""),
            info.get("dst", ""),
            info.get("proto", ""),
            info.get("info", ""),
        ]
        sev = str(info.get("severity", "")).lower()
        row_bg = {
            "error": QColor("#331717"),
            "warn": QColor("#35240f"),
            "info": QColor("#12233a"),
        }.get(sev)
        proto_colors = {
            "TCP": "#60a5fa", "UDP": "#34d399", "ARP": "#fbbf24",
            "ICMP": "#c084fc", "OTHER": _SUBTEXT,
        }
        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            if row_bg is not None:
                item.setBackground(row_bg)
            if col == 4:
                item.setForeground(QColor(proto_colors.get(val, _SUBTEXT)))
            t.setItem(row, col, item)
            t.setRowHeight(row, 26)

        t.scrollToBottom()

    def _packet_matches_filter(self, pkt: dict) -> bool:
        expr = self._live_filter.strip().lower()
        if not expr:
            return True

        src = str(pkt.get("src", "")).lower()
        dst = str(pkt.get("dst", "")).lower()
        proto = str(pkt.get("proto", "")).lower()
        info = str(pkt.get("info", "")).lower()
        haystack = f"{src} {dst} {proto} {info}"

        if expr.startswith("source=") or expr.startswith("src="):
            target = expr.split("=", 1)[1].strip()
            return target in src
        if expr.startswith("destination=") or expr.startswith("dest=") or expr.startswith("dst="):
            target = expr.split("=", 1)[1].strip()
            return target in dst
        if expr.startswith("proto=") or expr.startswith("protocol="):
            target = expr.split("=", 1)[1].strip()
            return target == proto
        if expr.startswith("contains="):
            target = expr.split("=", 1)[1].strip()
            return target in haystack

        return expr in haystack

    def _apply_live_filter(self):
        self._live_filter = self._live_filter_input.text().strip()
        self._refresh_filtered_packets()

    def _reset_live_filter(self):
        self._live_filter = ""
        self._live_filter_input.clear()
        self._refresh_filtered_packets()

    def _refresh_filtered_packets(self):
        self._pkt_table.setRowCount(0)
        matched = [pkt for pkt in self._all_packets if self._packet_matches_filter(pkt)]
        for pkt in matched[-_MAX_TABLE_ROWS:]:
            self._append_packet_row(pkt)

        if self._live_filter:
            self._live_filter_result.setText(
                f"Matched {len(matched):,} / {len(self._all_packets):,} live packets"
            )
        else:
            self._live_filter_result.setText("Showing all live packets")

    def _on_anomaly(self, anomaly: dict):
        self._alert_count += 1
        self._stored_anomalies.append(anomaly)

        sev   = anomaly.get("severity", "warn")
        color = _SEV_FG.get(sev, _ORANGE)
        icon  = "🔴" if sev == "error" else "🟠"
        num   = anomaly.get("packet_num", "?")

        # add to alert text pane
        self._alert_list.append(
            f'<p style="margin:4px 0;">'
            f'<span style="color:{color};font-weight:700;">{icon} #{num}</span>'
            f'&nbsp;<span style="color:{_SUBTEXT};font-size:11px;">'
            f'[{anomaly.get("rule","")}]</span><br>'
            f'<span style="color:{_TEXT};font-size:12px;">'
            f'{anomaly.get("msg","")}</span>'
            f'</p>'
        )

        # also highlight the anomaly row in packet table
        t = self._pkt_table
        for row in range(t.rowCount()):
            if t.item(row, 0) and t.item(row, 0).text() == str(num):
                for col in range(t.columnCount()):
                    if t.item(row, col):
                        t.item(row, col).setBackground(
                            QColor("#3d1515" if sev == "error" else "#2d1f10")
                        )
                        t.item(row, col).setForeground(QColor(color))
                break

        self._sv_alerts.setText(str(self._alert_count))

    def _on_stats(self, stats: dict):
        self._sv_total.setText(f"{stats.get('total', 0):,}")
        self._sv_tcp.setText(f"{stats.get('tcp', 0):,}")
        self._sv_udp.setText(f"{stats.get('udp', 0):,}")
        self.stats_for_compare.emit(stats)   # feed ComparePanel
        self._sv_arp.setText(f"{stats.get('arp', 0):,}")
        self._sv_alerts.setText(str(self._alert_count))

    def _on_error(self, msg: str):
        self._stop(silent=True)
        self._set_status(f"  ⚠  {msg}", _RED)

    def _tick(self):
        """Every second: refresh stats and animate the waiting dots."""
        self._sv_total.setText(f"{self._pkt_count:,}")
        self._sv_alerts.setText(str(self._alert_count))
        # animate dots while waiting for first packet
        if self._watching and not self._capturing:
            self._pulse_dots = (self._pulse_dots + 1) % 4
            dots = "●" * self._pulse_dots + "○" * (3 - self._pulse_dots)
            iface = self._iface_combo.currentData() or self._iface_combo.currentText()
            self._set_status(
                f"  ⏳  Watching {iface} — waiting for packets  {dots}",
                "#fbbf24",
            )

    # ── context dialog ────────────────────────────────────────────────────────

    def show_context(self, idx: int):
        if 0 <= idx < len(self._stored_anomalies):
            dlg = ContextDialog(self._stored_anomalies[idx], self)
            dlg.exec()

    def mousePressEvent(self, event):
        super().mousePressEvent(event)

    def _set_status(self, msg: str, color: str = _SUBTEXT):
        self._statusbar.setStyleSheet(
            f"color:{color};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {color}60;padding:5px 10px;"
        )
        self._statusbar.setText(msg)


# ── rules manager dialog ──────────────────────────────────────────────────────

class _RulesManagerDialog(QDialog):
    def __init__(self, rules: list[AnomalyRule], parent=None):
        super().__init__(parent)
        self.rules = list(rules)
        self.setWindowTitle("Anomaly Rules")
        self.resize(580, 420)
        self.setStyleSheet(
            f"QDialog,QWidget{{background:{_BG};color:{_TEXT};"
            f"font-family:'Segoe UI',sans-serif;font-size:13px;}}"
            f"QListWidget{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;color:{_TEXT};}}"
            f"QListWidget::item{{padding:8px 12px;border-bottom:1px solid {_BORDER}40;}}"
            f"QListWidget::item:selected{{background:{_ACCENT}30;color:{_TEXT};}}"
            f"QPushButton{{background:{_ACCENT};color:white;border:none;"
            f"border-radius:7px;padding:7px 16px;font-weight:700;}}"
            f"QPushButton:hover{{background:#9580ff;}}"
            f"QPushButton#btn_del{{background:{_CARD};color:{_RED};"
            f"border:1px solid {_RED}50;}}"
            f"QPushButton#btn_del:hover{{background:#2d1515;}}"
            f"QPushButton#btn_close{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};}}"
        )
        self._build()

    def _build(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(20, 16, 20, 16)
        vbox.setSpacing(10)

        hdr = QLabel("Anomaly Detection Rules")
        hdr.setStyleSheet(
            f"color:{_TEXT};font-size:15px;font-weight:800;"
            f"border-bottom:1px solid {_BORDER};padding-bottom:8px;"
        )
        vbox.addWidget(hdr)

        self._list = QListWidget()
        self._refresh_list()
        vbox.addWidget(self._list, 1)

        btn_row = QHBoxLayout()
        btn_add = QPushButton("  +  Add Rule")
        btn_add.setFixedHeight(34)
        btn_add.clicked.connect(self._add)

        btn_edit = QPushButton("  ✎  Edit")
        btn_edit.setFixedHeight(34)
        btn_edit.clicked.connect(self._edit)

        btn_del = QPushButton("  🗑  Remove")
        btn_del.setObjectName("btn_del")
        btn_del.setFixedHeight(34)
        btn_del.clicked.connect(self._delete)

        btn_close = QPushButton("  ✓  Done")
        btn_close.setObjectName("btn_close")
        btn_close.setFixedHeight(34)
        btn_close.clicked.connect(self.accept)

        btn_row.addWidget(btn_add)
        btn_row.addWidget(btn_edit)
        btn_row.addWidget(btn_del)
        btn_row.addStretch()
        btn_row.addWidget(btn_close)
        vbox.addLayout(btn_row)

    def _refresh_list(self):
        self._list.clear()
        for rule in self.rules:
            sev_icon = "🔴" if rule.severity == "error" else "🟠"
            item = QListWidgetItem(f"{sev_icon}  {rule.name}  —  {rule.describe()}")
            self._list.addItem(item)

    def _add(self):
        dlg = RuleDialog(parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.rules.append(dlg.get_rule())
            self._refresh_list()

    def _edit(self):
        idx = self._list.currentRow()
        if idx < 0:
            return
        dlg = RuleDialog(rule=self.rules[idx], parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.rules[idx] = dlg.get_rule()
            self._refresh_list()

    def _delete(self):
        idx = self._list.currentRow()
        if idx >= 0:
            self.rules.pop(idx)
            self._refresh_list()
