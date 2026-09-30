"""Visual query builder — constructs filters against loaded PCAP findings and flows."""
from __future__ import annotations
import os, shutil, subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QComboBox, QLineEdit, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QTextEdit, QSizePolicy, QTabWidget,
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QColor

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
_SEV_FG  = {"error": _RED, "warn": _ORANGE, "info": "#60a5fa"}
_SEV_BG  = {"error": "#2d1515", "warn": "#2d1f10", "info": "#0f1f35"}
_SEV_TAG = {"error": "● ERROR", "warn": "▲ WARN", "info": "ℹ  INFO"}

# ── field/operator definitions ────────────────────────────────────────────────
FIELDS = [
    # (display_label,  data_key,   operators,               value_type)
    ("Protocol",       "protocol", ["=", "≠", "in list"],   "protocol"),
    ("Severity",       "severity", ["=", "≠"],               "severity"),
    ("Source IP",      "src",      ["=", "≠", "contains",
                                    "starts with"],          "text"),
    ("Destination IP", "dst",      ["=", "≠", "contains",
                                    "starts with"],          "text"),
    ("Details / Msg",  "msg",      ["contains", "not contains",
                                    "starts with", "="],     "text"),
    ("Packets",        "packets",  [">", "<", "=", "≥", "≤"],"number"),
    ("Source Port",    "src_port", [">", "<", "="],          "number"),
    ("Dest Port",      "dst_port", [">", "<", "="],          "number"),
]

PROTOCOLS  = ["TCP", "UDP", "ARP", "MODBUS", "ICMP", "STP", "LLDP", "IGMP",
              "DNS", "HTTP", "HTTPS", "DATA", "OTHER", "PROFINET",
              "BACnet", "Ethernet", "IPv4", "IPv6", "VLAN", "DHCP", "SNMP"]
SEVERITIES = ["error", "warn", "info"]
LOGIC_OPS  = ["AND", "OR"]

_FIELD_KEYS   = {f[0]: f for f in FIELDS}
_COMBO_STYLE  = (
    f"QComboBox{{background:{_CARD};color:{_TEXT};"
    f"border:1px solid {_BORDER};border-radius:6px;padding:5px 8px;"
    f"font-size:12px;}}"
    f"QComboBox::drop-down{{border:none;width:20px;}}"
    f"QComboBox QAbstractItemView{{background:{_CARD};color:{_TEXT};"
    f"border:1px solid {_BORDER};}}"
)
_INPUT_STYLE  = (
    f"QLineEdit{{background:{_CARD};color:{_TEXT};"
    f"border:1px solid {_BORDER};border-radius:6px;padding:5px 8px;"
    f"font-size:12px;}}"
    f"QLineEdit:focus{{border:1px solid {_ACCENT};}}"
)


# ── single condition row ──────────────────────────────────────────────────────

class ConditionRow(QWidget):
    removed = pyqtSignal(object)   # emits self
    changed = pyqtSignal()

    def __init__(self, row_index: int, parent=None):
        super().__init__(parent)
        self._protocol_options = list(PROTOCOLS)
        self.setStyleSheet("background:transparent;")
        self._build(row_index)

    def _build(self, idx: int):
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)

        # AND/OR toggle (hidden on first row)
        self._logic = QComboBox()
        self._logic.addItems(LOGIC_OPS)
        self._logic.setFixedWidth(68)
        self._logic.setStyleSheet(_COMBO_STYLE)
        self._logic.setVisible(idx > 0)
        self._logic.currentIndexChanged.connect(self.changed)
        h.addWidget(self._logic)

        # field selector
        self._field = QComboBox()
        for f in FIELDS:
            self._field.addItem(f[0])
        self._field.setFixedWidth(155)
        self._field.setStyleSheet(_COMBO_STYLE)
        self._field.currentIndexChanged.connect(self._on_field_change)
        h.addWidget(self._field)

        # operator
        self._op = QComboBox()
        self._op.setFixedWidth(120)
        self._op.setStyleSheet(_COMBO_STYLE)
        self._op.currentIndexChanged.connect(self.changed)
        h.addWidget(self._op)

        # value widget (either free text or combo)
        self._val_text = QLineEdit()
        self._val_text.setPlaceholderText("value…")
        self._val_text.setFixedWidth(180)
        self._val_text.setStyleSheet(_INPUT_STYLE)
        self._val_text.textChanged.connect(self.changed)

        self._val_combo = QComboBox()
        self._val_combo.setFixedWidth(180)
        self._val_combo.setStyleSheet(_COMBO_STYLE)
        self._val_combo.currentIndexChanged.connect(self.changed)

        h.addWidget(self._val_text)
        h.addWidget(self._val_combo)

        # remove button
        btn_rm = QPushButton("✕")
        btn_rm.setFixedSize(28, 28)
        btn_rm.setStyleSheet(
            f"QPushButton{{background:transparent;color:{_SUBTEXT};"
            f"border:none;border-radius:6px;font-size:13px;font-weight:700;}}"
            f"QPushButton:hover{{background:#2d1515;color:{_RED};}}"
        )
        btn_rm.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_rm.clicked.connect(lambda: self.removed.emit(self))
        h.addWidget(btn_rm)
        h.addStretch(1)

        self._on_field_change(0)

    def _on_field_change(self, _=None):
        fname = self._field.currentText()
        _, _, ops, vtype = _FIELD_KEYS[fname]
        self._op.blockSignals(True)
        self._op.clear()
        self._op.addItems(ops)
        self._op.blockSignals(False)

        is_combo = vtype in ("protocol", "severity")
        self._val_text.setVisible(not is_combo)
        self._val_combo.setVisible(is_combo)
        if vtype == "protocol":
            self._val_combo.clear()
            self._val_combo.addItems(self._protocol_options)
            self._val_combo.setEditable(False)
        elif vtype == "severity":
            self._val_combo.clear()
            self._val_combo.addItems(SEVERITIES)
            self._val_combo.setEditable(False)
        self.changed.emit()

    def set_protocol_options(self, options: list[str]):
        self._protocol_options = options or list(PROTOCOLS)
        if self.field_vtype() == "protocol":
            current = self._val_combo.currentText()
            self._val_combo.blockSignals(True)
            self._val_combo.clear()
            self._val_combo.addItems(self._protocol_options)
            idx = self._val_combo.findText(current)
            if idx >= 0:
                self._val_combo.setCurrentIndex(idx)
            self._val_combo.blockSignals(False)

    # ── public accessors ──────────────────────────────────────────────────────

    def logic(self) -> str:
        return self._logic.currentText()

    def field_key(self) -> str:
        return _FIELD_KEYS[self._field.currentText()][1]

    def field_vtype(self) -> str:
        return _FIELD_KEYS[self._field.currentText()][3]

    def operator(self) -> str:
        return self._op.currentText()

    def value(self) -> str:
        if self._val_combo.isVisible():
            return self._val_combo.currentText()
        return self._val_text.text().strip()

    def set_logic_visible(self, visible: bool):
        self._logic.setVisible(visible)


# ── query builder panel ───────────────────────────────────────────────────────

class QueryBuilderPanel(QWidget):
    """Tab with Visual Builder + Manual tshark Filter modes."""

    filter_applied   = pyqtSignal(list, list)
    _manual_finished = pyqtSignal(list, str)   # (rows, error_msg)

    # common filter suggestions
    _FILTER_SUGGESTIONS = [
        "tcp.flags.reset==1",
        "tcp.analysis.retransmission",
        "arp.opcode==1",
        "http.response.code >= 400",
        "ip.src == 192.168.1.10",
        "ip.dst == 192.168.1.10",
        "tcp.port == 502",
        "modbus",
        "dns.flags.rcode > 0",
        "icmp.type == 3",
        "frame.len > 1400",
        "tcp.analysis.duplicate_ack",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._report: dict | None = None
        self._pcap_path: str = ""
        self._live_packets: list[dict] = []
        self._rows: list[ConditionRow] = []
        self._protocol_options: list[str] = list(PROTOCOLS)
        self._manual_finished.connect(self._populate_manual)
        self._build_ui()

    def set_report(self, report: dict):
        self._report = report
        self._refresh_protocol_options()

    def set_pcap(self, path: str):
        self._pcap_path = path

    def feed_live_packet(self, packet: dict):
        self._live_packets.append(packet)
        if len(self._live_packets) > 10000:
            self._live_packets = self._live_packets[-10000:]
        self._refresh_protocol_options()

    def clear_live_packets(self):
        self._live_packets.clear()
        self._refresh_protocol_options()

    @staticmethod
    def _tshark() -> str | None:
        t = shutil.which("tshark")
        if t: return t
        for c in [r"C:\Program Files\Wireshark\tshark.exe",
                   r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
            if os.path.isfile(c): return c
        return None

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 10)
        root.setSpacing(8)

        # header
        hdr = QHBoxLayout()
        ttl = QLabel("🔍  Query Builder")
        ttl.setStyleSheet(f"color:{_TEXT};font-size:15px;font-weight:800;")
        sub = QLabel("Visual filter builder  ·  or type raw tshark display filters directly")
        sub.setStyleSheet(f"color:{_SUBTEXT};font-size:12px;")
        hdr.addWidget(ttl); hdr.addWidget(sub, 1)
        root.addLayout(hdr)

        self._source_lbl = QLabel("Data source: Offline analysis report")
        self._source_lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:11px;")
        root.addWidget(self._source_lbl)

        # ── inner tab widget: Visual Builder | Manual Filter ──────────────────
        inner_tabs = QTabWidget()
        inner_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:none;background:transparent;}}"
            f"QTabBar::tab{{background:{_CARD};color:{_SUBTEXT};"
            f"padding:7px 18px;border-radius:6px 6px 0 0;margin-right:2px;"
            f"font-size:12px;font-weight:600;border:1px solid {_BORDER};border-bottom:none;}}"
            f"QTabBar::tab:selected{{background:{_SURFACE};color:{_ACCENT2};"
            f"border-bottom:2px solid {_ACCENT};}}"
        )
        inner_tabs.addTab(self._mk_visual_panel(), "  🔧 Visual Builder  ")
        inner_tabs.addTab(self._mk_manual_panel(), "  📝 Manual Filter (tshark)  ")
        root.addWidget(inner_tabs, 1)

    # ── Visual Builder panel ───────────────────────────────────────────────────

    def _mk_visual_panel(self) -> QWidget:
        # outer page — scroll wraps everything so nothing overlaps
        outer = QWidget()
        outer.setStyleSheet(f"background:{_BG};")
        outer_v = QVBoxLayout(outer)
        outer_v.setContentsMargins(0, 8, 0, 0)
        outer_v.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            f"QScrollArea{{background:{_BG};border:none;}}"
            f"QScrollBar:vertical{{background:transparent;width:6px;}}"
            f"QScrollBar::handle:vertical{{background:{_BORDER};border-radius:3px;}}"
        )

        content = QWidget()
        content.setStyleSheet(f"background:{_BG};")
        root = QVBoxLayout(content)
        root.setContentsMargins(0, 0, 8, 16)
        root.setSpacing(16)

        # ── SECTION 1: Conditions ─────────────────────────────────────────────
        sec1_hdr = QHBoxLayout()
        sec1_lbl = QLabel("Conditions")
        sec1_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:10px;font-weight:700;letter-spacing:2px;"
        )
        btn_add = QPushButton("  +  Add Condition")
        btn_add.setFixedHeight(30)
        btn_add.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_ACCENT2};"
            f"border:1px solid {_ACCENT}50;border-radius:7px;"
            f"font-weight:600;font-size:11px;padding:0 12px;}}"
            f"QPushButton:hover{{background:#1e1e3a;border-color:{_ACCENT};}}"
        )
        btn_add.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_add.clicked.connect(self._add_row)
        sec1_hdr.addWidget(sec1_lbl)
        sec1_hdr.addStretch(1)
        sec1_hdr.addWidget(btn_add)
        root.addLayout(sec1_hdr)

        self._rows_widget = QWidget()
        self._rows_widget.setStyleSheet("background:transparent;")
        self._rows_layout = QVBoxLayout(self._rows_widget)
        self._rows_layout.setContentsMargins(0, 0, 0, 0)
        self._rows_layout.setSpacing(8)
        self._rows_layout.addStretch(1)
        root.addWidget(self._rows_widget)

        # ── SECTION 2: Filter preview ─────────────────────────────────────────
        div1 = QFrame(); div1.setFrameShape(QFrame.Shape.HLine)
        div1.setStyleSheet(f"background:{_BORDER};border:none;max-height:1px;")
        root.addWidget(div1)

        prev_hdr = QLabel("Generated Filter Expression")
        prev_hdr.setStyleSheet(
            f"color:{_SUBTEXT};font-size:10px;font-weight:700;letter-spacing:2px;"
        )
        root.addWidget(prev_hdr)

        self._preview = QTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setFixedHeight(48)
        self._preview.setStyleSheet(
            f"QTextEdit{{background:{_CARD};color:{_ACCENT2};"
            f"border:1px solid {_BORDER};border-radius:8px;"
            f"padding:8px 12px;font-family:'Consolas',monospace;font-size:12px;}}"
        )
        self._preview.setPlaceholderText("Add conditions above to build a filter…")
        root.addWidget(self._preview)

        # ── SECTION 3: Action buttons ─────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self._btn_apply    = self._action_btn("  ▶  Apply Filter", _GREEN, "#15803d", self._apply)
        self._btn_clear_r  = self._action_btn("  ↺  Reset", _CARD, "#1e1e3a", self._reset_results,
                                               text_color=_SUBTEXT, border=_BORDER)
        self._btn_copy     = self._action_btn("  📋  Copy", _CARD, "#1e1e3a", self._copy_filter,
                                               text_color=_TEXT, border=_BORDER)
        self._btn_clear_all = self._action_btn("  ✕  Clear All", _CARD, "#2d1515", self._clear_all,
                                                text_color=_RED, border=f"{_RED}50")
        for b in (self._btn_apply, self._btn_clear_r, self._btn_copy, self._btn_clear_all):
            btn_row.addWidget(b)
        btn_row.addStretch(1)
        root.addLayout(btn_row)

        # ── SECTION 4: Results ────────────────────────────────────────────────
        div2 = QFrame(); div2.setFrameShape(QFrame.Shape.HLine)
        div2.setStyleSheet(f"background:{_BORDER};border:none;max-height:1px;")
        root.addWidget(div2)

        res_hdr = QHBoxLayout()
        res_lbl = QLabel("Query Results")
        res_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:10px;font-weight:700;letter-spacing:2px;"
        )
        self._btn_tab_findings = self._tab_btn("Findings", True)
        self._btn_tab_flows    = self._tab_btn("Flows", False)
        self._result_count     = QLabel("")
        self._result_count.setStyleSheet(f"color:{_SUBTEXT};font-size:11px;")
        res_hdr.addWidget(res_lbl)
        res_hdr.addSpacing(12)
        res_hdr.addWidget(self._btn_tab_findings)
        res_hdr.addWidget(self._btn_tab_flows)
        res_hdr.addStretch(1)
        res_hdr.addWidget(self._result_count)
        root.addLayout(res_hdr)

        self._tbl_findings = self._make_table(["Pkt #", "Severity", "Protocol", "Details"], [60, 100, 100])
        self._tbl_flows    = self._make_table(["Source", "Destination", "Protocol", "Packets"], [160, 160, 100])
        self._tbl_flows.setVisible(False)
        self._tbl_findings.setMinimumHeight(200)
        self._tbl_flows.setMinimumHeight(200)
        root.addWidget(self._tbl_findings)
        root.addWidget(self._tbl_flows)

        # usage hint
        self._hint = QLabel(
            "  💡  1. Select Field  →  2. Choose Operator  →  3. Enter Value  →  4. Click ▶ Apply Filter"
        )
        self._hint.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;"
            f"background:{_CARD};border:1px dashed {_BORDER};"
            f"border-radius:8px;padding:12px;"
        )
        root.addWidget(self._hint)

        scroll.setWidget(content)
        outer_v.addWidget(scroll, 1)

        self._add_row()
        return outer

    # ── Manual Filter panel ────────────────────────────────────────────────────

    def _mk_manual_panel(self) -> QWidget:
        page = QWidget()
        page.setStyleSheet(f"background:{_BG};")
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 10, 0, 0)
        v.setSpacing(10)

        # info bar
        info = QLabel(
            "  📝  Enter any Wireshark display filter — results are fetched directly from the .pcap file using tshark"
        )
        info.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;"
            f"background:{_CARD};border:1px solid {_BORDER};"
            f"border-left:3px solid {_ACCENT};border-radius:6px;padding:8px 12px;"
        )
        v.addWidget(info)

        # filter input row
        inp_row = QHBoxLayout()
        inp_row.setSpacing(8)

        self._manual_input = QLineEdit()
        self._manual_input.setPlaceholderText(
            "e.g.  tcp.flags.reset==1    ip.src==192.168.0.10    arp    modbus    http.response.code>=400"
        )
        self._manual_input.setStyleSheet(
            f"QLineEdit{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:8px;"
            f"padding:9px 14px;font-family:'Consolas',monospace;font-size:13px;}}"
            f"QLineEdit:focus{{border:1px solid {_ACCENT};}}"
        )
        self._manual_input.returnPressed.connect(self._run_manual_filter)

        btn_run = QPushButton("  ▶  Run Filter")
        btn_run.setFixedHeight(40)
        btn_run.setStyleSheet(
            f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {_ACCENT},stop:1 #a78bfa);"
            f"color:white;border:none;border-radius:8px;"
            f"font-weight:700;font-size:13px;padding:0 20px;}}"
            f"QPushButton:hover{{background:{_ACCENT};}}"
        )
        btn_run.clicked.connect(self._run_manual_filter)
        inp_row.addWidget(self._manual_input, 1)
        inp_row.addWidget(btn_run)
        v.addLayout(inp_row)

        # quick filter chips
        chip_row = QHBoxLayout()
        chip_row.setSpacing(6)
        chip_lbl = QLabel("Quick filters:")
        chip_lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:11px;")
        chip_row.addWidget(chip_lbl)
        for flt in self._FILTER_SUGGESTIONS[:6]:
            btn = QPushButton(flt)
            btn.setStyleSheet(
                f"QPushButton{{background:{_CARD};color:{_SUBTEXT};"
                f"border:1px solid {_BORDER};border-radius:10px;"
                f"padding:3px 10px;font-size:10px;font-family:'Consolas',monospace;}}"
                f"QPushButton:hover{{color:{_TEXT};border-color:{_ACCENT};}}"
            )
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, f=flt: self._set_manual_filter(f))
            chip_row.addWidget(btn)
        chip_row.addStretch(1)
        v.addLayout(chip_row)

        # results table
        self._manual_status = QLabel("  Enter a filter above and click ▶ Run Filter")
        self._manual_status.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_BORDER};padding:5px 10px;"
        )
        v.addWidget(self._manual_status)

        self._manual_table = QTableWidget(0, 7)
        self._manual_table.setHorizontalHeaderLabels(
            ["Pkt #", "Time (s)", "Δ (ms)", "Source", "Destination", "Protocol", "Length"]
        )
        self._manual_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self._manual_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        for col, w in enumerate([65, 90, 65, 0, 0, 80, 60]):
            if w: self._manual_table.horizontalHeader().resizeSection(col, w)
        self._manual_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._manual_table.setAlternatingRowColors(True)
        self._manual_table.verticalHeader().setVisible(False)
        self._manual_table.setShowGrid(False)
        self._manual_table.setStyleSheet(
            f"QTableWidget{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;color:{_TEXT};}}"
            f"QTableWidget::item{{padding:6px 10px;}}"
            f"QHeaderView::section{{background:{_BG};color:{_SUBTEXT};"
            f"padding:7px 10px;border:none;border-bottom:2px solid {_BORDER};"
            f"font-weight:700;font-size:11px;letter-spacing:1px;}}"
        )
        v.addWidget(self._manual_table, 1)
        return page

    def _set_manual_filter(self, flt: str):
        self._manual_input.setText(flt)
        self._run_manual_filter()

    def _run_manual_filter(self):
        flt = self._manual_input.text().strip()
        if not flt:
            return
        if not self._pcap_path or not os.path.isfile(self._pcap_path):
            self._set_manual_status("⚠  No PCAP file loaded — analyze a file first", "#fb923c")
            return
        ts = self._tshark()
        if not ts:
            self._set_manual_status("⚠  tshark not found — install Wireshark", "#fb923c")
            return
        self._set_manual_status("  ⏳  Running filter…", "#7c6af7")
        self._manual_table.setRowCount(0)

        # run in thread to avoid UI freeze
        import threading
        def _fetch():
            cmd = [ts, "-r", self._pcap_path, "-Y", flt,
                   "-T", "fields",
                   "-e", "frame.number",
                   "-e", "frame.time_relative",
                   "-e", "frame.time_delta",
                   "-e", "ip.src", "-e", "ip.dst",
                   "-e", "_ws.col.Protocol",
                   "-e", "frame.len",
                   "-E", "separator=|",
                   "-c", "200"]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30)
                rows = []
                for line in out.decode(errors="replace").splitlines():
                    parts = (line + "||||||").split("|")
                    try:
                        delta = float(parts[2]) * 1000 if parts[2].strip() else 0
                        rows.append({
                            "num":   parts[0].strip(),
                            "time":  parts[1].strip(),
                            "delta": f"{delta:.3f}",
                            "src":   parts[3].strip(),
                            "dst":   parts[4].strip(),
                            "proto": parts[5].strip(),
                            "len":   parts[6].strip(),
                        })
                    except Exception:
                        pass
                self._manual_finished.emit(rows, "")
            except subprocess.TimeoutExpired:
                self._manual_finished.emit([], "Query timed out — try a more specific filter")
            except Exception as e:
                self._manual_finished.emit([], str(e))

        threading.Thread(target=_fetch, daemon=True).start()

    def _populate_manual(self, rows: list, err: str):
        if err:
            self._set_manual_status(f"⚠  {err}", "#fb923c")
            return
        if not rows:
            self._set_manual_status(
                "  No packets matched — check filter syntax  "
                "(use ip.src not ip.source, == not =)", _SUBTEXT
            )
            return

        self._manual_table.setRowCount(len(rows))
        proto_colors = {"TCP": "#60a5fa", "UDP": "#34d399", "ARP": "#fbbf24",
                        "ICMP": "#c084fc", "HTTP": _ACCENT2, "MODBUS": _ORANGE}
        for row, p in enumerate(rows):
            for col, (val, color) in enumerate(zip(
                [p["num"], p["time"], p["delta"], p["src"], p["dst"], p["proto"], p["len"]],
                [_ACCENT2, _SUBTEXT, "#fbbf24", _TEXT, _TEXT,
                 proto_colors.get(p["proto"], _SUBTEXT), _SUBTEXT]
            )):
                item = QTableWidgetItem(val)
                item.setForeground(QColor(color))
                if col in (0, 2, 6):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._manual_table.setItem(row, col, item)
            self._manual_table.setRowHeight(row, 28)
        self._set_manual_status(
            f"  ✅  {len(rows)} packets matched  ·  filter: {self._manual_input.text().strip()}",
            _GREEN,
        )

    def _set_manual_status(self, msg: str, color: str):
        self._manual_status.setStyleSheet(
            f"color:{color};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {color}60;padding:5px 10px;"
        )
        self._manual_status.setText(msg)

    # ── widget helpers ────────────────────────────────────────────────────────

    def _action_btn(self, text, bg, bg_hover, slot,
                    text_color="white", border="none") -> QPushButton:
        btn = QPushButton(text)
        btn.setFixedHeight(36)
        btn.setStyleSheet(
            f"QPushButton{{background:{bg};color:{text_color};"
            f"border:1px solid {border};border-radius:8px;"
            f"font-weight:700;font-size:12px;padding:0 16px;}}"
            f"QPushButton:hover{{background:{bg_hover};}}"
        )
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(slot)
        return btn

    def _tab_btn(self, label, active: bool) -> QPushButton:
        btn = QPushButton(label)
        btn.setCheckable(True)
        btn.setChecked(active)
        btn.setFixedHeight(30)
        btn.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_SUBTEXT};"
            f"border:1px solid {_BORDER};border-radius:6px;"
            f"font-size:12px;font-weight:600;padding:0 14px;}}"
            f"QPushButton:checked{{background:{_ACCENT}30;color:{_ACCENT2};"
            f"border-color:{_ACCENT};}}"
        )
        btn.clicked.connect(self._switch_result_tab)
        return btn

    def _make_table(self, headers: list[str], col_widths: list[int]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(
            len(headers) - 1, QHeaderView.ResizeMode.Stretch
        )
        for i, w in enumerate(col_widths):
            t.horizontalHeader().resizeSection(i, w)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setStyleSheet(
            f"QTableWidget{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;color:{_TEXT};}}"
            f"QTableWidget::item{{padding:7px 10px;}}"
            f"QHeaderView::section{{background:{_BG};color:{_SUBTEXT};"
            f"padding:8px 10px;border:none;border-bottom:2px solid {_BORDER};"
            f"font-weight:700;font-size:11px;letter-spacing:1px;}}"
        )
        return t

    # ── row management ────────────────────────────────────────────────────────

    def _add_row(self):
        row = ConditionRow(len(self._rows), self)
        row.set_protocol_options(self._protocol_options)
        row.removed.connect(self._remove_row)
        row.changed.connect(self._update_preview)
        self._rows.append(row)
        # insert before the stretch at the end
        self._rows_layout.insertWidget(self._rows_layout.count() - 1, row)
        self._update_row_logic_visibility()
        self._update_preview()

    def _remove_row(self, row: ConditionRow):
        if len(self._rows) <= 1:
            return  # keep at least one
        self._rows.remove(row)
        self._rows_layout.removeWidget(row)
        row.deleteLater()
        self._update_row_logic_visibility()
        self._update_preview()

    def _update_row_logic_visibility(self):
        for i, row in enumerate(self._rows):
            row.set_logic_visible(i > 0)

    # ── filter expression builder ─────────────────────────────────────────────

    def _build_expression(self) -> str:
        parts = []
        for i, row in enumerate(self._rows):
            val = row.value()
            if not val:
                continue
            field  = row.field_key()
            op     = row.operator()
            logic  = row.logic() if i > 0 else ""

            # human-readable expression
            op_str = {"≠": "!=", "≥": ">=", "≤": "<="}.get(op, op)
            expr = f'{field} {op_str} "{val}"'

            if op == "contains":
                expr = f'{field} contains "{val}"'
            elif op == "not contains":
                expr = f'{field} not contains "{val}"'
            elif op == "starts with":
                expr = f'{field} starts_with "{val}"'
            elif op == "in list":
                expr = f'{field} in [{val}]'

            parts.append(f"{logic + '  ' if logic else ''}{expr}")

        return "  \n".join(parts) if parts else ""

    def _update_preview(self):
        expr = self._build_expression()
        self._preview.setPlainText(expr)

    # ── filter application ────────────────────────────────────────────────────

    def _apply(self):
        findings, flows = self._current_query_data()
        if findings is None or flows is None:
            self._result_count.setText("⚠  No data — analyze a file first")
            return

        self._hint.setVisible(False)

        findings = list(findings)
        flows    = list(flows)
        base_findings = list(findings)
        base_flows = list(flows)

        for i, row in enumerate(self._rows):
            val = row.value()
            if not val:
                continue
            field  = row.field_key()
            op     = row.operator()
            logic  = row.logic() if i > 0 else "AND"

            def matches_finding(f, field=field, op=op, val=val) -> bool:
                fval = str(f.get(field, "")).lower()
                v = val.lower()
                if op in ("=", "=="): return fval == v
                if op in ("≠", "!="): return fval != v
                if op == "contains": return v in fval
                if op == "not contains": return v not in fval
                if op == "starts with": return fval.startswith(v)
                if op == "in list":
                    return fval in [x.strip().lower() for x in val.split(",")]
                try:
                    n, fv = float(val), float(fval)
                    if op == ">": return fv > n
                    if op == "<": return fv < n
                    if op in ("≥", ">="): return fv >= n
                    if op in ("≤", "<="): return fv <= n
                except ValueError:
                    pass
                return False

            def matches_flow(f, field=field, op=op, val=val) -> bool:
                fval = str(f.get(field, "")).lower()
                v = val.lower()
                if op in ("=", "=="): return fval == v
                if op in ("≠", "!="): return fval != v
                if op == "contains": return v in fval
                if op == "starts with": return fval.startswith(v)
                try:
                    n, fv = float(val), float(fval)
                    if op == ">": return fv > n
                    if op == "<": return fv < n
                    if op in ("≥", ">="): return fv >= n
                    if op in ("≤", "<="): return fv <= n
                except ValueError:
                    pass
                return False

            if logic == "AND":
                findings = [f for f in findings if matches_finding(f)]
                flows    = [f for f in flows    if matches_flow(f)]
            else:  # OR — union with previously excluded
                all_f = base_findings
                all_v = base_flows
                findings = list({id(f): f for f in findings + [
                    x for x in all_f if matches_finding(x)]}.values())
                flows = list({id(f): f for f in flows + [
                    x for x in all_v if matches_flow(x)]}.values())

        self._populate_findings(findings)
        self._populate_flows(flows)
        self._result_count.setText(
            f"{len(findings)} findings · {len(flows)} flows matched"
        )
        self.filter_applied.emit(findings, flows)
        if len(findings) == 0 and len(flows) == 0:
            self._result_count.setText(
                "⚠  No matches — try a different field, operator or value"
            )

    def _reset_results(self):
        findings, flows = self._current_query_data()
        if findings is None or flows is None:
            return
        self._populate_findings(findings)
        self._populate_flows(flows)
        total_f = len(findings)
        total_v = len(flows)
        self._result_count.setText(f"Showing all: {total_f} findings · {total_v} flows")

    def _clear_all(self):
        while len(self._rows) > 1:
            row = self._rows[-1]
            self._rows.remove(row)
            self._rows_layout.removeWidget(row)
            row.deleteLater()
        if self._rows:
            # reset the last remaining row
            self._rows[0].deleteLater()
            self._rows.clear()
        self._add_row()
        self._preview.clear()
        self._tbl_findings.setRowCount(0)
        self._tbl_flows.setRowCount(0)
        self._result_count.setText("")

    def _copy_filter(self):
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self._preview.toPlainText())
        self._result_count.setText("✅  Filter copied to clipboard")

    # ── result tab switch ─────────────────────────────────────────────────────

    def _switch_result_tab(self):
        show_findings = self._btn_tab_findings.isChecked()
        self._btn_tab_findings.setChecked(show_findings)
        self._btn_tab_flows.setChecked(not show_findings)
        self._tbl_findings.setVisible(show_findings)
        self._tbl_flows.setVisible(not show_findings)

    # ── table populate ────────────────────────────────────────────────────────

    def _populate_findings(self, findings: list):
        t = self._tbl_findings
        t.setRowCount(len(findings))
        for row, f in enumerate(findings):
            sev = f.get("severity", "info")
            fg  = QColor(_SEV_FG.get(sev, _TEXT))
            pkt = f.get("pkt_num", "")
            ni  = QTableWidgetItem(str(pkt))
            ni.setForeground(QColor(_ACCENT2))
            ni.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            si  = QTableWidgetItem(_SEV_TAG.get(sev, sev.upper()))
            si.setForeground(fg)
            si.setBackground(QColor(_SEV_BG.get(sev, _CARD)))
            si.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            pi  = QTableWidgetItem(f.get("protocol", "—"))
            pi.setForeground(QColor(_SUBTEXT))
            mi  = QTableWidgetItem(f.get("msg", ""))
            mi.setForeground(QColor(_TEXT))
            t.setItem(row, 0, ni)
            t.setItem(row, 1, si)
            t.setItem(row, 2, pi)
            t.setItem(row, 3, mi)
            t.setRowHeight(row, 30)

    def _populate_flows(self, flows: list):
        t = self._tbl_flows
        t.setRowCount(len(flows))
        for row, f in enumerate(flows):
            t.setItem(row, 0, QTableWidgetItem(f.get("src", "")))
            t.setItem(row, 1, QTableWidgetItem(f.get("dst", "")))
            pi = QTableWidgetItem(f.get("protocol", ""))
            pi.setForeground(QColor(_ACCENT2))
            ci = QTableWidgetItem(str(f.get("packets", "")))
            ci.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            t.setItem(row, 2, pi)
            t.setItem(row, 3, ci)
            t.setRowHeight(row, 30)

    # ── source adapters ─────────────────────────────────────────────────────

    @staticmethod
    def _ports_from_packet_info(pkt: dict) -> tuple[str, str]:
        info = str(pkt.get("info", ""))
        if "→" not in info:
            return "", ""
        lhs, rhs = info.split("→", 1)
        sport = "".join(ch for ch in lhs if ch.isdigit())
        dport = ""
        for token in rhs.split():
            if token.isdigit():
                dport = token
                break
        return sport, dport

    def _build_from_live_packets(self) -> tuple[list[dict], list[dict]]:
        findings: list[dict] = []
        flow_counts: dict[tuple[str, str, str], int] = {}

        for pkt in self._live_packets:
            proto = str(pkt.get("proto", "OTHER") or "OTHER")
            src = str(pkt.get("src", "") or "")
            dst = str(pkt.get("dst", "") or "")
            sport, dport = self._ports_from_packet_info(pkt)

            src_ep = f"{src}:{sport}" if src and sport else src
            dst_ep = f"{dst}:{dport}" if dst and dport else dst
            if src_ep and dst_ep:
                key = (src_ep, dst_ep, proto)
                flow_counts[key] = flow_counts.get(key, 0) + 1

            findings.append({
                "pkt_num": pkt.get("num", ""),
                "severity": (pkt.get("severity") or "info"),
                "protocol": proto,
                "msg": pkt.get("info", ""),
                "src": src,
                "dst": dst,
                "src_port": sport,
                "dst_port": dport,
                "packets": 1,
            })

        flows = [
            {"src": src, "dst": dst, "protocol": proto, "packets": count}
            for (src, dst, proto), count in flow_counts.items()
        ]
        flows.sort(key=lambda f: f["packets"], reverse=True)
        return findings, flows

    def _current_query_data(self) -> tuple[list[dict] | None, list[dict] | None]:
        if self._live_packets:
            self._source_lbl.setText(
                f"Data source: Live capture ({len(self._live_packets):,} packets buffered)"
            )
            return self._build_from_live_packets()
        if self._report is None:
            self._source_lbl.setText("Data source: None")
            return None, None
        self._source_lbl.setText("Data source: Offline analysis report")
        return list(self._report.get("findings", [])), list(self._report.get("flows", []))

    def _refresh_protocol_options(self):
        values = {p.upper() for p in PROTOCOLS}

        if self._report:
            for proto in self._report.get("protocol_summary", {}).keys():
                if proto:
                    values.add(str(proto).upper())
            for f in self._report.get("findings", []):
                if f.get("protocol"):
                    values.add(str(f.get("protocol")).upper())

        for pkt in self._live_packets[-2000:]:
            proto = str(pkt.get("proto", "") or "").upper()
            if proto:
                values.add(proto)

        self._protocol_options = sorted(values)
        for row in self._rows:
            row.set_protocol_options(self._protocol_options)
