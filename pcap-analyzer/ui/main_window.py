import os
import zipfile
from collections import Counter
import csv
import datetime
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QProgressBar, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QLineEdit, QTextEdit, QSplitter, QMessageBox, QStyledItemDelegate,
    QStyleOptionViewItem,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import (
    QColor, QFont, QDragEnterEvent, QDropEvent, QIcon, QKeySequence,
    QBrush, QPainter,
)
from PyQt6.QtGui import QShortcut

from analyzer.report import build_report, build_multi_report
from ui.live_panel import LivePanel
from ui.query_builder import QueryBuilderPanel
from ui.compare_panel import ComparePanel
from ui.packet_inspector import PacketInspector
from ui.calculator import PacketCalculator
from ui.path_check_panel import PathCheckPanel

# Set to True to re-enable the optional AI Assistant tab.
_ENABLE_ASSISTANT_TAB = False

# ── palette ───────────────────────────────────────────────────────────────────
_BG      = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD    = "#16213e"
_BORDER  = "#2a2a4a"
_ACCENT  = "#7c6af7"
_ACCENT2 = "#a78bfa"
_GREEN   = "#22c55e"
_TEXT    = "#e2e8f0"
_SUBTEXT = "#64748b"

_SEV_FG  = {"error": "#f87171", "warn": "#fb923c", "info": "#60a5fa"}
_SEV_BG  = {"error": "#2d1515", "warn": "#2d1f10", "info": "#0f1f35"}
_SEV_TAG = {"error": "● ERROR", "warn": "▲ WARN", "info": "ℹ  INFO"}

_QSS = f"""
QMainWindow, QWidget {{
    background:{_BG}; color:{_TEXT};
    font-family:'Segoe UI',sans-serif; font-size:13px;
}}
QTabWidget::pane {{
    border:1px solid {_BORDER}; border-radius:10px;
    background:{_SURFACE}; margin-top:-1px;
}}
QTabBar {{
    background:transparent;
}}
QTabBar::tab {{
    background:transparent; color:{_SUBTEXT};
    padding:8px 12px; border-radius:8px 8px 0 0;
    margin-right:2px; font-weight:600; font-size:12px;
    border:1px solid transparent; border-bottom:none;
}}
QTabBar::tab:selected {{
    background:{_SURFACE}; color:{_ACCENT2};
    border:1px solid {_BORDER}; border-bottom:2px solid {_ACCENT};
}}
QTabBar::tab:hover:!selected {{
    color:{_TEXT}; background:{_CARD};
}}
QTableWidget {{
    background:{_SURFACE}; gridline-color:{_BORDER};
    border:none; border-radius:8px; color:{_TEXT};
    selection-background-color:#2a2a5a;
    alternate-background-color:{_CARD};
}}
QTableWidget::item {{
    padding:8px 12px; border:none;
}}
QTableWidget::item:selected {{
    background:#2a2a5a; color:{_TEXT};
}}
QHeaderView::section {{
    background:{_BG}; color:{_SUBTEXT};
    padding:10px 12px; border:none;
    border-right:2px solid {_BORDER};
    border-bottom:2px solid {_BORDER};
    font-weight:700; font-size:11px; letter-spacing:1px;
}}
QTextEdit {{
    background:{_SURFACE}; color:{_TEXT};
    border:none; border-radius:8px;
    padding:14px; font-family:'Segoe UI',sans-serif; font-size:13px;
    line-height:1.6;
}}
QLineEdit {{
    background:{_CARD}; color:{_TEXT};
    border:1px solid {_BORDER}; border-radius:8px;
    padding:9px 14px; font-size:13px;
    selection-background-color:{_ACCENT};
}}
QLineEdit:focus {{
    border:1px solid {_ACCENT};
    background:#1a1a35;
}}
QLineEdit:hover {{
    border:1px solid #3a3a6a;
}}
QProgressBar {{
    background:{_BORDER}; border-radius:4px; height:6px; border:none;
}}
QProgressBar::chunk {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {_ACCENT},stop:0.5 {_ACCENT2},stop:1 #c4b5fd);
    border-radius:4px;
}}
QPushButton {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {_ACCENT},stop:1 {_ACCENT2});
    color:white; border:none; border-radius:8px;
    padding:9px 20px; font-weight:700; font-size:13px;
}}
QPushButton:hover {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #9580ff,stop:1 #b99dff);
}}
QPushButton:pressed {{
    background:{_ACCENT};
}}
QPushButton#btn_analyze {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #16a34a,stop:1 #22c55e);
    padding:9px 28px; font-size:14px;
}}
QPushButton#btn_analyze:hover {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #15803d,stop:1 #16a34a);
}}
QScrollBar:vertical {{
    background:transparent; width:6px; border-radius:3px;
}}
QScrollBar::handle:vertical {{
    background:{_BORDER}; border-radius:3px; min-height:24px;
}}
QScrollBar::handle:vertical:hover {{
    background:{_SUBTEXT};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{
    background:transparent; height:6px; border-radius:3px;
}}
QScrollBar::handle:horizontal {{
    background:{_BORDER}; border-radius:3px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width:0; }}
QToolTip {{
    background:{_CARD}; color:{_TEXT}; border:1px solid {_BORDER};
    border-radius:6px; padding:4px 8px; font-size:12px;
}}
"""


# ── worker thread ──────────────────────────────────────────────────────────────
class _Worker(QThread):
    finished = pyqtSignal(dict)
    error    = pyqtSignal(str)

    def __init__(self, path: str, user_filter: str):
        super().__init__()
        self._path   = path
        self._filter = user_filter or None

    def run(self):
        try:
            if os.path.isdir(self._path) or zipfile.is_zipfile(self._path):
                report = build_multi_report(self._path, self._filter)
            else:
                report = build_report(self._path, self._filter)
            self.finished.emit(report)
        except Exception as e:
            self.error.emit(str(e))


# ── stat card helper ───────────────────────────────────────────────────────────
def _card(title: str, value: str, color: str) -> QFrame:
    f = QFrame()
    f.setStyleSheet(
        f"QFrame{{"
        f"background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
        f"stop:0 #1e1e35,stop:1 {_CARD});"
        f"border:1px solid {color}30;"
        f"border-top:2px solid {color};"
        f"border-radius:10px;"
        f"}}"
        f"QFrame:hover{{"
        f"border:1px solid {color}80;"
        f"border-top:2px solid {color};"
        f"background:qlineargradient(x1:0,y1:0,x2:0,y2:1,"
        f"stop:0 #252545,stop:1 #1a1a30);"
        f"}}"
    )
    v = QVBoxLayout(f)
    v.setContentsMargins(10, 7, 10, 7)
    v.setSpacing(2)
    lv = QLabel(value)
    lv.setStyleSheet(
        f"color:{color};font-size:20px;font-weight:800;"
        f"border:none;letter-spacing:-0.5px;"
    )
    lt = QLabel(title)
    lt.setStyleSheet(
        f"color:{_SUBTEXT};font-size:9px;font-weight:700;"
        f"letter-spacing:1px;border:none;"
    )
    v.addWidget(lv)
    v.addWidget(lt)
    return f


class _FlowBatchDelegate(QStyledItemDelegate):
    """Paint two consecutive flow rows with one repeating batch color."""

    _COLORS = (QColor("#191a2e"), QColor("#172442"))

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index):
        painter.save()
        painter.fillRect(option.rect, self._COLORS[(index.row() // 2) % 2])
        painter.restore()

        clean_option = QStyleOptionViewItem(option)
        clean_option.backgroundBrush = QBrush(Qt.BrushStyle.NoBrush)
        super().paint(painter, clean_option, index)


# ── main window ────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self, start_mode: str = "offline"):
        super().__init__()
        self.setWindowTitle("PCAP Analyzer")
        self.setMinimumSize(1200, 780)
        self.setAcceptDrops(True)
        self.setStyleSheet(_QSS)
        self._pcap_path = ""
        self._worker    = None
        self._zoom      = 13
        self._build_ui()
        self._setup_zoom_shortcuts()
        # jump to Live tab if that mode was selected
        if start_mode == "live":
            self._tabs.setCurrentWidget(self._tab_live)

    # ── build ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(16, 12, 16, 12)
        vbox.setSpacing(10)

        vbox.addWidget(self._mk_header())
        vbox.addWidget(self._mk_input_card())

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._progress.setFixedHeight(5)
        self._progress.setTextVisible(False)
        vbox.addWidget(self._progress)

        self._stats_row = self._mk_stats_row()
        vbox.addWidget(self._stats_row)

        self._tabs = QTabWidget()
        self._tab_summary  = self._mk_summary_tab()
        self._tab_findings_widget, self._tab_findings, self._inspector_findings = \
            self._mk_findings_with_inspector()
        self._tab_flows_widget, self._tab_flows, self._inspector_flows = \
            self._mk_flows_with_inspector()
        self._tab_protos   = self._mk_proto_table()
        self._tab_chat     = None
        if _ENABLE_ASSISTANT_TAB:
            from ui.chatbot import ChatPanel
            self._tab_chat = ChatPanel(
                bg=_BG, surface=_CARD, accent=_ACCENT,
                text=_TEXT, subtext=_SUBTEXT, border=_BORDER,
                sev_fg=_SEV_FG,
            )
        self._tab_live     = LivePanel()
        self._tab_query    = QueryBuilderPanel()
        self._tab_compare  = ComparePanel()
        self._tab_calc     = PacketCalculator()
        self._tab_path     = PathCheckPanel()
        self._tabs.addTab(self._tab_summary,          " Summary ")
        self._tabs.addTab(self._tab_findings_widget,  " Findings ")
        self._tabs.addTab(self._tab_flows_widget,     " Flows ")
        self._tabs.addTab(self._tab_protos,           " Protocols ")
        self._tabs.addTab(self._tab_query,            " 🔍 Query ")
        self._tabs.addTab(self._tab_compare,          " 🔬 Compare ")
        self._tabs.addTab(self._tab_calc,             " 🧮 Calculator ")
        self._tabs.addTab(self._tab_path,             " 🧊 Freeze ")
        self._tabs.addTab(self._tab_live,             " 📡 Live ")
        if self._tab_chat is not None:
            self._tabs.addTab(self._tab_chat,         " 🤖 AI ")
        vbox.addWidget(self._tabs, 1)

        # click row → show inspector panel inline
        self._tab_findings.cellClicked.connect(self._on_finding_click)
        self._tab_flows.cellClicked.connect(self._on_flow_click)
        # live capture feeds into compare panel
        self._tab_live.packet_for_compare.connect(self._tab_compare.feed_live_packet)
        self._tab_live.stats_for_compare.connect(self._tab_compare.feed_live_stats)
        self._tab_live.live_stopped.connect(self._tab_compare.stop_live)
        # compare panel similarity alert
        self._tab_compare.alert_triggered.connect(self._on_similarity_alert)

        self._statusbar = QLabel("  Open or drop a .pcap / .pcapng file, then click Analyze")
        self._statusbar.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_BORDER};"
            f"padding:5px 10px;"
        )
        vbox.addWidget(self._statusbar)

    def _mk_header(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(
            f"background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 #1a1035,stop:0.5 #16213e,stop:1 #0f2027);"
            f"border-radius:12px;"
            f"border:1px solid {_BORDER};"
        )
        w.setFixedHeight(62)
        h = QHBoxLayout(w)
        h.setContentsMargins(20, 0, 16, 0)
        h.setSpacing(12)

        # logo + title
        title = QLabel("🦈  PCAP Analyzer")
        title.setStyleSheet(
            f"color:{_TEXT};font-size:20px;font-weight:800;"
            f"letter-spacing:-0.5px;background:transparent;"
        )
        badge = QLabel("NETWORK ANALYZER")
        badge.setStyleSheet(
            f"color:{_ACCENT2};font-size:9px;font-weight:700;"
            f"letter-spacing:2px;background:rgba(124,106,247,0.15);"
            f"border:1px solid {_ACCENT}60;border-radius:4px;padding:2px 7px;"
        )
        h.addWidget(title)
        h.addWidget(badge)
        h.addStretch(1)

        # zoom controls
        zoom_frame = QWidget()
        zoom_frame.setStyleSheet(
            f"background:rgba(255,255,255,0.05);border-radius:8px;"
            f"border:1px solid {_BORDER};"
        )
        zf = QHBoxLayout(zoom_frame)
        zf.setContentsMargins(6, 4, 6, 4)
        zf.setSpacing(4)
        for symbol, delta in (("−", -1), ("+", +1)):
            btn = QPushButton(symbol)
            btn.setFixedSize(26, 26)
            btn.setStyleSheet(
                f"QPushButton{{background:transparent;color:{_SUBTEXT};"
                f"border:none;border-radius:5px;"
                f"font-size:15px;font-weight:700;padding:0;}}"
                f"QPushButton:hover{{background:{_ACCENT}30;color:{_ACCENT2};}}"
            )
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, d=delta: self._apply_zoom(d))
            zf.addWidget(btn)
        self._zoom_lbl = QLabel("100%")
        self._zoom_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;min-width:34px;"
            f"background:transparent;"
        )
        self._zoom_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        zf.addWidget(self._zoom_lbl)
        h.addWidget(zoom_frame)
        return w

    def _mk_input_card(self) -> QWidget:
        """Combined file + filter input card."""
        card = QFrame()
        card.setStyleSheet(
            f"QFrame{{background:{_SURFACE};"
            f"border:1px solid {_BORDER};"
            f"border-radius:12px;}}"
        )
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(16, 12, 16, 12)
        vbox.setSpacing(10)

        # ── file row ─────────────────────────────────────────────────────────
        file_row = QWidget()
        file_row.setStyleSheet("background:transparent;")
        fh = QHBoxLayout(file_row)
        fh.setContentsMargins(0, 0, 0, 0)
        fh.setSpacing(10)

        self._drop_lbl = QLabel("⬇  Drop .pcap / .pcapng / .zip / folder here  —  or")
        self._drop_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:13px;font-weight:600;background:transparent;"
        )
        btn_open = QPushButton("  📂  Browse…")
        btn_open.setFixedHeight(36)
        btn_open.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:8px;"
            f"padding:0 14px;font-weight:600;font-size:12px;}}"
            f"QPushButton:hover{{border-color:{_ACCENT};color:{_ACCENT2};"
            f"background:#1e1e3a;}}"
        )
        btn_open.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_open.clicked.connect(self._open_file)

        self._file_lbl = QLabel("No file selected")
        self._file_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-style:italic;font-size:12px;"
            f"background:{_CARD};border:1px dashed {_BORDER}30;"
            f"border-radius:8px;padding:7px 14px;"
        )
        fh.addWidget(self._drop_lbl)
        fh.addWidget(btn_open)
        fh.addWidget(self._file_lbl, 1)
        vbox.addWidget(file_row)

        # ── divider ───────────────────────────────────────────────────────────
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"background:{_BORDER};border:none;max-height:1px;")
        vbox.addWidget(div)

        # ── filter row ────────────────────────────────────────────────────────
        filter_row = QWidget()
        filter_row.setStyleSheet("background:transparent;")
        filt_h = QHBoxLayout(filter_row)
        filt_h.setContentsMargins(0, 0, 0, 0)
        filt_h.setSpacing(10)

        lbl = QLabel("🔍  Filter:")
        lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-weight:700;font-size:12px;"
            f"background:transparent;"
        )
        lbl.setFixedWidth(62)

        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText(
            "Wireshark display filter  e.g.  bacnet   tcp   http   modbus   ip.addr==192.168.1.10"
        )
        self._filter_input.setFixedHeight(36)
        self._filter_input.returnPressed.connect(self._on_analyze)

        btn = QPushButton("  ▶  Analyze")
        btn.setObjectName("btn_analyze")
        btn.setFixedHeight(36)
        btn.setMinimumWidth(120)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(self._on_analyze)

        self._btn_export = QPushButton("  💾  Export Findings")
        self._btn_export.setToolTip("Export Error and Warning findings as TXT, CSV, or HTML")
        self._btn_export.setFixedHeight(36)
        self._btn_export.setEnabled(False)
        self._btn_export.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_SUBTEXT};"
            f"border:1px solid {_BORDER};border-radius:8px;"
            f"padding:0 14px;font-weight:600;font-size:12px;}}"
            f"QPushButton:enabled{{color:{_TEXT};}}"
            f"QPushButton:enabled:hover{{border-color:{_ACCENT};color:{_ACCENT2};"
            f"background:#1e1e3a;}}"
        )
        self._btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_export.clicked.connect(self._export_log)

        filt_h.addWidget(lbl)
        filt_h.addWidget(self._filter_input, 1)
        filt_h.addWidget(btn)
        filt_h.addWidget(self._btn_export)
        vbox.addWidget(filter_row)
        return card

    def _mk_stats_row(self) -> QWidget:
        w = QWidget()
        w.setVisible(False)
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        self._c_packets  = _card("PACKETS ANALYZED", "—", _ACCENT2)
        self._c_flows    = _card("FLOWS", "—", "#34d399")
        self._c_errors   = _card("ERRORS", "—", _SEV_FG["error"])
        self._c_warnings = _card("WARNINGS", "—", _SEV_FG["warn"])
        self._c_info     = _card("INFO", "—", _SEV_FG["info"])
        for c in (self._c_packets, self._c_flows, self._c_errors, self._c_warnings, self._c_info):
            h.addWidget(c, 1)
        return w

    def _mk_summary_tab(self) -> QTextEdit:
        t = QTextEdit()
        t.setReadOnly(True)
        return t

    # ── zoom ──────────────────────────────────────────────────────────────────

    def _setup_zoom_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+="), self).activated.connect(lambda: self._apply_zoom(+1))
        QShortcut(QKeySequence("Ctrl++"), self).activated.connect(lambda: self._apply_zoom(+1))
        QShortcut(QKeySequence("Ctrl+-"), self).activated.connect(lambda: self._apply_zoom(-1))
        QShortcut(QKeySequence("Ctrl+0"), self).activated.connect(self._reset_zoom)

    def _apply_zoom(self, delta: int):
        self._zoom = max(9, min(24, self._zoom + delta))
        self._zoom_lbl.setText(f"{round(self._zoom / 13 * 100)}%")
        font = QFont("Segoe UI", self._zoom)
        for widget in (
            self._tab_summary, self._tab_findings,
            self._tab_flows, self._tab_protos,
        ):
            widget.setFont(font)
        # summary is HTML — re-render at new size only if report is loaded
        self._tab_summary.setStyleSheet(
            f"QTextEdit{{background:{_SURFACE};color:{_TEXT};border:none;"
            f"border-radius:6px;padding:12px;font-family:'Segoe UI',sans-serif;"
            f"font-size:{self._zoom}px;}}"
        )

    def _reset_zoom(self):
        self._zoom = 13
        self._apply_zoom(0)

    def _mk_findings_with_inspector(self):
        """Findings table + PacketInspector in a vertical splitter."""
        outer = QWidget()
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Packet number"))
        self._findings_packet_filter = QLineEdit()
        self._findings_packet_filter.setPlaceholderText("Filter packet number, e.g. 298436 or 298436-298440")
        self._findings_packet_filter.setFixedHeight(30)
        self._findings_packet_filter.textChanged.connect(self._filter_findings)
        filter_row.addWidget(self._findings_packet_filter, 1)
        outer_layout.addLayout(filter_row)
        resize_hint = QLabel("↔  Drag the bright vertical lines in the table header to resize columns")
        resize_hint.setStyleSheet(
            f"color:{_ACCENT2};font-size:11px;font-weight:600;"
            f"background:{_CARD};border-left:3px solid {_ACCENT};"
            f"padding:5px 8px;"
        )
        outer_layout.addWidget(resize_hint)
        container = QSplitter(Qt.Orientation.Vertical)
        container.setStyleSheet(
            f"QSplitter::handle{{background:{_BORDER};height:3px;}}"
        )
        table = self._mk_findings_table()
        inspector = PacketInspector()
        container.addWidget(table)
        container.addWidget(inspector)
        container.setSizes([9999, 0])   # inspector collapsed until a row is clicked
        container.setCollapsible(1, False)
        self._findings_splitter = container
        outer_layout.addWidget(container, 1)
        return outer, table, inspector

    def _mk_flows_with_inspector(self):
        """Flows table + PacketInspector in a vertical splitter."""
        container = QSplitter(Qt.Orientation.Vertical)
        container.setStyleSheet(
            f"QSplitter::handle{{background:{_BORDER};height:3px;}}"
        )
        table = self._mk_flows_table()
        inspector = PacketInspector()
        container.addWidget(table)
        container.addWidget(inspector)
        container.setSizes([9999, 0])
        container.setCollapsible(1, False)
        return container, table, inspector

    def _mk_findings_table(self) -> QTableWidget:
        t = QTableWidget(0, 6)
        t.setHorizontalHeaderLabels(["File #", "File Name", "Pkt #", "Severity", "Protocol", "Details"])
        t.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        t.horizontalHeader().setCursor(Qt.CursorShape.SizeHorCursor)
        t.horizontalHeader().setStyleSheet(
            f"QHeaderView::section{{border-right:1px solid {_BORDER};"
            f"border-bottom:2px solid {_BORDER};padding:10px 12px;}}"
        )
        t.horizontalHeader().resizeSection(0, 60)
        t.horizontalHeader().resizeSection(1, 220)
        t.horizontalHeader().resizeSection(2, 60)
        t.horizontalHeader().resizeSection(3, 100)
        t.horizontalHeader().resizeSection(4, 100)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        return t

    def _mk_flows_table(self) -> QTableWidget:
        t = QTableWidget(0, 4)
        t.setHorizontalHeaderLabels(["Source", "Destination", "Protocol", "Packets"])
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        t.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        t.horizontalHeader().resizeSection(2, 120)
        t.horizontalHeader().resizeSection(3, 90)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setAlternatingRowColors(False)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        t.setItemDelegate(_FlowBatchDelegate(t))
        return t

    def _mk_proto_table(self) -> QTableWidget:
        t = QTableWidget(0, 2)
        t.setHorizontalHeaderLabels(["Protocol", "Packets"])
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        t.horizontalHeader().resizeSection(1, 120)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(False)
        return t

    # ── drag & drop ────────────────────────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                local = url.toLocalFile()
                if (local.lower().endswith(('.pcap', '.pcapng', '.zip'))
                        or os.path.isdir(local)):
                    self._drop_lbl.setStyleSheet(
                        f"color:{_ACCENT};font-size:13px;font-weight:700;")
                    event.acceptProposedAction()
                    return

    def dragLeaveEvent(self, event):
        self._reset_drop_style()

    def dropEvent(self, event: QDropEvent):
        self._reset_drop_style()
        urls = event.mimeData().urls()
        if urls:
            self._set_file(urls[0].toLocalFile())

    def _reset_drop_style(self):
        self._drop_lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:13px;font-weight:600;")

    # ── file selection ─────────────────────────────────────────────────────────

    def _open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP / PCAPNG / ZIP",
            "",
            "Supported captures (*.pcap *.pcapng *.zip);;All files (*)",
        )
        if path:
            self._set_file(path)

    def _set_file(self, path: str):
        self._pcap_path = path
        self._tab_path.set_pcap(path)
        name = os.path.basename(path)
        is_zip = path.lower().endswith('.zip') or (
            os.path.isfile(path) and zipfile.is_zipfile(path))
        is_dir = os.path.isdir(path)
        icon  = "📦" if is_zip else "📁" if is_dir else "📄"
        hint  = " (ZIP — multiple PCAPs)" if is_zip else (" (folder)" if is_dir else "")
        self._file_lbl.setText(f"  {icon}  {name}{hint}")
        self._file_lbl.setStyleSheet(
            f"color:{_TEXT};font-style:normal;font-size:12px;"
            f"background:{_CARD};"
            f"border:1px solid {_ACCENT}50;"
            f"border-radius:8px;padding:7px 14px;")
        self._statusbar.setText(
            f"  {icon}  {name}{hint}  ·  Enter a filter (optional) and click Analyze")

    # ── analyze ────────────────────────────────────────────────────────────────

    def _on_analyze(self):
        if not self._pcap_path:
            self._statusbar.setText("⚠  Please open a file first")
            return
        user_filter = self._filter_input.text().strip()
        label = f"Filter: {user_filter}" if user_filter else "No filter (all packets)"
        self._statusbar.setText(f"Analyzing…  {label}")
        self._progress.setVisible(True)
        self._stats_row.setVisible(False)
        self._clear_tables()

        self._worker = _Worker(self._pcap_path, user_filter)
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    # ── results ────────────────────────────────────────────────────────────────

    def _on_done(self, r: dict):
        self._progress.setVisible(False)
        n_err  = sum(1 for f in r["findings"] if f["severity"] == "error")
        n_warn = sum(1 for f in r["findings"] if f["severity"] == "warn")
        n_info = sum(1 for f in r["findings"] if f["severity"] == "info")
        flow_pairs = {
            f.get("pair_key", f"{f.get('protocol','')}|{f.get('src','')}|{f.get('dst','')}")
            for f in r["flows"]
        }

        self._card_val(self._c_packets,  str(r["total_packets"]))
        self._card_val(self._c_flows,    str(len(flow_pairs)))
        self._card_val(self._c_errors,   str(n_err))
        self._card_val(self._c_warnings, str(n_warn))
        self._card_val(self._c_info,     str(n_info))
        self._stats_row.setVisible(True)

        self._populate_summary(r)
        self._populate_findings(r["findings"])
        self._populate_flows(r["flows"])
        self._populate_protocols(r["protocol_summary"])
        self._last_findings = r["findings"]   # for Inspector click
        self._last_flows    = r["flows"]
        self._last_report   = r
        self._tab_path.set_pcap(self._pcap_path)
        self._tab_path.set_report(r)
        self._btn_export.setEnabled(bool(r["findings"]))
        if self._tab_chat is not None:
            self._tab_chat.set_report(r)
        self._tab_query.set_report(r)
        self._tab_query.set_pcap(self._pcap_path)
        from analyzer.smart_query import set_pcap as set_ai_pcap
        set_ai_pcap(self._pcap_path)
        self._tab_compare.set_offline_report(r)
        self._tab_compare.set_offline_path(self._pcap_path)
        self._tab_calc.set_pcap(self._pcap_path)
        self._tabs.setCurrentIndex(0)

        fname = os.path.basename(self._pcap_path)
        uf    = r.get("user_filter", "")
        if r.get("multi_file"):
            label = f"{r['file_count']} files  ·  {r['total_packets']:,} packets total"
        else:
            label = f"{fname}  ·  {r['total_packets']:,} packets"
        self._statusbar.setStyleSheet(
            f"color:{_GREEN};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_GREEN};"
            f"padding:5px 10px;"
        )
        self._statusbar.setText(
            f"  ✅  Done — {label}  ·  "
            f"Filter: {uf or 'none'}  ·  "
            f"{n_err} errors, {n_warn} warnings")

    def _on_error(self, msg: str):
        self._progress.setVisible(False)
        self._statusbar.setStyleSheet(
            f"color:{_SEV_FG['error']};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_SEV_FG['error']};"
            f"padding:5px 10px;"
        )
        self._statusbar.setText(f"  ⚠  Error: {msg}")

    def _on_finding_click(self, row: int, _col: int):
        visible_findings = getattr(self, "_visible_findings", getattr(self, "_last_findings", []))
        if row >= len(visible_findings):
            return
        self._inspector_findings.inspect_finding(visible_findings[row])
        # expand inspector panel if it was collapsed
        sizes = self._findings_splitter.sizes()
        if sizes[1] < 50:
            total = sum(sizes)
            self._findings_splitter.setSizes([int(total * 0.55), int(total * 0.45)])

    def _on_flow_click(self, row: int, _col: int):
        if not hasattr(self, '_last_flows') or row >= len(self._last_flows):
            return
        self._inspector_flows.inspect_flow(self._last_flows[row])
        sizes = self._tab_flows_widget.sizes()
        if sizes[1] < 50:
            total = sum(sizes)
            self._tab_flows_widget.setSizes([int(total * 0.55), int(total * 0.45)])

    def _on_similarity_alert(self, score: float, level: str):
        """Flash the Compare tab label when similarity is high."""
        pct = int(score * 100)
        color = '#f87171' if level == 'critical' else '#fb923c'
        compare_idx = [self._tabs.tabText(i).strip()
                       for i in range(self._tabs.count())].index('🔬 Compare')
        self._tabs.setTabText(compare_idx, f" 🔬 Compare 🚨{pct}% ")
        self._tabs.tabBar().setTabTextColor(compare_idx, QColor(color))
        self._statusbar.setStyleSheet(
            f"color:{color};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {color};padding:5px 10px;"
        )
        self._statusbar.setText(
            f"  🚨  BEHAVIOR MATCH DETECTED — live traffic is {pct}% similar "
            f"to uploaded PCAP!  ({level.upper()})  Click '🔬 Compare' tab to review."
        )

    def _card_val(self, card: QFrame, val: str):
        card.findChildren(QLabel)[0].setText(val)

    def _clear_tables(self):
        self._tab_findings.setRowCount(0)
        self._tab_flows.setRowCount(0)
        self._tab_protos.setRowCount(0)
        self._tab_summary.clear()
        self._btn_export.setEnabled(False)

    # ── export log ─────────────────────────────────────────────────────────────

    def _export_log(self):
        r        = getattr(self, "_last_report", {})
        findings = [f for f in r.get("findings", [])
                    if f["severity"] in ("error", "warn")]
        if not findings:
            QMessageBox.information(self, "Export Findings", "No errors or warnings to export.")
            return

        is_multi  = r.get("multi_file", False)
        src_name  = (f"{r.get('file_count', '?')} files"
                     if is_multi else os.path.basename(self._pcap_path))
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default   = f"pcap_issues_{timestamp}"

        path, sel_filter = QFileDialog.getSaveFileName(
            self, "Export Findings", default,
            "Text log (*.txt);;CSV (*.csv);;HTML report (*.html)")
        if not path:
            return

        try:
            if path.endswith(".csv"):
                self._export_csv(path, findings, is_multi, src_name)
            elif path.endswith(".html"):
                self._export_html(path, findings, is_multi, src_name, r)
            else:
                self._export_txt(path, findings, is_multi, src_name, r)

            self._statusbar.setText(f"  ✅  Log saved → {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    def _export_txt(self, path: str, findings: list, is_multi: bool,
                    src_name: str, r: dict):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "=" * 70,
            "  PCAP ANALYZER — ISSUES REPORT",
            f"  Source : {src_name}",
            f"  Filter : {r.get('user_filter') or 'none'}",
            f"  Date   : {timestamp}",
            f"  Total packets : {r.get('total_packets', '?'):,}",
            "=" * 70,
            "",
        ]
        n_err  = sum(1 for f in findings if f["severity"] == "error")
        n_warn = sum(1 for f in findings if f["severity"] == "warn")
        lines.append(f"  {n_err} error(s)  |  {n_warn} warning(s)\n")

        for sev_label, sev_key in (("ERRORS", "error"), ("WARNINGS", "warn")):
            subset = [f for f in findings if f["severity"] == sev_key]
            if not subset:
                continue
            lines.append(f"{'─' * 70}")
            lines.append(f"  {sev_label}  ({len(subset)})")
            lines.append(f"{'─' * 70}")
            for f in subset:
                file_part = f"  File #{f['file_num']}" if f.get("file_num") != "" and is_multi else ""
                pkt_part  = f"  Pkt #{f['pkt_num']}"  if f.get("pkt_num")  else ""
                loc       = (file_part + pkt_part).strip()
                proto     = f["protocol"]
                msg       = f["msg"]
                lines.append(f"  [{loc}]  [{proto}]  {msg}" if loc
                              else f"  [{proto}]  {msg}")
            lines.append("")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    def _export_csv(self, path: str, findings: list, is_multi: bool, src_name: str):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            header = (["File #", "Pkt #", "Severity", "Protocol", "Message"]
                      if is_multi else ["Pkt #", "Severity", "Protocol", "Message"])
            writer.writerow(header)
            for f in findings:
                row = []
                if is_multi:
                    row.append(f.get("file_num", ""))
                row += [
                    f.get("pkt_num", ""),
                    f["severity"].upper(),
                    f["protocol"],
                    f["msg"],
                ]
                writer.writerow(row)

    def _export_html(self, path: str, findings: list, is_multi: bool,
                     src_name: str, r: dict):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sev_color = {"error": "#f87171", "warn": "#fb923c"}
        sev_bg    = {"error": "#2d1515", "warn": "#2d1f10"}

        def badge(text, color, bg):
            return (f'<span style="background:{bg};color:{color};border-radius:4px;'
                    f'padding:2px 8px;font-size:11px;font-weight:700;">{text}</span>')

        rows_html = ""
        for f in findings:
            sev   = f["severity"]
            color = sev_color.get(sev, "#fff")
            bg    = sev_bg.get(sev, "#111")
            file_cell = (f'<td style="text-align:center;color:#94e2d5;">'
                         f'{f.get("file_num","—")}</td>' if is_multi else "")
            rows_html += (
                f'<tr style="background:{bg};">'
                f'{file_cell}'
                f'<td style="text-align:center;color:#a78bfa;">{f.get("pkt_num","—")}</td>'
                f'<td style="text-align:center;">{badge(sev.upper(), color, bg)}</td>'
                f'<td style="color:#64748b;">{f["protocol"]}</td>'
                f'<td>{f["msg"]}</td>'
                f'</tr>\n'
            )

        file_col_header = '<th>File #</th>' if is_multi else ""
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<title>PCAP Issues Report</title>
<style>
  body{{background:#0f0f1a;color:#e2e8f0;font-family:'Segoe UI',sans-serif;padding:24px;}}
  h1{{color:#a78bfa;}} h2{{color:#64748b;font-size:13px;font-weight:400;margin-top:-12px;}}
  table{{width:100%;border-collapse:collapse;margin-top:20px;}}
  th{{background:#1a1a2e;color:#64748b;text-align:left;padding:10px 12px;
      font-size:11px;letter-spacing:1px;border-bottom:2px solid #2a2a4a;}}
  td{{padding:9px 12px;border-bottom:1px solid #2a2a4a;font-size:13px;}}
</style>
</head>
<body>
<h1>&#128220; PCAP Issues Report</h1>
<h2>Source: {src_name} &nbsp;·&nbsp; Filter: {r.get('user_filter') or 'none'}
    &nbsp;·&nbsp; {r.get('total_packets',0):,} packets &nbsp;·&nbsp; Generated: {timestamp}</h2>
<table>
<thead><tr>{file_col_header}<th>Pkt #</th><th>Severity</th><th>Protocol</th><th>Details</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)

    # ── summary tab ────────────────────────────────────────────────────────────

    def _populate_summary(self, r: dict):
        findings    = r["findings"]
        flows       = r["flows"]
        protos      = r["protocol_summary"]
        is_multi    = r.get("multi_file", False)
        file_count  = r.get("file_count", 1)
        file_names  = r.get("file_names", [])
        fname       = (f"{file_count} PCAP files" if is_multi
                       else os.path.basename(self._pcap_path))
        uf          = r.get("user_filter", "") or "none (all packets)"

        n_err  = sum(1 for f in findings if f["severity"] == "error")
        n_warn = sum(1 for f in findings if f["severity"] == "warn")

        def section(title, color):
            return (f'<p style="margin:16px 0 6px 0;font-size:15px;font-weight:700;'
                    f'color:{color};">{title}</p>'
                    f'<hr style="border:none;border-top:1px solid {_BORDER};margin:0 0 8px 0;">')

        def row(text, color=_TEXT, bold=False):
            w = "700" if bold else "400"
            return (f'<p style="margin:3px 0;color:{color};font-weight:{w};">'
                    f'&nbsp;&nbsp;{text}</p>')

        html = (f'<body style="background:{_BG};font-family:Segoe UI,sans-serif;">'
                f'<p style="font-size:20px;font-weight:800;color:{_TEXT};margin-bottom:4px;">'
                f'📋 Capture Summary</p>'
                f'<p style="color:{_SUBTEXT};font-size:12px;margin-bottom:16px;">'
                f'{"Archive" if is_multi else "File"}: <b style="color:{_TEXT}">{fname}</b>'
                f'&nbsp;·&nbsp; Filter applied: <b style="color:{_ACCENT}">{uf}</b></p>')

        # Overview block
        html += section("📊 Overview", _ACCENT)
        if is_multi:
            html += row(f'Files analysed: <b style="color:{_TEXT}">{file_count:,}</b>')
        html += row(f'Total packets analyzed: <b style="color:{_TEXT}">{r["total_packets"]:,}</b>')
        html += row(f'Conversations (flows): <b style="color:#94e2d5">{len(flows):,}</b>')
        top_protos = ", ".join(f"{p} ({c:,})" for p, c in list(protos.items())[:5])
        html += row(f'Top protocols: <b style="color:{_TEXT}">{top_protos or "—"}</b>')

        # File list (multi-file only)
        if is_multi and file_names:
            html += section(f"📁 Files  ({file_count})", _SUBTEXT)
            for i, fn in enumerate(file_names[:30], start=1):
                html += row(f'<span style="color:{_ACCENT2};min-width:28px;display:inline-block;">'
                            f'#{i}</span>&nbsp; {fn}')
            if len(file_names) > 30:
                html += row(f'… and {len(file_names) - 30} more', _SUBTEXT)

        # Individual findings are intentionally kept in the Findings tab.
        html += section("🚦 Finding Totals", _ACCENT)
        error_color = _SEV_FG["error"] if n_err else _GREEN
        warning_color = _SEV_FG["warn"] if n_warn else _GREEN
        html += row(f'Errors: <b style="color:{error_color}">{n_err:,}</b>', error_color)
        html += row(f'Warnings: <b style="color:{warning_color}">{n_warn:,}</b>', warning_color)
        html += row('Open the <b style="color:{_ACCENT2}">Findings</b> tab to review every packet and detail.', _SUBTEXT)

        # Top flows
        if flows:
            html += section("📡 Top Conversations", "#94e2d5")
            for fl in flows[:8]:
                html += row(
                    f'{fl["src"]} &nbsp;↔&nbsp; {fl["dst"]}'
                    f'&nbsp;&nbsp;<span style="color:{_ACCENT}">{fl["protocol"]}</span>'
                    f'&nbsp;&nbsp;<b>{fl["packets"]:,} pkts</b>')

        # Protocol breakdown
        if protos:
            html += section("📋 Protocol Breakdown", _SUBTEXT)
            total = r["total_packets"] or 1
            for proto, cnt in list(protos.items())[:12]:
                pct = cnt / total * 100
                html += row(f'{proto:<14} {cnt:>10,} packets  ({pct:.1f}%)')

        html += '</body>'
        self._tab_summary.setHtml(html)

    # ── tables ─────────────────────────────────────────────────────────────────

    def _populate_findings(self, findings: list):
        self._last_findings = list(findings)
        self._render_findings(self._last_findings)

    def _filter_findings(self):
        query = self._findings_packet_filter.text().strip()
        if not query:
            self._render_findings(getattr(self, "_last_findings", []))
            return
        numbers = set()
        for part in query.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                if start.isdigit() and end.isdigit():
                    numbers.update(range(int(start), int(end) + 1))
            elif part.isdigit():
                numbers.add(int(part))
        self._render_findings([
            finding for finding in getattr(self, "_last_findings", [])
            if str(finding.get("pkt_num", "")).isdigit() and int(finding["pkt_num"]) in numbers
        ])

    def _render_findings(self, findings: list):
        self._visible_findings = list(findings)
        t = self._tab_findings
        t.setRowCount(len(findings))
        for row, f in enumerate(findings):
            sev = f["severity"]
            fg  = QColor(_SEV_FG[sev])
            bg  = QColor(_SEV_BG[sev])

            file_num = f.get("file_num", "")
            file_name = f.get("file_name", "") or os.path.basename(self._pcap_path)
            pkt_num  = f.get("pkt_num", "")

            fi  = QTableWidgetItem(str(file_num) if file_num != "" else "—")
            fi.setForeground(QColor(_ACCENT2))
            fi.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            fni = QTableWidgetItem(file_name or "—")
            fni.setForeground(QColor(_TEXT))

            ni  = QTableWidgetItem(str(pkt_num) if pkt_num != "" else "—")
            ni.setForeground(QColor(_ACCENT2))
            ni.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            si  = QTableWidgetItem(_SEV_TAG[sev])
            pi  = QTableWidgetItem(f.get("protocol", "—"))
            mi  = QTableWidgetItem(f["msg"])
            si.setForeground(fg); si.setBackground(bg)
            si.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            pi.setForeground(QColor(_SUBTEXT))
            mi.setForeground(QColor(_TEXT))
            t.setItem(row, 0, fi)
            t.setItem(row, 1, fni)
            t.setItem(row, 2, ni)
            t.setItem(row, 3, si)
            t.setItem(row, 4, pi)
            t.setItem(row, 5, mi)
            t.setRowHeight(row, 30)

    def _populate_flows(self, flows: list):
        t = self._tab_flows
        t.setRowCount(len(flows))

        for row, f in enumerate(flows):
            src = QTableWidgetItem(f["src"])
            dst = QTableWidgetItem(f["dst"])
            direction = f.get("direction", "tx")
            arrow = "↩" if direction == "rx" else "→"
            pi = QTableWidgetItem(f"{f['protocol']} {arrow}")
            pi.setForeground(QColor("#f8fbff"))
            ci = QTableWidgetItem(str(f["packets"]))
            ci.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ci.setForeground(QColor("#f8fbff"))
            src.setForeground(QColor("#f8fbff"))
            dst.setForeground(QColor("#f8fbff"))

            t.setItem(row, 0, src)
            t.setItem(row, 1, dst)
            t.setItem(row, 2, pi)
            t.setItem(row, 3, ci)
            t.setRowHeight(row, 30)

    def _populate_protocols(self, protos: dict):
        t = self._tab_protos
        t.setRowCount(len(protos))
        for row, (proto, cnt) in enumerate(protos.items()):
            pi = QTableWidgetItem(proto)
            pi.setForeground(QColor(_ACCENT))
            ci = QTableWidgetItem(str(cnt))
            ci.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            t.setItem(row, 0, pi)
            t.setItem(row, 1, ci)
            t.setRowHeight(row, 30)
