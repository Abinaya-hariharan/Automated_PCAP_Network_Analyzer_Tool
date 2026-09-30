from __future__ import annotations

import os

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
    QHeaderView, QScrollArea, QToolButton, QTabWidget, QComboBox,
)

from analyzer.capture import tshark_packet_detail
from analyzer.path_check import ISSUE_TYPES, PROTOCOL_TYPES, check_path

_BG = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD = "#16213e"
_BORDER = "#2a2a4a"
_ACCENT = "#7c6af7"
_ACCENT2 = "#a78bfa"
_GREEN = "#22c55e"
_RED = "#f87171"
_ORANGE = "#fb923c"
_TEXT = "#e2e8f0"
_SUBTEXT = "#64748b"

_CHECKBOX_STYLE = (
    f"QCheckBox{{color:{_TEXT};font-size:13px;font-weight:700;padding:6px;}}"
    f"QCheckBox::indicator{{width:19px;height:19px;border:2px solid #94a3b8;"
    f"border-radius:4px;background:#202b46;}}"
    f"QCheckBox::indicator:hover{{border-color:{_ACCENT2};background:#2d3a5c;}}"
    f"QCheckBox::indicator:checked{{border:2px solid #86efac;"
    f"background:#16a34a;}}"
)


class ProtocolSelectionPanel(QWidget):
    def __init__(self):
        super().__init__()
        self._checks: dict[str, QToolButton] = {}
        self._build_ui()

    def _build_ui(self):
        root = QGridLayout(self)
        self._root_layout = root
        root.setContentsMargins(10, 8, 10, 8)
        root.setContentsMargins(10, 8, 10, 8)
        root.setHorizontalSpacing(12)
        root.setVerticalSpacing(4)
        column_widths = (170, 180, 170, 190, 150, 230, 180)
        for column, width in enumerate(column_widths):
            root.setColumnMinimumWidth(column, width)
        title = QLabel("Protocol selection - click a protocol to select it")
        title.setStyleSheet(f"color:{_ACCENT};font-size:13px;font-weight:800;")
        root.addWidget(title, 0, 0, 1, 7)
        protocol_options = (*PROTOCOL_TYPES, ("ping", "Ping"), ("missing_response", "Missing response"))
        for column, (key, label) in enumerate(protocol_options):
            toggle = QToolButton()
            toggle.setText(f"  {label}")
            toggle.setCheckable(True)
            toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            toggle.setStyleSheet(
                f"QToolButton{{color:{_TEXT};font-size:13px;font-weight:700;"
                f"text-align:left;border:1px solid transparent;border-radius:4px;padding:6px 8px;}}"
                f"QToolButton:hover{{background:{_CARD};}}"
                f"QToolButton:checked{{color:white;background:{_ACCENT};border-color:{_ACCENT2};}}"
            )
            self._checks[key] = toggle
            root.addWidget(toggle, 1, column)
        root.setColumnStretch(0, 1)
        root.setColumnStretch(1, 1)
        root.setColumnStretch(2, 1)
        root.setColumnStretch(3, 1)
        root.setColumnStretch(4, 1)
        root.setColumnStretch(5, 1)
        root.setColumnStretch(6, 1)
        self.setMinimumHeight(66)

    def add_path_check_button(self, button: QPushButton):
        button.setMinimumWidth(180)
        self._root_layout.addWidget(button, 1, 6)

    def selected_protocols(self) -> set[str]:
        return {key for key, check in self._checks.items() if key in dict(PROTOCOL_TYPES) and check.isChecked()}

    def ping_enabled(self) -> bool:
        return self._checks["ping"].isChecked()

    def missing_response_enabled(self) -> bool:
        return self._checks["missing_response"].isChecked()


class _PathWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, path: str, source: str, destination: str,
                 source_mac: str, destination_mac: str, selected: set[str],
                 protocols: set[str], check_ping: bool, check_response: bool,
                 address_family: str):
        super().__init__()
        self.path = path
        self.source = source
        self.destination = destination
        self.source_mac = source_mac
        self.destination_mac = destination_mac
        self.selected = selected
        self.protocols = protocols
        self.check_ping = check_ping
        self.check_response = check_response
        self.address_family = address_family

    def run(self):
        try:
            result = check_path(
                self.path, self.source, self.destination,
                self.source_mac, self.destination_mac,
                self.selected, self.progress.emit, self.protocols,
                self.check_ping, self.check_response, self.address_family,
            )
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))


class _PacketDetailWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, pcap_path: str, packet_number: str):
        super().__init__()
        self._pcap_path = pcap_path
        self._packet_number = packet_number

    def run(self):
        try:
            self.finished.emit(tshark_packet_detail(self._pcap_path, self._packet_number))
        except Exception as exc:
            self.finished.emit(f"Unable to load packet {self._packet_number}: {exc}")


class PathCheckPanel(QWidget):
    def __init__(self, protocol_panel: ProtocolSelectionPanel | None = None):
        super().__init__()
        self._pcap_path = ""
        self._report = {}
        self._worker = None
        self._packet_detail_worker = None
        self._events: list[dict] = []
        self._filter_cache: dict[tuple, list[dict]] = {}
        self._protocol_panel = protocol_panel or ProtocolSelectionPanel()
        self._build_ui()

    def set_pcap(self, path: str):
        self._pcap_path = path or ""
        self._events = []
        self._filter_cache.clear()
        if hasattr(self, "_file_filter"):
            self._file_filter.blockSignals(True)
            self._file_filter.clear()
            self._file_filter.addItem("All files")
            self._file_filter.blockSignals(False)
        self._details.setRowCount(0)
        self._packet_detail.clear()
        self._status.setText(
            "PCAP ready. Select a protocol above, then click Run path check."
            if path else "Analyze a PCAP first"
        )
        self._run.setEnabled(bool(path))

    def set_report(self, report: dict):
        self._report = report or {}

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)

        title = QLabel("🕵  Network Issue Finder")
        title.setStyleSheet(f"color:{_TEXT};font-size:17px;font-weight:800;padding-bottom:6px;")
        root.addWidget(title)
        intro = QLabel("1. Enter optional IP/MAC filters  ·  2. Select protocols below  ·  3. Click RUN CHECK to see packet evidence below")
        intro.setStyleSheet(f"color:{_TEXT};font-size:12px;font-weight:600;padding:5px 8px;background:{_CARD};border-left:3px solid {_ACCENT};")
        root.addWidget(intro)

        inputs = QGroupBox("Traffic path")
        inputs.setStyleSheet(f"QGroupBox{{color:{_TEXT};border:1px solid {_BORDER};border-radius:8px;margin-top:8px;padding:12px;}} QGroupBox::title{{subcontrol-origin:margin;left:10px;padding:0 5px;color:{_ACCENT};}}")
        form = QGridLayout(inputs)
        self._source = QLineEdit()
        self._source.setPlaceholderText("Source IP, e.g. 192.168.0.189")
        self._destination = QLineEdit()
        self._destination.setPlaceholderText("Destination IP, e.g. 192.168.0.71")
        self._source_mac = QLineEdit()
        self._source_mac.setPlaceholderText("aa:bb:cc:dd:ee:ff")
        self._destination_mac = QLineEdit()
        self._destination_mac.setPlaceholderText("aa:bb:cc:dd:ee:ff")
        form.addWidget(QLabel("Source IP"), 0, 0)
        form.addWidget(self._source, 0, 1)
        form.addWidget(QLabel("Destination IP"), 0, 2)
        form.addWidget(self._destination, 0, 3)
        form.addWidget(QLabel("Source MAC"), 1, 0)
        form.addWidget(self._source_mac, 1, 1)
        form.addWidget(QLabel("Destination MAC"), 1, 2)
        form.addWidget(self._destination_mac, 1, 3)
        root.addWidget(inputs)
        root.addWidget(self._protocol_panel)

        self._family_tabs = QTabWidget()
        self._family_tabs.setDocumentMode(True)
        self._family_tabs.addTab(QWidget(), "All IP")
        self._family_tabs.addTab(QWidget(), "IPv4")
        self._family_tabs.addTab(QWidget(), "IPv6")
        self._family_tabs.setFixedHeight(34)
        self._family_tabs.currentChanged.connect(self._family_changed)
        root.addWidget(self._family_tabs)

        self._run = QPushButton("▶  Path Check")
        self._run.setToolTip("Analyze the selected issue types in the loaded PCAP")
        self._run.setFixedHeight(32)
        self._run.setMinimumWidth(180)
        self._run.setStyleSheet(
            f"QPushButton{{background:{_ACCENT};color:white;border:none;border-radius:7px;"
            f"padding:0 18px;font-size:13px;font-weight:800;}}"
            f"QPushButton:hover{{background:#9580ff;}}"
            f"QPushButton:disabled{{background:#3b326f;color:#b8aaff;}}"
        )
        self._run.clicked.connect(self._run_check)
        self._run.setEnabled(False)
        self._protocol_panel.add_path_check_button(self._run)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("File"))
        self._file_filter = QComboBox()
        self._file_filter.addItem("All files")
        self._file_filter.setFixedHeight(30)
        self._file_filter.setMinimumWidth(220)
        self._file_filter.setEnabled(True)
        self._file_filter.setToolTip("Choose a capture file before filtering packet numbers")
        self._file_filter.currentTextChanged.connect(self._filter_events)
        filter_row.addWidget(self._file_filter)
        filter_row.addWidget(QLabel("Optional packet number"))
        self._packet_filter = QLineEdit()
        self._packet_filter.setPlaceholderText("e.g. 298436 or 298436-298440")
        self._packet_filter.setFixedHeight(30)
        self._packet_filter.textChanged.connect(self._filter_events)
        filter_row.addWidget(self._packet_filter, 1)
        root.addLayout(filter_row)

        self._status = QLabel("Analyze a PCAP first")
        self._status.setStyleSheet(f"color:{_ACCENT2};font-size:12px;font-weight:700;padding:4px 0;")
        self._status.setVisible(True)
        self._status.setMinimumHeight(24)
        root.addWidget(self._status)
        self._details = QTableWidget(0, 8)
        self._details.setHorizontalHeaderLabels([
            "File", "Packet #", "Time (s)", "Source", "Destination", "Protocol", "Length", "Details",
        ])
        self._details.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._details.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._details.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._details.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._details.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._details.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self._details.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self._details.setWordWrap(True)
        self._details.verticalHeader().setDefaultSectionSize(32)
        self._details.setMinimumHeight(420)
        self._details.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._details.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._details.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._details.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._details.itemSelectionChanged.connect(self._show_selected_packet)
        self._packet_detail = QTextEdit()
        self._packet_detail.setReadOnly(True)
        self._packet_detail.setPlaceholderText("Select a packet row to view its full Wireshark details")
        self._packet_detail.setStyleSheet(
            f"QTextEdit{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:6px;padding:8px;color:{_TEXT};font-family:Consolas,monospace;font-size:11px;}}"
        )
        evidence_splitter = QSplitter(Qt.Orientation.Vertical)
        evidence_splitter.setChildrenCollapsible(False)
        evidence_splitter.setHandleWidth(7)
        evidence_splitter.setStyleSheet(f"QSplitter::handle{{background:{_BORDER};}}")
        evidence_splitter.addWidget(self._details)
        evidence_splitter.addWidget(self._packet_detail)
        evidence_splitter.setMinimumHeight(640)
        evidence_splitter.setStretchFactor(0, 3)
        evidence_splitter.setStretchFactor(1, 2)
        evidence_splitter.setSizes([420, 280])
        root.addWidget(evidence_splitter, 1)
        scroll.setWidget(content)
        outer.addWidget(scroll)
        self._update_selected_label()

    def _filter_events(self, _index: int | None = None):
        family = ("all", "ipv4", "ipv6")[self._family_tabs.currentIndex()]
        selected_file = self._file_filter.currentText() if hasattr(self, "_file_filter") else "All files"
        query = self._packet_filter.text().strip()
        cache_key = (family, selected_file, query)
        if cache_key in self._filter_cache:
            self._populate_events(self._filter_cache[cache_key])
            return
        events = self._events
        if selected_file and selected_file != "All files":
            events = [event for event in events if event.get("file_name") == selected_file]
        if family == "ipv4":
            events = [event for event in events if ":" not in str(event.get("source", "")) and ":" not in str(event.get("destination", ""))]
        elif family == "ipv6":
            events = [event for event in events if ":" in str(event.get("source", "")) or ":" in str(event.get("destination", ""))]
        if query:
            numbers = set()
            for part in query.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-", 1)
                    if start.isdigit() and end.isdigit():
                        numbers.update(range(int(start), int(end) + 1))
                elif part.isdigit():
                    numbers.add(int(part))
            events = [event for event in events if str(event.get("packet", "")).isdigit() and int(event["packet"]) in numbers]
        self._filter_cache[cache_key] = events
        self._populate_events(events)

    def _family_changed(self, _index: int):
        self._filter_events()

    def _has_selection(self) -> bool:
        protocols = self._protocol_panel.selected_protocols() if self._protocol_panel else set()
        return bool(protocols or self._protocol_panel.ping_enabled() or self._protocol_panel.missing_response_enabled())

    def _set_checks(self, checked: bool):
        return

    def _update_selected_label(self):
        return

    def _run_check(self):
        if not self._pcap_path:
            self._status.setText("Select and analyze a PCAP first")
            return
        selected: set[str] = set()
        protocols = self._protocol_panel.selected_protocols() if self._protocol_panel else set()
        check_ping = self._protocol_panel.ping_enabled() if self._protocol_panel else False
        check_response = self._protocol_panel.missing_response_enabled() if self._protocol_panel else False
        if not selected and not (protocols or check_ping or check_response):
            self._status.setText("Select a protocol, Ping, or Missing response above")
            return
        self._run.setEnabled(False)
        self._run.setText("⏳  Checking…")
        self._status.setText("Scanning selected capture file(s) with tshark; the window remains available…")
        self._details.setRowCount(0)
        self._packet_detail.clear()
        self._status.setText("Checking selected path…")
        self._worker = _PathWorker(
            self._pcap_path,
            self._source.text().strip(),
            self._destination.text().strip(),
            self._source_mac.text().strip(),
            self._destination_mac.text().strip(),
            selected,
            protocols,
            check_ping,
            check_response,
            ("all", "ipv4", "ipv6")[self._family_tabs.currentIndex()],
        )
        self._worker.progress.connect(self._status.setText)
        self._worker.finished.connect(self._show_result)
        self._worker.error.connect(self._show_error)
        self._worker.start()

    def _show_result(self, result: dict):
        self._run.setEnabled(True)
        self._run.setText("▶  Path Check")
        self._events = sorted(
            result["events"],
            key=lambda event: (
                event.get("file_number", 1),
                event.get("time") is None,
                event.get("time") or 0,
            ),
        )
        self._filter_cache.clear()
        self._file_filter.blockSignals(True)
        self._file_filter.clear()
        self._file_filter.addItem("All files")
        result_files = {
            event.get("file_name", "") for event in self._events
            if event.get("file_name")
        }
        if os.path.isfile(self._pcap_path):
            result_files.add(os.path.basename(self._pcap_path))
        elif os.path.isdir(self._pcap_path):
            result_files.update(
                name for root, _, names in os.walk(self._pcap_path)
                for name in names
                if os.path.splitext(name)[1].lower() in (".pcap", ".pcapng")
            )
        self._file_filter.addItems(sorted(result_files))
        self._file_filter.blockSignals(False)
        self._filter_events()
        direction = f"{result['source_ip'] or 'any source'} → {result['destination_ip'] or 'any destination'}"
        file_note = (
            f" across {result['file_count']} files"
            if result.get("file_count", 1) > 1 else ""
        )
        self._status.setText(
            f"Completed: checked {result['packet_count']:,} packets{file_note} on {direction}  ·  "
            f"{len(result['events']):,} packet events, grouped by file"
        )
        if not result["events"]:
            self._status.setText(
                f"No matching packet events found after checking {result['packet_count']:,} packets."
            )

    def _populate_events(self, events: list[dict]):
        self._details.setUpdatesEnabled(False)
        self._details.setRowCount(len(events))
        for row, event in enumerate(events):
            timestamp = event.get("time")
            values = [
                event.get("file_name", "") or "—",
                event.get("packet", "") or "—",
                f"{timestamp:.6f}" if isinstance(timestamp, float) else "—",
                event.get("source", "—"),
                event.get("destination", "—"),
                event.get("protocol", "—"),
                event.get("length", "—"),
                event.get("detail", ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 1:
                    item.setData(Qt.ItemDataRole.UserRole, event.get("file_path", self._pcap_path))
                self._details.setItem(row, column, item)
        self._packet_detail.clear()
        self._details.setUpdatesEnabled(True)

    def _show_selected_packet(self):
        selected = self._details.selectedItems()
        if not selected or not self._pcap_path:
            return
        row = selected[0].row()
        packet_number = self._details.item(row, 1).text()
        if not packet_number.isdigit():
            return
        file_path = self._details.item(row, 1).data(Qt.ItemDataRole.UserRole) or self._pcap_path
        file_name = os.path.basename(file_path)
        self._packet_detail.setPlainText(
            f"Loading full Wireshark details for packet {packet_number} in {file_name}…"
        )
        self._packet_detail_worker = _PacketDetailWorker(file_path, packet_number)
        self._packet_detail_worker.finished.connect(self._packet_detail.setPlainText)
        self._packet_detail_worker.start()

    def _show_error(self, message: str):
        self._run.setEnabled(True)
        self._run.setText("▶  Path Check")
        self._status.setText(f"Path check failed: {message}")
