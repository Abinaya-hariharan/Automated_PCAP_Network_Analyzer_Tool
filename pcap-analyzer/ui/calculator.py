"""Packet Time Calculator — time deltas between individual packets or ranges."""
from __future__ import annotations
import os, re, subprocess, shutil
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QLineEdit, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QComboBox, QFileDialog,
    QScrollArea,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

_BG      = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD    = "#16213e"
_BORDER  = "#2a2a4a"
_ACCENT  = "#7c6af7"
_ACCENT2 = "#a78bfa"
_GREEN   = "#22c55e"
_ORANGE  = "#fb923c"
_TEXT    = "#e2e8f0"
_SUBTEXT = "#64748b"

_BTN = (
    f"QPushButton{{background:{_ACCENT};color:white;border:none;"
    f"border-radius:8px;font-weight:700;font-size:13px;padding:8px 20px;}}"
    f"QPushButton:hover{{background:#9580ff;}}"
)
_BTN_SEC = (
    f"QPushButton{{background:{_CARD};color:{_TEXT};"
    f"border:1px solid {_BORDER};border-radius:8px;"
    f"font-weight:600;font-size:12px;padding:8px 16px;}}"
    f"QPushButton:hover{{border-color:{_ACCENT};color:{_ACCENT2};}}"
)
_INP = (
    f"QLineEdit{{background:{_CARD};color:{_TEXT};"
    f"border:1px solid {_BORDER};border-radius:7px;padding:8px 12px;font-size:13px;}}"
    f"QLineEdit:focus{{border:1px solid {_ACCENT};}}"
)


def _tshark_path() -> str | None:
    # check PATH first, then known Wireshark install locations
    found = shutil.which("tshark")
    if found:
        return found
    for candidate in [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]:
        if __import__("os").path.isfile(candidate):
            return candidate
    return None


def _fetch_packets(pcap: str, frame_filter: str) -> list[dict]:
    """Return list of {num, time_abs, time_rel, length} via tshark."""
    tshark = _tshark_path()
    if not tshark:
        return []
    packet_limits = [int(value) for value in re.findall(r"frame\.number\s*(?:==|<=|>=)\s*(\d+)", frame_filter)]
    cmd = [
        tshark, "-r", pcap,
        *( ["-c", str(max(packet_limits))] if packet_limits else [] ),
        "-Y", frame_filter,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "frame.time_delta",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-E", "separator=|",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=180)
        rows = []
        for line in out.decode(errors="replace").splitlines():
            parts = line.rstrip("\r\n").split("|")
            if len(parts) < 10 or not parts[0].strip():
                continue
            try:
                rows.append({
                    "num":       parts[0].strip(),
                    "time_rel":  float(parts[1].strip()) if parts[1].strip() else 0.0,
                    "time_delta": float(parts[2].strip()) if parts[2].strip() else 0.0,
                    "length":    int(parts[3].strip()) if parts[3].strip().isdigit() else 0,
                    "src":       parts[4].strip() or parts[6].strip() or parts[8].strip() or "—",
                    "dst":       parts[5].strip() or parts[7].strip() or parts[9].strip() or "—",
                })
            except (ValueError, IndexError):
                continue
        return rows
    except subprocess.TimeoutExpired:
        raise RuntimeError("Packet lookup timed out while reading this large capture")
    except Exception:
        return []


class _Worker(QThread):
    done = pyqtSignal(list, str)   # packets, error_msg

    def __init__(self, pcap: str, frame_filter: str):
        super().__init__()
        self._pcap   = pcap
        self._filter = frame_filter

    def run(self):
        if not _tshark_path():
            self.done.emit([], "tshark not found — install Wireshark to enable packet lookup")
            return
        try:
            pkts = _fetch_packets(self._pcap, self._filter)
            self.done.emit(pkts, "")
        except RuntimeError as exc:
            self.done.emit([], str(exc))


class PacketCalculator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._pcap_path: str = ""
        self._files_map: dict[str, str] = {}  # filename -> full path mapping
        self._current_file: str = ""
        self._worker: _Worker | None = None
        self._build_ui()

    def set_pcap(self, path: str):
        """Support both single files and folders with multiple .pcap files."""
        self._files_map.clear()
        self._file_combo.clear()
        self._current_file = ""
        
        if not path:
            self._pcap_path = ""
            self._update_status_disabled()
            return

        # Check if it's a single .pcap file
        is_file = os.path.isfile(path)
        ext = os.path.splitext(path)[1].lower()
        
        if is_file and ext in (".pcap", ".pcapng"):
            # Single file mode
            self._files_map[os.path.basename(path)] = path
            self._file_combo.addItem(os.path.basename(path))
            self._current_file = path
            self._pcap_path = path
            self._update_status_enabled(os.path.basename(path))
            return
        
        # Check if it's a folder with .pcap files
        if os.path.isdir(path):
            pcap_files = [
                f for f in os.listdir(path)
                if os.path.isfile(os.path.join(path, f)) 
                and os.path.splitext(f)[1].lower() in (".pcap", ".pcapng")
            ]
            
            if pcap_files:
                for fname in sorted(pcap_files):
                    fpath = os.path.join(path, fname)
                    self._files_map[fname] = fpath
                    self._file_combo.addItem(fname)
                
                if self._files_map:
                    self._current_file = list(self._files_map.values())[0]
                    self._pcap_path = self._current_file
                    self._file_combo.setCurrentIndex(0)
                    self._update_status_enabled(f"📁 Folder: {len(pcap_files)} files")
                return
        
        # No valid files found
        self._pcap_path = ""
        self._update_status_disabled()

    def _add_files(self, paths: list[str]):
        added = 0
        for path in paths:
            if not os.path.isfile(path) or os.path.splitext(path)[1].lower() not in (".pcap", ".pcapng"):
                continue
            name = os.path.basename(path)
            if name in self._files_map:
                name = f"{os.path.splitext(name)[0]} ({len(self._files_map) + 1}){os.path.splitext(name)[1]}"
            self._files_map[name] = path
            self._file_combo.addItem(name)
            added += 1
        if added:
            if not self._pcap_path:
                self._file_combo.setCurrentIndex(0)
                self._pcap_path = next(iter(self._files_map.values()))
                self._current_file = self._pcap_path
            self._update_status_enabled(f"{len(self._files_map)} file(s) loaded")

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        content.setMinimumHeight(760)
        root = QVBoxLayout(content)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        # ── title ─────────────────────────────────────────────────────────────
        ttl = QLabel("🧮  Packet Time Calculator")
        ttl.setStyleSheet(f"color:{_TEXT};font-size:16px;font-weight:800;")

        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"background:{_BORDER};border:none;max-height:1px;")

        # ── mode tabs ─────────────────────────────────────────────────────────
        mode_row = QHBoxLayout()
        mode_row.setSpacing(8)
        mode_lbl = QLabel("Mode:")
        mode_lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:12px;font-weight:600;")
        self._btn_m_two = QPushButton("⏱  Two Packets")
        self._btn_m_rng = QPushButton("📦  Range")
        for b in (self._btn_m_two, self._btn_m_rng):
            b.setCheckable(True)
            b.setFixedHeight(32)
            b.setStyleSheet(
                f"QPushButton{{background:{_CARD};color:{_SUBTEXT};"
                f"border:1px solid {_BORDER};border-radius:7px;"
                f"font-size:12px;font-weight:600;padding:0 16px;}}"
                f"QPushButton:checked{{background:{_ACCENT}30;color:{_ACCENT2};"
                f"border-color:{_ACCENT};}}"
            )
        self._btn_m_two.setChecked(True)
        self._btn_m_two.clicked.connect(lambda: self._switch_mode("two"))
        self._btn_m_rng.clicked.connect(lambda: self._switch_mode("range"))
        mode_row.addWidget(mode_lbl)
        mode_row.addWidget(self._btn_m_two)
        mode_row.addWidget(self._btn_m_rng)
        mode_row.addStretch(1)
        # Both calculation methods are shown together below.

        # ── file selection card ───────────────────────────────────────────────
        file_card = QFrame()
        file_card.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border:1px solid {_BORDER};border-radius:10px;}}"
        )
        fc = QHBoxLayout(file_card)
        fc.setContentsMargins(16, 12, 16, 12)
        fc.setSpacing(10)
        
        file_lbl = QLabel("📄  File:")
        file_lbl.setStyleSheet(f"color:{_TEXT};font-size:12px;font-weight:700;")
        
        self._file_combo = QComboBox()
        self._file_combo.setFixedHeight(38)
        self._file_combo.setStyleSheet(
            f"QComboBox{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:6px;"
            f"padding:6px 10px;font-size:12px;}}")
        self._file_combo.currentTextChanged.connect(self._on_file_selected)
        
        btn_browse = QPushButton("  📂  Browse…")
        btn_browse.setFixedHeight(38)
        btn_browse.setStyleSheet(_BTN_SEC)
        btn_browse.clicked.connect(self._open_file)

        btn_add = QPushButton("  + Add Files")
        btn_add.setFixedHeight(38)
        btn_add.setStyleSheet(_BTN_SEC)
        btn_add.clicked.connect(self._add_files_dialog)
        
        fc.addWidget(file_lbl)
        fc.addWidget(self._file_combo, 1)
        fc.addWidget(btn_browse)
        fc.addWidget(btn_add)
        title_row = QHBoxLayout()
        title_row.setSpacing(12)
        title_row.addWidget(ttl)
        title_row.addStretch(1)
        title_row.addWidget(file_card)
        root.addLayout(title_row)
        root.addWidget(div)

        # ── input card ────────────────────────────────────────────────────────
        input_card = QFrame()
        input_card.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border:1px solid {_BORDER};border-radius:10px;}}"
        )
        iv = QHBoxLayout(input_card)
        iv.setContentsMargins(16, 14, 16, 14)
        iv.setSpacing(12)

        # two-packet panel
        self._panel_two = QWidget()
        self._panel_two.setStyleSheet("background:transparent;")
        pt = QVBoxLayout(self._panel_two)
        pt.setContentsMargins(0, 0, 0, 0)
        pt.setSpacing(12)
        two_title = QLabel("Between two consecutive packets")
        two_title.setStyleSheet(f"color:{_ACCENT2};font-size:12px;font-weight:800;")
        pt.addWidget(two_title)
        two_fields = QHBoxLayout()
        two_fields.setSpacing(12)
        for lbl_text, attr, ph in [
            ("Packet A  (#)", "_inp_a", "e.g. 847"),
            ("Packet B  (#)", "_inp_b", "e.g. 848"),
        ]:
            col = QVBoxLayout()
            col.setSpacing(4)
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:11px;font-weight:600;")
            inp = QLineEdit()
            inp.setPlaceholderText(ph)
            inp.setStyleSheet(_INP)
            inp.setFixedHeight(38)
            setattr(self, attr, inp)
            inp.returnPressed.connect(self._calc_two_packet)
            col.addWidget(lbl); col.addWidget(inp)
            two_fields.addLayout(col, 1)
        btn_two = QPushButton("  ▶  Calculate")
        btn_two.setFixedHeight(38)
        btn_two.setStyleSheet(_BTN)
        btn_two.clicked.connect(self._calc_two_packet)
        two_fields.addWidget(btn_two)
        pt.addLayout(two_fields)
        iv.addWidget(self._panel_two, 1)

        # range panel
        self._panel_rng = QWidget()
        self._panel_rng.setStyleSheet("background:transparent;")
        self._panel_rng.setVisible(True)
        pr = QVBoxLayout(self._panel_rng)
        pr.setContentsMargins(0, 0, 0, 0)
        pr.setSpacing(12)
        range_title = QLabel("Analyze a range of packets")
        range_title.setStyleSheet(f"color:{_ACCENT2};font-size:12px;font-weight:800;")
        pr.addWidget(range_title)
        range_fields = QHBoxLayout()
        range_fields.setSpacing(12)
        for lbl_text, attr, ph in [
            ("From packet  (#)", "_inp_from", "e.g. 100"),
            ("To packet    (#)", "_inp_to",   "e.g. 500"),
        ]:
            col = QVBoxLayout()
            col.setSpacing(4)
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:11px;font-weight:600;")
            inp = QLineEdit()
            inp.setPlaceholderText(ph)
            inp.setStyleSheet(_INP)
            inp.setFixedHeight(38)
            setattr(self, attr, inp)
            inp.returnPressed.connect(self._calc_range)
            col.addWidget(lbl); col.addWidget(inp)
            range_fields.addLayout(col, 1)
        btn_rng = QPushButton("  ▶  Analyze Range")
        btn_rng.setFixedHeight(38)
        btn_rng.setStyleSheet(
            f"QPushButton{{background:#15803d;color:white;border:none;"
            f"border-radius:8px;font-weight:700;font-size:13px;padding:0 20px;}}"
            f"QPushButton:hover{{background:{_GREEN};}}"
        )
        btn_rng.clicked.connect(self._calc_range)
        range_fields.addWidget(btn_rng)
        pr.addLayout(range_fields)
        iv.addWidget(self._panel_rng, 1)
        root.addWidget(input_card)

        # ── result banner (hidden until done) ─────────────────────────────────
        self._banner = QFrame()
        self._banner.setVisible(False)
        self._banner.setStyleSheet(
            f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 #1a1035,stop:1 #0f2027);"
            f"border:1px solid {_BORDER};border-radius:10px;}}"
        )
        bh = QHBoxLayout(self._banner)
        bh.setContentsMargins(20, 12, 20, 12)
        bh.setSpacing(0)

        def _stat(label, color):
            w = QWidget(); w.setStyleSheet("background:transparent;")
            wv = QVBoxLayout(w); wv.setContentsMargins(14, 0, 14, 0); wv.setSpacing(2)
            val = QLabel("—")
            val.setStyleSheet(
                f"color:{color};font-size:20px;font-weight:800;"
                f"background:transparent;border:none;"
            )
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"color:{_SUBTEXT};font-size:9px;font-weight:700;"
                f"letter-spacing:1px;background:transparent;border:none;"
            )
            wv.addWidget(val); wv.addWidget(lbl)
            return w, val

        self._rv_delta, self._rvv_delta = _stat("TIME DELTA",  _ACCENT2)
        self._rv_count, self._rvv_count = _stat("PACKETS",     "#34d399")
        self._rv_bytes, self._rvv_bytes = _stat("BYTES TOTAL", "#60a5fa")
        self._rv_pps,   self._rvv_pps   = _stat("PKTS / SEC",  _ORANGE)
        self._rv_bps,   self._rvv_bps   = _stat("BYTES / SEC", "#c084fc")

        for i, w in enumerate([self._rv_delta, self._rv_count,
                                self._rv_bytes, self._rv_pps, self._rv_bps]):
            if i:
                sep = QFrame(); sep.setFrameShape(QFrame.Shape.VLine)
                sep.setStyleSheet(f"background:{_BORDER};border:none;max-width:1px;")
                bh.addWidget(sep)
            bh.addWidget(w, 1)
        root.addWidget(self._banner)

        # ── packet table ──────────────────────────────────────────────────────
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Pkt #", "Time (s)", "Δ from prev (ms)", "Length (B)", "Source", "Destination"]
        )
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for col, w in enumerate([65, 110, 130, 80, 130]):
            self._table.horizontalHeader().resizeSection(col, w)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setStyleSheet(
            f"QTableWidget{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;color:{_TEXT};}}"
            f"QTableWidget::item{{padding:6px 10px;}}"
            f"QHeaderView::section{{background:{_BG};color:{_SUBTEXT};"
            f"padding:8px 10px;border:none;border-bottom:2px solid {_BORDER};"
            f"font-weight:700;font-size:11px;letter-spacing:1px;}}"
        )
        root.addWidget(self._table, 1)

        # ── status ────────────────────────────────────────────────────────────
        self._status = QLabel("  💡  Analyze a .pcap file first, then enter packet numbers above")
        self._status.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_BORDER};padding:5px 10px;"
        )
        root.addWidget(self._status)
        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _switch_mode(self, mode: str):
        self._btn_m_two.setChecked(mode == "two")
        self._btn_m_rng.setChecked(mode == "range")
        self._panel_two.setVisible(mode == "two")
        self._panel_rng.setVisible(mode == "range")

    # ── file selection ────────────────────────────────────────────────────────

    def _open_file(self):
        """Choose a folder or one capture and replace the current list."""
        path = QFileDialog.getExistingDirectory(self, "Open Folder with PCAP Files", "")
        if path:
            self.set_pcap(path)
            return
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "Open PCAP File(s)", "",
            "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if file_paths:
            self._files_map.clear()
            self._file_combo.clear()
            self._pcap_path = ""
            self._add_files(file_paths)

    def _add_files_dialog(self):
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "Add PCAP File(s)", "",
            "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if file_paths:
            self._add_files(file_paths)

    def _on_file_selected(self, filename: str):
        """Handle file combo box selection change."""
        if filename in self._files_map:
            self._current_file = self._files_map[filename]
            self._pcap_path = self._current_file

    def _update_status_enabled(self, info: str):
        """Enable calculations and show status."""
        self._status.setStyleSheet(
            f"color:{_GREEN};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_GREEN}60;padding:5px 10px;"
        )
        self._status.setText(f"  ✅  {info}")
        self._file_combo.setEnabled(True)

    def _update_status_disabled(self):
        """Disable calculations and show warning."""
        self._status.setStyleSheet(
            f"color:{_ORANGE};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {_ORANGE}60;padding:5px 10px;"
        )
        self._status.setText("  ⚠  Analyze a .pcap file first, then enter packet numbers above")
        self._file_combo.setEnabled(False)

    # ── calculations ──────────────────────────────────────────────────────────

    def _calc_two_packet(self):
        if not self._pcap_path:
            self._set_status("⚠  No file loaded — analyze a PCAP file first", _ORANGE)
            return
        a, b = self._inp_a.text().strip(), self._inp_b.text().strip()
        if not a.isdigit() or not b.isdigit():
            self._set_status("⚠  Enter valid packet numbers in both fields", _ORANGE)
            return
        lo, hi = sorted([int(a), int(b)])
        if hi - lo != 1:
            self._set_status("⚠  Enter consecutive packet numbers (e.g. 847 and 848)", _ORANGE)
            return
        self._run_query(f"frame.number == {lo} || frame.number == {hi}", "two")

    def _calc_range(self):
        if not self._pcap_path:
            self._set_status("⚠  No file loaded — analyze a PCAP file first", _ORANGE)
            return
        frm, to = self._inp_from.text().strip(), self._inp_to.text().strip()
        if not frm.isdigit() or not to.isdigit():
            self._set_status("⚠  Enter valid packet numbers in both fields", _ORANGE)
            return
        lo, hi = sorted([int(frm), int(to)])
        self._run_query(f"frame.number >= {lo} && frame.number <= {hi}", "range")

    def _run_query(self, filt: str, mode: str):
        self._set_status("  ⏳  Fetching packets…", _ACCENT2)
        self._table.setRowCount(0)
        self._banner.setVisible(False)
        self._worker = _Worker(self._pcap_path, filt)
        self._worker.done.connect(lambda pkts, err: self._on_done(pkts, err, mode))
        self._worker.start()

    def _on_done(self, pkts: list, err: str, mode: str):
        if err:
            self._set_status(f"⚠  {err}", _ORANGE)
            return
        if not pkts:
            self._set_status("⚠  No packets found — check the packet numbers and try again", _ORANGE)
            return

        pkts.sort(key=lambda p: p["time_rel"])

        # populate table
        self._table.setRowCount(len(pkts))
        for row, p in enumerate(pkts):
            delta_ms = "—" if row == 0 else f"{p['time_delta'] * 1000:.3f}"
            for col, (val, color) in enumerate(zip(
                [p["num"], f"{p['time_rel']:.6f}", delta_ms,
                 str(p["length"]), p["src"], p["dst"]],
                [_ACCENT2, _TEXT, "#fbbf24", "#34d399", _SUBTEXT, _SUBTEXT]
            )):
                item = QTableWidgetItem(val)
                item.setForeground(QColor(color))
                if col in (0, 2, 3):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._table.setItem(row, col, item)
            self._table.setRowHeight(row, 28)

        # stats
        t_first = pkts[0]["time_rel"]
        t_last  = pkts[-1]["time_rel"]
        delta   = t_last - t_first
        total_b = sum(p["length"] for p in pkts)
        count   = len(pkts)
        pps     = count / delta if delta > 0 else 0
        bps     = total_b / delta if delta > 0 else 0

        self._rvv_delta.setText(f"{delta*1000:.3f} ms" if delta < 1 else f"{delta:.6f} s")
        self._rvv_count.setText(f"{count:,}")
        self._rvv_bytes.setText(f"{total_b/1024:.1f} KB" if total_b > 1024 else f"{total_b} B")
        self._rvv_pps.setText(f"{pps:.1f}")
        self._rvv_bps.setText(f"{bps/1024:.1f} KB/s" if bps > 1024 else f"{bps:.0f} B/s")
        self._banner.setVisible(True)

        self._set_status(
            f"  ✅  {count} packets  ·  "
            f"{t_first:.3f}s → {t_last:.3f}s  ·  "
            f"Delta: {delta*1000:.3f} ms",
            _GREEN,
        )

    def _set_status(self, msg: str, color: str = _SUBTEXT):
        self._status.setStyleSheet(
            f"color:{color};font-size:11px;"
            f"background:{_SURFACE};border-radius:6px;"
            f"border-left:3px solid {color}60;padding:5px 10px;"
        )
        self._status.setText(msg)