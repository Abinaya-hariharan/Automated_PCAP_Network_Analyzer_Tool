"""Comparison panel — offline PCAP vs live capture, or two offline files."""
from __future__ import annotations
import os, shutil, subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QProgressBar, QTextEdit, QPushButton, QScrollArea, QSplitter,
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

from analyzer.behavior import (
    BehaviorProfile, SimilarityResult, from_report, from_live_stats, compare,
)

_BG      = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD    = "#16213e"
_BORDER  = "#2a2a4a"
_ACCENT  = "#7c6af7"
_ACCENT2 = "#a78bfa"
_GREEN   = "#22c55e"
_RED     = "#f87171"
_ORANGE  = "#fb923c"
_YELLOW  = "#fbbf24"
_TEXT    = "#e2e8f0"
_SUBTEXT = "#64748b"


def _pbar(color: str) -> QProgressBar:
    pb = QProgressBar()
    pb.setRange(0, 100); pb.setValue(0)
    pb.setFixedHeight(8); pb.setTextVisible(False)
    pb.setStyleSheet(
        f"QProgressBar{{background:{_BORDER};border-radius:4px;border:none;}}"
        f"QProgressBar::chunk{{background:{color};border-radius:4px;}}"
    )
    return pb


def _tshark() -> str | None:
    t = shutil.which("tshark")
    if t: return t
    for c in [r"C:\Program Files\Wireshark\tshark.exe",
               r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
        if os.path.isfile(c): return c
    return None


def _fetch_sample_packets(pcap: str, display_filter: str, limit: int = 6) -> list[dict]:
    """Return up to `limit` packets matching a tshark display filter."""
    ts = _tshark()
    if not ts or not pcap or not os.path.isfile(pcap):
        return []
    cmd = [ts, "-r", pcap, "-Y", display_filter, "-T", "fields",
           "-e", "frame.number", "-e", "frame.time_relative",
           "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
           "-e", "frame.len", "-E", "separator=|", "-c", str(limit)]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10)
        rows = []
        for line in out.decode(errors="replace").splitlines():
            parts = (line + "|||||").split("|")
            rows.append({
                "num":   parts[0].strip(),
                "time":  parts[1].strip(),
                "src":   parts[2].strip(),
                "dst":   parts[3].strip(),
                "proto": parts[4].strip(),
                "len":   parts[5].strip(),
            })
        return rows
    except Exception:
        return []


class ComparePanel(QWidget):
    alert_triggered = pyqtSignal(float, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._offline_profile: BehaviorProfile | None = None
        self._offline_path: str = ""
        self._offline_file_paths: list[str] = []
        self._offline2_profile: BehaviorProfile | None = None
        self._offline2_path: str = ""
        self._live_packets: list[dict] = []
        self._live_stats: dict = {}
        self._last_result: SimilarityResult | None = None
        self._alerted_level: str = ""
        self._mode: str = "live"   # 'live' or 'offline2'
        self._profile_worker = None
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_comparison)
        self._refresh_timer.setInterval(3000)
        self._build_ui()

    class _ProfileWorker(QThread):
        finished = pyqtSignal(object, str)

        def __init__(self, path: str):
            super().__init__()
            self._path = path

        def run(self):
            try:
                from analyzer.report import build_report
                self.finished.emit(from_report(build_report(self._path)), "")
            except Exception as exc:
                self.finished.emit(None, str(exc))

    # ── public ────────────────────────────────────────────────────────────────

    def set_offline_report(self, report: dict):
        self._offline_profile = from_report(report)
        self._offline_file_paths = list(report.get("file_paths", []))
        self._render_offline_profile()
        self._try_compare()

    def set_offline_path(self, path: str):
        self._offline_path = path
        if os.path.isfile(path):
            self._offline_file_paths = [path]

    def feed_live_packet(self, pkt: dict):
        self._live_packets.append(pkt)

    def feed_live_stats(self, stats: dict):
        self._live_stats = stats
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def stop_live(self):
        self._refresh_timer.stop()
        self._refresh_comparison()   # final comparison

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # outer layout holds toolbar + scrollable content
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── fixed toolbar (not scrolled) ──────────────────────────────────────
        toolbar = QWidget()
        toolbar.setStyleSheet(f"background:{_BG};")
        tb = QVBoxLayout(toolbar)
        tb.setContentsMargins(16, 10, 16, 8)
        tb.setSpacing(8)

        hdr = QHBoxLayout()
        ttl = QLabel("🔬  Behavior Comparison")
        ttl.setStyleSheet(f"color:{_TEXT};font-size:15px;font-weight:800;")
        hdr.addWidget(ttl)
        hdr.addSpacing(12)

        def _mode_btn(label, mode):
            b = QPushButton(label)
            b.setCheckable(True)
            b.setFixedHeight(30)
            b.setStyleSheet(
                f"QPushButton{{background:{_CARD};color:{_SUBTEXT};"
                f"border:1px solid {_BORDER};border-radius:6px;"
                f"font-size:11px;font-weight:600;padding:0 12px;}}"
                f"QPushButton:checked{{background:{_ACCENT}30;color:{_ACCENT2};"
                f"border-color:{_ACCENT};}}"
            )
            b.clicked.connect(lambda: self._set_mode(mode))
            return b

        self._btn_mode_live = _mode_btn("📡  Offline vs Live", "live")
        self._btn_mode_off2 = _mode_btn("📂  Offline vs Offline", "offline2")
        self._btn_mode_live.setChecked(True)
        hdr.addWidget(self._btn_mode_live)
        hdr.addWidget(self._btn_mode_off2)
        hdr.addStretch(1)
        btn_now = QPushButton("  ↻  Compare Now")
        btn_now.setFixedHeight(30)
        btn_now.setStyleSheet(
            f"QPushButton{{background:{_CARD};color:{_ACCENT2};"
            f"border:1px solid {_ACCENT}50;border-radius:7px;"
            f"font-size:11px;font-weight:600;padding:0 12px;}}"
            f"QPushButton:hover{{background:#1e1e3a;}}"
        )
        btn_now.clicked.connect(self._refresh_comparison)
        hdr.addWidget(btn_now)
        tb.addLayout(hdr)

        # offline-vs-offline picker row
        self._off2_row = QFrame()
        self._off2_row.setStyleSheet(
            f"QFrame{{background:{_CARD};border:1px solid {_BORDER};border-radius:8px;}}"
        )
        off2_h = QHBoxLayout(self._off2_row)
        off2_h.setContentsMargins(12, 6, 12, 6)
        off2_lbl = QLabel("Second PCAP:")
        off2_lbl.setStyleSheet(f"color:{_SUBTEXT};font-size:12px;font-weight:600;")
        self._off2_path_lbl = QLabel("No file selected")
        self._off2_path_lbl.setStyleSheet(f"color:{_SUBTEXT};font-style:italic;font-size:12px;")
        btn_off2 = QPushButton("  📂  Browse…")
        btn_off2.setFixedHeight(28)
        btn_off2.setStyleSheet(
            f"QPushButton{{background:{_SURFACE};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:6px;font-size:12px;padding:0 10px;}}"
            f"QPushButton:hover{{border-color:{_ACCENT};color:{_ACCENT2};}}"
        )
        btn_off2.clicked.connect(self._load_second_file)
        self._btn_off2 = btn_off2
        off2_h.addWidget(off2_lbl)
        off2_h.addWidget(self._off2_path_lbl, 1)
        off2_h.addWidget(btn_off2)
        self._off2_row.setVisible(False)
        tb.addWidget(self._off2_row)
        outer.addWidget(toolbar)

        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"background:{_BORDER};border:none;max-height:1px;")
        outer.addWidget(div)

        # ── scrollable content area ───────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            f"QScrollArea{{background:{_BG};border:none;}}"
            f"QScrollBar:vertical{{background:transparent;width:6px;}}"
            f"QScrollBar::handle:vertical{{background:{_BORDER};border-radius:3px;}}"
        )
        content = QWidget()
        content.setStyleSheet(f"background:{_BG};")
        cv = QVBoxLayout(content)
        cv.setContentsMargins(16, 14, 16, 20)
        cv.setSpacing(14)

        # ── score banner ──────────────────────────────────────────────────────
        self._score_banner = QFrame()
        self._score_banner.setStyleSheet(
            f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 #1a1035,stop:1 #0f2027);"
            f"border:1px solid {_BORDER};border-radius:12px;}}"
        )
        sb_h = QHBoxLayout(self._score_banner)
        sb_h.setContentsMargins(20, 14, 20, 14)
        self._score_icon  = QLabel("⚪")
        self._score_icon.setStyleSheet("font-size:28px;background:transparent;border:none;")
        self._score_pct   = QLabel("—")
        self._score_pct.setStyleSheet(
            f"color:{_TEXT};font-size:32px;font-weight:800;background:transparent;border:none;"
        )
        self._score_label = QLabel("Analyze a PCAP file and start live capture to begin comparison")
        self._score_label.setStyleSheet(
            f"color:{_SUBTEXT};font-size:12px;background:transparent;border:none;"
        )
        self._overall_bar = _pbar(_SUBTEXT)
        self._overall_bar.setFixedWidth(120)
        sb_h.addWidget(self._score_icon)
        sb_h.addSpacing(10)
        sb_h.addWidget(self._score_pct)
        sb_h.addSpacing(14)
        sb_h.addWidget(self._score_label, 1)
        sb_h.addWidget(self._overall_bar)
        cv.addWidget(self._score_banner)

        # ── category scores row (compact horizontal) ──────────────────────────
        cat_sec_lbl = QLabel("CATEGORY SCORES")
        cat_sec_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:10px;font-weight:700;letter-spacing:2px;"
        )
        cat_sec_lbl.setVisible(False)

        self._cat_grid = QWidget()
        self._cat_grid.setStyleSheet("background:transparent;")
        self._cat_grid_layout = QHBoxLayout(self._cat_grid)
        self._cat_grid_layout.setContentsMargins(0, 0, 0, 0)
        self._cat_grid_layout.setSpacing(8)
        self._cat_rows: dict[str, tuple] = {}
        self._cat_grid.setVisible(False)

        # ── similar patterns section ──────────────────────────────────────────
        match_sec_lbl = QLabel("SIMILAR PATTERNS FOUND")
        match_sec_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:10px;font-weight:700;letter-spacing:2px;"
        )
        cv.addWidget(match_sec_lbl)

        self._matches_container = QWidget()
        self._matches_container.setStyleSheet("background:transparent;")
        self._matches_layout = QVBoxLayout(self._matches_container)
        self._matches_layout.setContentsMargins(0, 0, 0, 0)
        self._matches_layout.setSpacing(10)
        self._no_matches_lbl = QLabel(
            "  No matches yet — run a comparison to see similar patterns between both captures"
        )
        self._no_matches_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:12px;"
            f"background:{_CARD};border:1px dashed {_BORDER};"
            f"border-radius:8px;padding:16px;"
        )
        self._matches_layout.addWidget(self._no_matches_lbl)
        cv.addWidget(self._matches_container)
        cv.addStretch(1)

        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

    # ── profile box kept for backward compat with _set_mode ───────────────────
    def _profile_box(self, title: str, placeholder: str):
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame{{background:{_SURFACE};"
            f"border:1px solid {_BORDER};border-radius:10px;}}"
        )
        v = QVBoxLayout(frame)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(6)
        ttl = QLabel(title)
        ttl.setStyleSheet(
            f"color:{_TEXT};font-size:12px;font-weight:700;"
            f"border-bottom:1px solid {_BORDER};padding-bottom:4px;"
        )
        content = QTextEdit()
        content.setReadOnly(True)
        content.setStyleSheet(
            f"QTextEdit{{background:transparent;border:none;"
            f"font-size:11px;color:{_SUBTEXT};}}"
        )
        content.setPlaceholderText(placeholder)
        v.addWidget(ttl)
        v.addWidget(content, 1)
        return frame, content

    # ── mode switching ────────────────────────────────────────────────────────

    def _set_mode(self, mode: str):
        self._mode = mode
        self._btn_mode_live.setChecked(mode == "live")
        self._btn_mode_off2.setChecked(mode == "offline2")
        self._off2_row.setVisible(mode == "offline2")
        if mode == "offline2" and self._offline2_profile:
            self._refresh_comparison()

    def _load_second_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Second PCAP", "",
            "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if not path:
            return
        self._offline2_path = path
        self._off2_path_lbl.setText(f"  📄  {os.path.basename(path)}")
        self._off2_path_lbl.setStyleSheet(
            f"color:{_TEXT};font-style:normal;font-size:12px;"
        )
        self._score_label.setText("⏳  Analyzing second file…")
        self._btn_off2.setEnabled(False)
        self._profile_worker = self._ProfileWorker(path)
        self._profile_worker.finished.connect(self._second_profile_ready)
        self._profile_worker.start()

    def _second_profile_ready(self, profile: BehaviorProfile | None, error: str):
        self._btn_off2.setEnabled(True)
        if error or profile is None:
            self._offline2_profile = None
            self._score_label.setText(f"Unable to analyze second file: {error}")
            return
        self._offline2_profile = profile
        self._score_label.setText("Second capture analyzed. Click Compare Now to refresh the comparison.")
        self._refresh_comparison()

    # ── rendering ─────────────────────────────────────────────────────────────

    def _render_offline_profile(self):
        pass  # shown inside match cards

    def _render_live_profile(self, p: BehaviorProfile):
        pass  # shown inside match cards

    def _format_profile(self, p: BehaviorProfile) -> str:
        return f"Total: {p.total_packets:,}  Dominant: {p.dominant_protocol or '—'}"

    def _update_category_bars(self, result: SimilarityResult):
        cats = result.categories
        while self._cat_grid_layout.count():
            item = self._cat_grid_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._cat_rows.clear()

        for name, score in cats.items():
            pct = int(score * 100)
            color = _GREEN if score > 0.7 else _YELLOW if score > 0.4 else _RED
            chip = QFrame()
            chip.setStyleSheet(
                f"QFrame{{background:{_CARD};"
                f"border:1px solid {color}40;"
                f"border-bottom:2px solid {color};"
                f"border-radius:8px;}}"
            )
            chv = QVBoxLayout(chip)
            chv.setContentsMargins(10, 6, 10, 6)
            chv.setSpacing(3)
            top = QHBoxLayout()
            nlbl = QLabel(name)
            nlbl.setStyleSheet(
                f"color:{_TEXT};font-size:10px;font-weight:600;background:transparent;border:none;"
            )
            vlbl = QLabel(f"{pct}%")
            vlbl.setStyleSheet(
                f"color:{color};font-size:12px;font-weight:800;background:transparent;border:none;"
            )
            vlbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            top.addWidget(nlbl, 1)
            top.addWidget(vlbl)
            pb = QProgressBar()
            pb.setRange(0, 100); pb.setValue(pct); pb.setFixedHeight(5)
            pb.setTextVisible(False)
            pb.setStyleSheet(
                f"QProgressBar{{background:{_BORDER};border-radius:3px;border:none;}}"
                f"QProgressBar::chunk{{background:{color};border-radius:3px;}}"
            )
            chv.addLayout(top)
            chv.addWidget(pb)
            self._cat_grid_layout.addWidget(chip, 1)
            self._cat_rows[name] = (nlbl, pb, vlbl)

    def _update_match_list(self, r: SimilarityResult):
        while self._matches_layout.count():
            item = self._matches_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not r.rich_matches:
            lbl = QLabel("  No behavioral matches found — traffic patterns are different")
            lbl.setStyleSheet(
                f"color:{_SUBTEXT};font-size:12px;"
                f"background:{_CARD};border:1px dashed {_BORDER};"
                f"border-radius:8px;padding:16px;"
            )
            self._matches_layout.addWidget(lbl)
            return

        wanted = {
            "Shared Protocols", "Shared Ports", "ARP Broadcast Storm",
            "Same Source → Destination",
        }
        visible_matches = [m for m in r.rich_matches if m.get("title") in wanted]
        if not visible_matches:
            lbl = QLabel("  No shared protocols, ports, ARP storm, or exact endpoint pairs found")
            lbl.setStyleSheet(
                f"color:{_SUBTEXT};font-size:12px;background:{_CARD};"
                f"border:1px dashed {_BORDER};border-radius:8px;padding:16px;"
            )
            self._matches_layout.addWidget(lbl)
            return
        for m in visible_matches:
            self._matches_layout.addWidget(self._mk_match_card(m))

    def _mk_match_card(self, m: dict) -> QFrame:
        card = QFrame()
        card.setStyleSheet(
            f"QFrame{{background:{_SURFACE};"
            f"border:1px solid {_BORDER};"
            f"border-left:4px solid {_GREEN};"
            f"border-radius:10px;}}"
        )
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 12, 16, 12)
        v.setSpacing(10)

        # title + detail row
        title_row = QHBoxLayout()
        icon_lbl = QLabel(m.get("icon", "✓"))
        icon_lbl.setStyleSheet("font-size:18px;background:transparent;border:none;")
        title_lbl = QLabel(m.get("title", ""))
        title_lbl.setStyleSheet(
            f"color:{_TEXT};font-size:13px;font-weight:700;background:transparent;border:none;"
        )
        detail_lbl = QLabel(m.get("detail", ""))
        detail_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;background:transparent;border:none;"
        )
        title_row.addWidget(icon_lbl)
        title_row.addWidget(title_lbl)
        title_row.addStretch(1)
        title_row.addWidget(detail_lbl)
        v.addLayout(title_row)

        # side-by-side aggregate evidence
        evidence_row = QHBoxLayout()
        evidence_row.setSpacing(12)
        for side_label, items in [("📂  Offline PCAP", m.get("offline", [])),
                                    ("📡  Live / Second", m.get("live", []))]:
            box = QFrame()
            box.setStyleSheet(
                f"QFrame{{background:{_CARD};border:1px solid {_BORDER}40;border-radius:8px;}}"
            )
            bv = QVBoxLayout(box)
            bv.setContentsMargins(10, 8, 10, 8)
            bv.setSpacing(4)
            hdr_lbl = QLabel(side_label)
            hdr_lbl.setStyleSheet(
                f"color:{_ACCENT2};font-size:10px;font-weight:700;"
                f"background:transparent;border:none;letter-spacing:1px;"
            )
            bv.addWidget(hdr_lbl)
            for item in (items or ["—"]):
                il = QLabel(f"  {item}")
                il.setStyleSheet(
                    f"color:{_TEXT};font-size:12px;background:transparent;border:none;"
                )
                bv.addWidget(il)
            evidence_row.addWidget(box, 1)
        v.addLayout(evidence_row)

        # ── matching packets section ───────────────────────────────────────────
        pkt_filter = m.get("filter", "")
        if pkt_filter and _tshark():
            pkt_lbl = QLabel("Matching Packets")
            pkt_lbl.setStyleSheet(
                f"color:{_SUBTEXT};font-size:10px;font-weight:700;letter-spacing:1px;"
            )
            v.addWidget(pkt_lbl)

            # two tables side by side
            tables_row = QHBoxLayout()
            tables_row.setSpacing(10)

            offline_paths = self._offline_file_paths or ([self._offline_path] if self._offline_path else [])
            for file_path, col_title in [
                (offline_paths,  f"📂  Offline PCAP — {self._offline_path}" if len(offline_paths) > 1 else "📂  Offline PCAP"),
                (self._offline2_path if self._mode == "offline2" else "", "📡  Live / Second"),
            ]:
                tbl_frame = QFrame()
                tbl_frame.setStyleSheet(
                    f"QFrame{{background:{_CARD};border:1px solid {_BORDER}40;border-radius:8px;}}"
                )
                tf_v = QVBoxLayout(tbl_frame)
                tf_v.setContentsMargins(0, 0, 0, 0)
                tf_v.setSpacing(0)
                col_hdr = QLabel(f"  {col_title}")
                col_hdr.setStyleSheet(
                    f"color:{_ACCENT2};font-size:10px;font-weight:700;"
                    f"background:{_BG};border-radius:8px 8px 0 0;"
                    f"padding:6px 10px;letter-spacing:1px;"
                )
                tf_v.addWidget(col_hdr)

                is_multi_offline = isinstance(file_path, list)
                tbl = QTableWidget(0, 5 if is_multi_offline else 4)
                tbl.setHorizontalHeaderLabels(
                    ["File", "Pkt #", "Time (s)", "Src → Dst", "Proto"]
                    if is_multi_offline else ["Pkt #", "Time (s)", "Src → Dst", "Proto"]
                )
                tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
                tbl.horizontalHeader().resizeSection(0, 55)
                tbl.horizontalHeader().resizeSection(1, 80)
                tbl.horizontalHeader().resizeSection(3, 60)
                tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
                tbl.verticalHeader().setVisible(False)
                tbl.setShowGrid(False)
                tbl.setAlternatingRowColors(True)
                tbl.setFixedHeight(140)
                tbl.setStyleSheet(
                    f"QTableWidget{{background:{_CARD};border:none;color:{_TEXT};}}"
                    f"QTableWidget::item{{padding:4px 6px;}}"
                    f"QHeaderView::section{{background:{_BG};color:{_SUBTEXT};"
                    f"padding:4px 6px;border:none;border-bottom:1px solid {_BORDER};"
                    f"font-size:10px;font-weight:700;}}"
                )

                if is_multi_offline:
                    pkts = []
                    for source_path in file_path:
                        for packet in _fetch_sample_packets(source_path, pkt_filter, max(1, 6 - len(pkts))):
                            packet["file"] = os.path.basename(source_path)
                            pkts.append(packet)
                            if len(pkts) >= 6:
                                break
                        if len(pkts) >= 6:
                            break
                    tbl.setRowCount(len(pkts))
                    for row, p in enumerate(pkts):
                        flow = f"{p['src']} → {p['dst']}" if p["src"] else "—"
                        values = [p.get("file", ""), p["num"], p["time"], flow, p["proto"]]
                        for col, (val, color) in enumerate(zip(values, [_SUBTEXT, _ACCENT2, _SUBTEXT, _TEXT, _ACCENT2])):
                            item = QTableWidgetItem(val)
                            item.setForeground(QColor(color))
                            tbl.setItem(row, col, item)
                            tbl.setRowHeight(row, 24)
                elif file_path and os.path.isfile(file_path):
                    pkts = _fetch_sample_packets(file_path, pkt_filter)
                    tbl.setRowCount(len(pkts))
                    for row, p in enumerate(pkts):
                        flow = f"{p['src']} → {p['dst']}" if p["src"] else "—"
                        for col, (val, color) in enumerate(zip(
                            [p["num"], p["time"], flow, p["proto"]],
                            [_ACCENT2, _SUBTEXT, _TEXT, _ACCENT2]
                        )):
                            item = QTableWidgetItem(val)
                            item.setForeground(QColor(color))
                            tbl.setItem(row, col, item)
                            tbl.setRowHeight(row, 24)
                elif self._mode == "live" and col_title.startswith("📡") and self._live_packets:
                    # for live mode, filter from in-memory packets
                    proto_kw = pkt_filter.lower().replace("tcp.flags.reset==1", "rst")
                    matched = [p for p in self._live_packets
                               if proto_kw in p.get("proto", "").lower()
                               or proto_kw in p.get("info", "").lower()][:6]
                    tbl.setRowCount(len(matched))
                    for row, p in enumerate(matched):
                        flow = f"{p.get('src','')} → {p.get('dst','')}"
                        for col, (val, color) in enumerate(zip(
                            [str(p.get("num","")), str(p.get("time","")), flow, p.get("proto","")],
                            [_ACCENT2, _SUBTEXT, _TEXT, _ACCENT2]
                        )):
                            item = QTableWidgetItem(val)
                            item.setForeground(QColor(color))
                            tbl.setItem(row, col, item)
                            tbl.setRowHeight(row, 24)
                else:
                    tbl.setRowCount(1)
                    item = QTableWidgetItem("  No file path available for packet lookup")
                    item.setForeground(QColor(_SUBTEXT))
                    tbl.setItem(0, 0, item)
                    tbl.setSpan(0, 0, 1, 4)

                tf_v.addWidget(tbl)
                tables_row.addWidget(tbl_frame, 1)
            v.addLayout(tables_row)

        return card

    def _refresh_comparison(self):
        if not self._offline_profile:
            return
        if self._mode == "offline2":
            if not self._offline2_profile:
                if self._offline2_path and self._profile_worker and self._profile_worker.isRunning():
                    self._score_label.setText("⏳  Analyzing the selected second capture…")
                else:
                    self._score_label.setText("Select a second .pcap file above to compare")
                return
            right_profile = self._offline2_profile
        else:
            if not self._live_packets:
                return
            right_profile = from_live_stats(self._live_stats, self._live_packets)
        result = compare(self._offline_profile, right_profile)
        self._last_result = result
        self._update_score_card(result)
        self._update_category_bars(result)
        self._update_match_list(result)
        if self._mode == "live":
            self._check_alert(result)

    def _try_compare(self):
        if self._offline_profile and (self._live_packets or self._offline2_profile):
            self._refresh_comparison()

    def _update_score_card(self, r: SimilarityResult):
        pct = int(r.overall * 100)
        self._score_pct.setText(f"{pct}%")
        self._score_pct.setStyleSheet(
            f"color:{r.level_color};font-size:32px;font-weight:800;"
            f"background:transparent;border:none;"
        )
        self._score_icon.setText(r.level_icon)
        descs = {
            "low":      "Low similarity — traffic patterns differ significantly",
            "medium":   "Medium similarity — some overlapping patterns detected",
            "high":     "High similarity — traffic closely resembles the other capture!",
            "critical": "Critical — captures are nearly identical in behaviour!",
        }
        self._score_label.setText(descs.get(r.level, ""))
        self._score_label.setStyleSheet(
            f"color:{r.level_color};font-size:12px;background:transparent;border:none;"
        )
        self._overall_bar.setValue(pct)
        self._overall_bar.setStyleSheet(
            f"QProgressBar{{background:{_BORDER};border-radius:4px;border:none;}}"
            f"QProgressBar::chunk{{background:{r.level_color};border-radius:4px;}}"
        )

    def _check_alert(self, r: SimilarityResult):
        if r.level in ("high", "critical") and self._alerted_level != r.level:
            self._alerted_level = r.level
            self.alert_triggered.emit(r.overall, r.level)
