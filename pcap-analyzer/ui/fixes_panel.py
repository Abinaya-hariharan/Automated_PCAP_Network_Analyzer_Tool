"""Fixes & Diagnostics tab — enter a packet number, get deep root-cause + fix steps."""
from __future__ import annotations
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTextBrowser, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtCore import QUrl

from analyzer.smart_query import get_packet_detail, get_context_packets, set_pcap
from analyzer.expert_knowledge import diagnose_packet

_BG      = "#0f0f1a"
_SURFACE = "#1a1a2e"
_CARD    = "#16213e"
_BORDER  = "#2a2a4a"
_ACCENT  = "#7c6af7"
_GREEN   = "#22c55e"
_RED     = "#f87171"
_ORANGE  = "#fb923c"
_BLUE    = "#60a5fa"
_TEXT    = "#e2e8f0"
_SUBTEXT = "#64748b"

_SEV_COLOR = {"critical": _RED, "warning": _ORANGE, "info": _BLUE}
_SEV_BG    = {"critical": "#1a0a0a", "warning": "#1a110a", "info": "#0a0f1a"}


class _Worker(QThread):
    done    = pyqtSignal(dict, list)
    errored = pyqtSignal(str)

    def __init__(self, pcap_file: str, frame_num: int):
        super().__init__()
        self._file = pcap_file
        self._num = frame_num

    def run(self):
        try:
            set_pcap(self._file)  # Set the specific file for this query
            pkt     = get_packet_detail(self._num)
            context = get_context_packets(self._num, window=8)
            fix     = diagnose_packet(pkt)
            self.done.emit(fix, context)
        except Exception as e:
            self.errored.emit(str(e))


class FixesPanel(QWidget):
    def __init__(self):
        super().__init__()
        self._worker = None
        self._files_map = {}  # filename -> full path mapping
        self._current_file = ""
        self._build_ui()

    def set_pcap(self, path: str):
        """Support both single files and folders with multiple .pcap files."""
        self._files_map.clear()
        self._file_combo.clear()
        self._current_file = ""
        
        if not path:
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
                    self._file_combo.setCurrentIndex(0)
                    self._update_status_enabled(f"📁 Folder: {len(pcap_files)} files")
                return
        
        # No valid files found
        self._update_status_disabled()

    def _update_status_enabled(self, info: str):
        """Enable diagnostics and show status."""
        self._status.setText(f"✅ {info}")
        self._status.setStyleSheet(f"color:{_GREEN};font-size:11px;")
        self._file_combo.setEnabled(True)
        self._input.setEnabled(True)
        self._btn.setEnabled(True)

    def _update_status_disabled(self):
        """Disable diagnostics and show warning."""
        self._status.setText("⚠  Select .pcap/.pcapng file(s) and click Analyze to enable diagnostics.")
        self._status.setStyleSheet(f"color:{_ORANGE};font-size:11px;")
        self._file_combo.setEnabled(False)
        self._input.setEnabled(False)
        self._btn.setEnabled(False)
        self._result.setHtml(
            f'<p style="color:{_ORANGE};">'
            f'Select one or more .pcap/.pcapng files to enable packet diagnostics.'
            f'</p>'
        )

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)

        # Header
        hdr = QLabel("🔧  Fixes & Diagnostics")
        hdr.setStyleSheet(
            f"color:{_TEXT};font-size:17px;font-weight:800;"
            f"border-bottom:1px solid {_BORDER};padding-bottom:8px;")
        root.addWidget(hdr)

        # Input row: File selector + Packet # + Diagnose button
        input_card = QFrame()
        input_card.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border:1px solid {_BORDER};border-radius:10px;}}")
        ic = QHBoxLayout(input_card)
        ic.setContentsMargins(16, 12, 16, 12)
        ic.setSpacing(10)

        # File selector
        file_lbl = QLabel("File:")
        file_lbl.setStyleSheet(f"color:{_TEXT};font-size:12px;font-weight:700;")
        self._file_combo = QComboBox()
        self._file_combo.setFixedHeight(42)
        self._file_combo.setStyleSheet(
            f"QComboBox{{background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:6px;"
            f"padding:6px 10px;font-size:12px;}}")
        self._file_combo.currentTextChanged.connect(self._on_file_selected)
        
        # Packet number input
        pkt_lbl = QLabel("Packet #:")
        pkt_lbl.setStyleSheet(f"color:{_TEXT};font-size:12px;font-weight:700;")
        self._input = QLineEdit()
        self._input.setPlaceholderText("e.g.  535420")
        self._input.setFixedHeight(42)
        self._input.setStyleSheet(
            f"background:{_CARD};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:8px;"
            f"padding:8px 14px;font-size:14px;font-weight:600;")
        self._input.returnPressed.connect(self._diagnose)
        self._input.setEnabled(False)

        # Diagnose button
        self._btn = QPushButton("🔍  Diagnose")
        self._btn.setFixedHeight(42)
        self._btn.setStyleSheet(
            f"QPushButton{{background:{_ACCENT};color:white;border:none;"
            f"border-radius:8px;font-weight:700;font-size:12px;padding:0 20px;}}"
            f"QPushButton:hover{{background:#9580ff;}}"
            f"QPushButton:disabled{{background:{_BORDER};color:{_SUBTEXT};}}")
        self._btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn.clicked.connect(self._diagnose)
        self._btn.setEnabled(False)

        # Status label
        self._status = QLabel("⚠  Analyze a file first to enable diagnostics.")
        self._status.setStyleSheet(f"color:{_SUBTEXT};font-size:11px;")

        ic.addWidget(file_lbl)
        ic.addWidget(self._file_combo, 1)
        ic.addWidget(pkt_lbl)
        ic.addWidget(self._input, 1)
        ic.addWidget(self._btn)
        root.addWidget(input_card)
        root.addWidget(self._status)

        # Main splitter: fix card (top) + context table (bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{_BORDER};height:3px;}}")

        # Fix result browser
        self._result = QTextBrowser()
        self._result.setOpenLinks(False)
        self._result.anchorClicked.connect(lambda url: QDesktopServices.openUrl(url))
        self._result.setStyleSheet(
            f"QTextBrowser{{background:{_SURFACE};color:{_TEXT};"
            f"border:1px solid {_BORDER};border-radius:8px;"
            f"padding:14px;font-family:'Segoe UI',sans-serif;font-size:13px;line-height:1.7;}}")
        self._result.setHtml(self._placeholder_html())
        splitter.addWidget(self._result)

        # Context table
        ctx_frame = QFrame()
        ctx_v = QVBoxLayout(ctx_frame)
        ctx_v.setContentsMargins(0, 0, 0, 0)
        ctx_v.setSpacing(4)
        ctx_lbl = QLabel("  📊 Surrounding Packets (context window ±8)")
        ctx_lbl.setStyleSheet(
            f"color:{_SUBTEXT};font-size:11px;font-weight:700;"
            f"background:{_BG};padding:4px;border-bottom:1px solid {_BORDER};")
        self._ctx_table = QTableWidget(0, 5)
        self._ctx_table.setHorizontalHeaderLabels(
            ["No.", "Time (s)", "Source → Destination", "Protocol", "Flags"])
        h = self._ctx_table.horizontalHeader()
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        h.resizeSection(0, 70); h.resizeSection(1, 90)
        h.resizeSection(3, 90); h.resizeSection(4, 120)
        self._ctx_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._ctx_table.verticalHeader().setVisible(False)
        self._ctx_table.setShowGrid(False)
        self._ctx_table.setAlternatingRowColors(True)
        self._ctx_table.setStyleSheet(
            f"QTableWidget{{background:{_SURFACE};color:{_TEXT};"
            f"border:none;alternate-background-color:{_CARD};}}"
            f"QHeaderView::section{{background:{_BG};color:{_SUBTEXT};"
            f"border-bottom:1px solid {_BORDER};padding:5px;font-size:11px;font-weight:700;}}")
        ctx_v.addWidget(ctx_lbl)
        ctx_v.addWidget(self._ctx_table)
        splitter.addWidget(ctx_frame)
        splitter.setSizes([480, 260])
        root.addWidget(splitter, 1)

    # ── file selection ────────────────────────────────────────────────────────

    def _on_file_selected(self, filename: str):
        """Handle file selection from dropdown."""
        if filename in self._files_map:
            self._current_file = self._files_map[filename]

    # ── diagnose ───────────────────────────────────────────────────────────────

    def _diagnose(self):
        if not self._current_file:
            self._result.setHtml(
                f'<p style="color:{_ORANGE};">⚠ Please select a file first.</p>')
            return
        
        txt = self._input.text().strip()
        if not txt.isdigit():
            self._result.setHtml(
                f'<p style="color:{_ORANGE};">⚠ Please enter a valid packet number.</p>')
            return
        
        self._btn.setEnabled(False)
        self._btn.setText("Analyzing…")
        self._ctx_table.setRowCount(0)
        self._result.setHtml(
            f'<p style="color:{_SUBTEXT};font-style:italic;">Analyzing packet #{txt} from {os.path.basename(self._current_file)}…</p>')

        self._worker = _Worker(self._current_file, int(txt))
        self._worker.done.connect(self._on_done)
        self._worker.errored.connect(self._on_error)
        self._worker.start()

    def _on_done(self, fix: dict, context: list):
        self._btn.setEnabled(True)
        self._btn.setText("🔍  Diagnose")
        if 'error' in fix:
            self._result.setHtml(
                f'<p style="color:{_RED};">❌ {fix["error"]}</p>')
            return
        self._result.setHtml(self._render_fix(fix))
        self._populate_context(context)

    def _on_error(self, msg: str):
        self._btn.setEnabled(True)
        self._btn.setText("🔍  Diagnose")
        self._result.setHtml(f'<p style="color:{_RED};">❌ Error: {msg}</p>')

    # ── rendering ──────────────────────────────────────────────────────────────

    def _render_fix(self, fix: dict) -> str:
        sev     = fix.get('severity', 'info')
        color   = _SEV_COLOR.get(sev, _BLUE)
        bg      = _SEV_BG.get(sev, _CARD)
        sev_icon = {'critical': '🔴', 'warning': '🟡', 'info': 'ℹ️'}.get(sev, '🔵')
        ref     = fix.get('reference', '')

        causes_html = ''
        if fix.get('causes'):
            causes_html = (
                f'<p style="color:{_ORANGE};font-weight:700;margin:14px 0 6px 0;">⚠️ Common Causes:</p>'
                + ''.join(f'<p style="margin:3px 0 3px 16px;color:{_TEXT};">• {c}</p>'
                          for c in fix['causes'])
            )

        steps_html = ''
        if fix.get('fix_steps'):
            steps_html = (
                f'<p style="color:{_GREEN};font-weight:700;margin:14px 0 6px 0;">🔧 Fix Steps:</p>'
                + ''.join(
                    f'<p style="margin:4px 0 4px 8px;color:{_TEXT};">'
                    f'<pre style="margin:0;white-space:pre-wrap;font-family:Consolas,monospace;'
                    f'font-size:12px;color:{_TEXT};background:{_CARD};">'
                    f'{s}</pre></p>'
                    for s in fix['fix_steps']
                )
            )

        ref_html = (
            f'<p style="margin-top:16px;">'
            f'<a href="{ref}" style="color:{_BLUE};">📖 Reference documentation →</a></p>'
            if ref else ''
        )

        return f"""
        <body style="background:{_BG};font-family:'Segoe UI',sans-serif;">
        <div style="background:{bg};border-left:4px solid {color};
                    border-radius:8px;padding:16px 18px;margin-bottom:12px;">
            <p style="color:{color};font-size:17px;font-weight:800;margin:0 0 4px 0;">
                {sev_icon} {fix.get('title','Diagnosis')}
            </p>
            <p style="color:{_SUBTEXT};font-size:12px;font-family:Consolas;margin:0 0 12px 0;">
                {fix.get('packet_summary','')}
            </p>
            <p style="color:{_TEXT};margin:0;"><b>Root Cause:</b><br>
                {fix.get('root_cause','')}
            </p>
            {'<p style="color:'+_SUBTEXT+';margin:8px 0 0 0;font-style:italic;">' + fix.get('context_note','') + '</p>' if fix.get('context_note') else ''}
        </div>
        {causes_html}
        {steps_html}
        {ref_html}
        </body>"""

    def _populate_context(self, context: list):
        self._ctx_table.setRowCount(len(context))
        for i, p in enumerate(context):
            is_target = p.get('is_target', False)
            bg = QColor("#2d1f0a") if is_target else QColor(_SURFACE)
            fg = QColor(_ORANGE) if is_target else QColor(_TEXT)

            cells = [
                p['num'],
                p['time'],
                f"{p['src']} → {p['dst']}",
                p['proto'],
                p['flags'] + (' ← YOU ARE HERE' if is_target else ''),
            ]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(str(val))
                item.setForeground(fg)
                item.setBackground(bg)
                if col in (0, 3):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._ctx_table.setItem(i, col, item)
            self._ctx_table.setRowHeight(i, 26)

    def _placeholder_html(self) -> str:
        return f"""
        <body style="background:{_BG};font-family:'Segoe UI',sans-serif;">
        <div style="text-align:center;padding:40px;">
            <p style="font-size:48px;margin:0;">🔍</p>
            <p style="color:{_TEXT};font-size:16px;font-weight:700;margin:12px 0 8px 0;">
                Packet Diagnostics</p>
            <p style="color:{_SUBTEXT};font-size:13px;">
                1. Analyze a .pcap / .pcapng file first<br>
                2. Enter a packet number from the Findings tab<br>
                3. Click <b style="color:{_ACCENT};">Diagnose</b> — get root cause + exact fix steps
            </p>
            <p style="color:{_SUBTEXT};font-size:11px;margin-top:20px;">
                Supports: TCP RST · Retransmissions · Zero Window ·<br>
                HTTP errors · DNS failures · ICMP errors · Modbus exceptions
            </p>
        </div></body>"""
