"""PCAP assistant — local rule-based + Groq AI."""
from __future__ import annotations
import re
from collections import Counter

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel,
    QScrollArea, QFrame,
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal

from analyzer.ai_chat import ask as _groq_ask, load_key, save_key

_CFG_KEY_EXISTS = bool(load_key())


class _GroqWorker(QThread):
    answered = pyqtSignal(str)
    errored  = pyqtSignal(str)

    def __init__(self, question: str, report: dict, api_key: str, history: list):
        super().__init__()
        self._q, self._report, self._key, self._history = question, report, api_key, history

    def run(self):
        try:
            self.answered.emit(_groq_ask(self._q, self._report, self._key, self._history))
        except Exception as e:
            self.errored.emit(str(e))

# ── palette passed in from main_window ────────────────────────────────────────
_PROTO_HELP = {
    "modbus": (
        "Modbus TCP is an industrial automation protocol used to read/write "
        "registers on PLCs and drives. Port 502. Modbus dominance in a capture "
        "means this is a factory/SCADA network."
    ),
    "arp": (
        "ARP (Address Resolution Protocol) maps IP addresses to MAC addresses. "
        "Unanswered ARP requests mean a device is broadcasting 'who has IP X?' "
        "but nobody replies — the target IP is offline, misconfigured, or doesn't exist."
    ),
    "tcp": (
        "TCP (Transmission Control Protocol) provides reliable, ordered delivery. "
        "TCP RST = connection forcibly reset by the remote end. "
        "Retransmissions = a packet was sent but not acknowledged, so it's resent."
    ),
    "tcp rst": (
        "TCP RST (Reset) means a connection was abruptly terminated. "
        "Common causes: server refused the connection, firewall dropped it, "
        "the server process crashed, or the remote end went offline mid-session."
    ),
    "retransmission": (
        "A retransmission occurs when a TCP segment is resent because the sender "
        "didn't receive an ACK within the timeout. High retransmissions indicate "
        "packet loss, network congestion, or an overwhelmed receiver."
    ),
    "igmp": (
        "IGMP (Internet Group Management Protocol) manages multicast group membership. "
        "Seen in networks with multicast streaming or industrial protocols using multicast."
    ),
    "stp": (
        "STP (Spanning Tree Protocol) prevents Layer 2 loops in switched networks. "
        "Normal background traffic on managed switches."
    ),
    "lldp": (
        "LLDP (Link Layer Discovery Protocol) lets network devices advertise "
        "their identity and capabilities to neighbors. Normal background traffic."
    ),
    "icmp": (
        "ICMP (Internet Control Message Protocol) carries diagnostic messages "
        "like ping (echo request/reply) and 'destination unreachable' errors."
    ),
    "dns": (
        "DNS (Domain Name System) resolves hostnames to IP addresses. "
        "Excessive DNS failures can slow down applications."
    ),
}

_QUICK_TIPS = [
    "how many errors?",
    "explain TCP RST",
    "top flows",
    "top protocols",
    "how many packets?",
    "what is MODBUS?",
    "explain ARP warnings",
    "summary",
]


class ChatPanel(QWidget):
    def __init__(self, bg: str, surface: str, accent: str, text: str,
                 subtext: str, border: str, sev_fg: dict):
        super().__init__()
        self._bg = bg
        self._surface = surface
        self._accent = accent
        self._text = text
        self._subtext = subtext
        self._border = border
        self._sev_fg = sev_fg
        self._report: dict | None = None
        self._demo_queue: list[str] = []
        self._demo_timer = QTimer(self)
        self._demo_timer.timeout.connect(self._demo_next)
        self._groq_history: list = []
        self._groq_worker = None
        self._build_ui()
        self._greet()

    # ── public API ─────────────────────────────────────────────────────────────

    def set_report(self, report: dict):
        self._report = report
        n = report.get("total_packets", 0)
        n_err  = sum(1 for f in report["findings"] if f["severity"] == "error")
        n_warn = sum(1 for f in report["findings"] if f["severity"] == "warn")
        c_err  = self._sev_fg["error"]
        c_warn = self._sev_fg["warn"]
        self._add_bot(
            f"Analysis loaded — <b>{n:,} packets</b>, "
            f"<span style='color:{c_err}'>{n_err:,} errors</span>, "
            f"<span style='color:{c_warn}'>{n_warn:,} warnings</span>.<br>"
            "Ask me anything about the results!"
        )

    # ── UI build ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(12, 10, 12, 10)
        vbox.setSpacing(8)

        # header
        hdr = QLabel("🤖  PCAP Assistant")
        hdr.setStyleSheet(
            f"color:{self._text};font-size:14px;font-weight:700;"
            f"border-bottom:1px solid {self._border};padding-bottom:6px;"
        )
        vbox.addWidget(hdr)

        # chat history
        self._history = QTextEdit()
        self._history.setReadOnly(True)
        self._history.setStyleSheet(
            f"QTextEdit{{background:{self._bg};border:1px solid {self._border};"
            f"border-radius:8px;padding:10px;font-size:13px;}}"
        )
        vbox.addWidget(self._history, 1)

        # quick-tip chips
        chip_row = QWidget()
        chip_layout = QHBoxLayout(chip_row)
        chip_layout.setContentsMargins(0, 0, 0, 0)
        chip_layout.setSpacing(6)
        lbl_try = QLabel("Try:")
        lbl_try.setStyleSheet(f"color:{self._subtext};font-size:11px;")
        chip_layout.addWidget(lbl_try)
        for tip in _QUICK_TIPS[:4]:
            btn = QPushButton(tip)
            btn.setStyleSheet(
                f"QPushButton{{background:{self._surface};color:{self._subtext};"
                f"border:1px solid {self._border};border-radius:12px;"
                f"padding:3px 10px;font-size:11px;font-weight:500;}}"
                f"QPushButton:hover{{color:{self._text};border-color:{self._accent};}}"
            )
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, t=tip: self._ask(t))
            chip_layout.addWidget(btn)
        chip_layout.addStretch()
        vbox.addWidget(chip_row)

        # AI provider key row (hidden if key already saved)
        key_row = QWidget()
        key_row.setStyleSheet(
            f"background:{self._surface};border-radius:8px;border:1px solid {self._border};")
        kh = QHBoxLayout(key_row)
        kh.setContentsMargins(10, 6, 10, 6); kh.setSpacing(8)
        lbl_k = QLabel("\U0001f511 AI API Key:")
        lbl_k.setStyleSheet(f"color:{self._subtext};font-size:11px;font-weight:700;")
        self._key_input = QLineEdit()
        self._key_input.setPlaceholderText("Paste the approved AI provider key to enable answers")
        self._key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_input.setFixedHeight(30)
        self._key_input.setStyleSheet(
            f"background:#1a1a2e;color:{self._text};"
            f"border:1px solid {self._border};border-radius:6px;"
            f"padding:4px 10px;font-size:11px;")
        self._btn_eye = QPushButton("\U0001f441")
        self._btn_eye.setFixedSize(30, 30); self._btn_eye.setCheckable(True)
        self._btn_eye.setStyleSheet(
            f"QPushButton{{background:{self._border};color:{self._text};"
            f"border:none;border-radius:6px;font-size:13px;}}"
            f"QPushButton:checked{{background:{self._accent};}}")
        self._btn_eye.clicked.connect(
            lambda c: self._key_input.setEchoMode(
                QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        btn_save_k = QPushButton("Save")
        btn_save_k.setFixedSize(60, 30)
        btn_save_k.setStyleSheet(
            f"QPushButton{{background:{self._border};color:{self._text};"
            f"border:none;border-radius:6px;font-size:11px;}}"
            f"QPushButton:hover{{background:{self._accent};color:white;}}")
        btn_save_k.clicked.connect(self._save_key)
        btn_change = QPushButton("\U0001f511 Change Key")
        btn_change.setFixedHeight(24)
        btn_change.setStyleSheet(
            f"QPushButton{{background:transparent;color:{self._subtext};"
            f"border:1px solid {self._border};border-radius:5px;"
            f"padding:2px 8px;font-size:10px;}}"
            f"QPushButton:hover{{color:{self._accent};border-color:{self._accent};}}")
        btn_change.clicked.connect(lambda: key_row.setVisible(True))
        kh.addWidget(lbl_k); kh.addWidget(self._key_input, 1)
        kh.addWidget(self._btn_eye); kh.addWidget(btn_save_k)
        vbox.addWidget(key_row)
        self._key_row = key_row
        self._btn_change_key = btn_change
        vbox.addWidget(btn_change)
        # hide key row if already saved; show change button instead
        if load_key():
            key_row.setVisible(False)
        else:
            btn_change.setVisible(False)

        # input row — AI answers, Enter key triggers it
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        self._input = QLineEdit()
        self._input.setPlaceholderText("Ask anything about the capture\u2026 press Enter or click Ask AI")
        self._input.setFixedHeight(42)
        self._input.returnPressed.connect(self._send_groq)
        self._btn_groq = QPushButton("\u2726 Ask AI")
        self._btn_groq.setFixedSize(130, 42)
        self._btn_groq.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_groq.setStyleSheet(
            f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"stop:0 {self._accent},stop:1 #a855f7);"
            f"color:white;border:none;border-radius:8px;font-weight:700;font-size:13px;}}"
            f"QPushButton:hover{{background:{self._accent};}}"
            f"QPushButton:disabled{{background:{self._border};color:{self._subtext};}}")
        self._btn_groq.clicked.connect(self._send_groq)
        h.addWidget(self._input, 1)
        h.addWidget(self._btn_groq)
        vbox.addWidget(row)

    def _greet(self):
        self._add_bot(
            "Hi! I'm your PCAP analysis assistant.<br><br>"
            "Use <b>Send</b> for instant local answers or "
            "<b>\u2726 Ask AI</b> for capture-specific analysis.<br><br>"
            f"<span style='color:{self._subtext}'>Quick examples: "
            "<i>how many errors? · explain TCP RST · top flows · what is MODBUS?</i></span>"
        )

    # ── Groq key + AI send ─────────────────────────────────────────────────────

    def _save_key(self):
        key = self._key_input.text().strip()
        if key:
            save_key(key)
            self._key_input.clear()
            self._btn_eye.setChecked(False)
            self._key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._key_row.setVisible(False)
            self._btn_change_key.setVisible(True)
            self._add_bot("\u2705 AI key saved. Click <b>\u2726 Ask AI</b> for detailed answers.")
        else:
            self._add_bot("\u26a0 Please paste the AI provider key first.")

    def _send_groq(self):
        text = self._input.text().strip()
        if not text:
            return
        if not self._report:
            self._add_bot("\u26a0 Please analyze a capture file first.")
            return
        key = self._key_input.text().strip() or load_key()
        if not key:
            self._add_bot("\u26a0 Enter the AI provider key above and click Save.")
            self._key_row.setVisible(True)
            return
        self._input.clear()
        self._add_user(text)
        self._btn_groq.setEnabled(False)
        self._btn_groq.setText("Thinking\u2026")
        self._groq_worker = _GroqWorker(text, self._report, key, self._groq_history)
        self._groq_worker.answered.connect(lambda ans, q=text: self._on_groq_answer(ans, q))
        self._groq_worker.errored.connect(self._on_groq_error)
        self._groq_worker.start()

    def _on_groq_answer(self, answer: str, question: str):
        self._groq_history.append({"role": "user",      "text": question})
        self._groq_history.append({"role": "assistant", "text": answer[:300]})
        if len(self._groq_history) > 6:
            self._groq_history = self._groq_history[-6:]
        import re as _re
        html = _re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>',
                       answer.replace("&", "&amp;").replace("<", "&lt;")
                             .replace("\n", "<br>"))
        self._add_bot(f"<span style='color:#a5b4fc'>\u2726 AI:</span><br>{html}")
        self._btn_groq.setEnabled(True)
        self._btn_groq.setText("\u2726 Ask AI")

    def _on_groq_error(self, msg: str):
        import re as _re
        m = _re.search(r"'message':\s*'([^']+)'", msg)
        friendly = m.group(1) if m else msg[:300]
        self._add_bot(f"<span style='color:#f87171'>\u274c AI provider error: {friendly}</span>")
        self._btn_groq.setEnabled(True)
        self._btn_groq.setText("\u2726 Ask AI")

    # ── auto demo ──────────────────────────────────────────────────────────────

    # 30 varied questions covering every aspect of the analysis
    _DEMO_QUESTIONS = [
        "summary",
        "how many packets?",
        "how many errors?",
        "how many warnings?",
        "how many flows?",
        "top flows",
        "top protocols",
        "what is the most common protocol?",
        "what is MODBUS?",
        "explain ARP",
        "what is TCP?",
        "explain TCP RST",
        "what does retransmission mean?",
        "what is IGMP?",
        "what is STP?",
        "what is LLDP?",
        "what is ICMP?",
        "explain ARP warnings",
        "what are the errors in this capture?",
        "show warnings",
        "info findings",
        "what does TCP RST mean for this network?",
        "which IPs are generating the most traffic?",
        "protocols breakdown",
        "how many conversations are there?",
        "what does ARP unanswered mean here?",
        "retransmit details",
        "what is rst?",
        "overview",
        "help",
    ]

    def _run_demo(self):
        if self._report is None:
            self._add_bot(
                "<span style='color:#fb923c'>⚠  Please analyze a .pcap file first, "
                "then click Run 30 Auto Questions.</span>"
            )
            return
        if self._demo_timer.isActive():
            return  # already running
        self._demo_queue = list(self._DEMO_QUESTIONS)
        self._add_bot(
            f"<b style='color:{self._accent}'>🎬 Starting automated demo — "
            f"{len(self._demo_queue)} questions about your capture…</b>"
        )
        self._demo_timer.start(900)  # one question every 900ms

    def _demo_next(self):
        if not self._demo_queue:
            self._demo_timer.stop()
            self._add_bot(
                f"<b style='color:#22c55e'>✅ Demo complete — "
                f"all 30 questions answered!</b>"
            )
            return
        q = self._demo_queue.pop(0)
        self._add_user(q)
        self._add_bot(self._respond(q))

    # ── messaging ──────────────────────────────────────────────────────────────

    def _ask(self, text: str):
        self._input.setText(text)
        self._send()

    def _send(self):
        text = self._input.text().strip()
        if not text:
            return
        self._input.clear()
        self._add_user(text)
        self._add_bot(self._respond(text))

    def _add_user(self, text: str):
        self._history.append(
            f'<div style="text-align:right;margin:6px 0;">'
            f'<span style="background:{self._accent};color:white;border-radius:12px;'
            f'padding:6px 12px;display:inline-block;font-size:13px;">{self._esc(text)}</span>'
            f'</div>'
        )

    def _add_bot(self, html: str):
        self._history.append(
            f'<div style="margin:6px 0;">'
            f'<span style="color:{self._subtext};font-size:11px;font-weight:700;">🤖 Assistant</span><br>'
            f'<span style="color:{self._text};font-size:13px;line-height:1.6;">{html}</span>'
            f'</div><hr style="border:none;border-top:1px solid {self._border};margin:4px 0;">'
        )
        # scroll to bottom
        sb = self._history.verticalScrollBar()
        sb.setValue(sb.maximum())

    @staticmethod
    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── response engine ────────────────────────────────────────────────────────

    def _respond(self, q: str) -> str:  # noqa: C901
        ql = q.lower().strip()
        r = self._report

        if r is None:
            return ("No analysis loaded yet. Please open a <code>.pcap</code> file "
                    "and click <b>Analyze</b> first.")

        findings = r.get("findings", [])
        flows    = r.get("flows", [])
        protos   = r.get("protocol_summary", {})
        total    = r.get("total_packets", 0)
        n_err    = sum(1 for f in findings if f["severity"] == "error")
        n_warn   = sum(1 for f in findings if f["severity"] == "warn")
        n_info   = sum(1 for f in findings if f["severity"] == "info")
        c_err    = self._sev_fg["error"]
        c_warn   = self._sev_fg["warn"]

        def has(*words):
            return all(w in ql for w in words)

        def any_of(*words):
            return any(w in ql for w in words)

        # ── help ──────────────────────────────────────────────────────────────
        if any_of("help", "what can you", "commands", "what do you do"):
            return (
                "I can answer questions like:<br>"
                "&nbsp;&nbsp;• <i>errors, warnings, packets, flows, info</i><br>"
                "&nbsp;&nbsp;• <i>top flows, top protocols, protocol breakdown</i><br>"
                "&nbsp;&nbsp;• <i>explain TCP RST, retransmissions, ARP</i><br>"
                "&nbsp;&nbsp;• <i>what is MODBUS / ARP / TCP / IGMP / STP / LLDP?</i><br>"
                "&nbsp;&nbsp;• <i>summary</i>"
            )

        # ── summary ───────────────────────────────────────────────────────────
        if any_of("summary", "overview", "tell me", "what happened", "results", "overall"):
            top_p = list(protos.items())[:3]
            proto_str = ", ".join(f"{p} ({c:,})" for p, c in top_p)
            return (
                f"<b>Capture summary:</b><br>"
                f"&nbsp;&nbsp;• <b>{total:,}</b> total packets<br>"
                f"&nbsp;&nbsp;• <b>{len(flows):,}</b> unique flows/conversations<br>"
                f"&nbsp;&nbsp;• <span style='color:{c_err}'><b>{n_err:,}</b> errors</span><br>"
                f"&nbsp;&nbsp;• <span style='color:{c_warn}'><b>{n_warn:,}</b> warnings</span><br>"
                f"&nbsp;&nbsp;• Top protocols: <b>{proto_str or '—'}</b>"
            )

        # ── packets ───────────────────────────────────────────────────────────
        if any_of("packet", "total"):
            return f"This capture contains <b>{total:,} packets</b>."

        # ── errors ────────────────────────────────────────────────────────────
        if "error" in ql and "warning" not in ql:
            if n_err == 0:
                return "✅ <b>No errors</b> detected in this capture."
            top = Counter(
                " ".join(f["msg"].split()[:7])
                for f in findings if f["severity"] == "error"
            ).most_common(5)
            lines = [f"<span style='color:{c_err}'><b>{n_err:,} errors</b></span> found. Top types:<br>"]
            for msg, cnt in top:
                lines.append(f"&nbsp;&nbsp;• <b>{cnt:,}×</b> {self._esc(msg)}…")
            return "<br>".join(lines)

        # ── warnings ──────────────────────────────────────────────────────────
        if any_of("warning", "warn"):
            if n_warn == 0:
                return "✅ <b>No warnings</b> detected."
            top = Counter(
                " ".join(f["msg"].split()[:7])
                for f in findings if f["severity"] == "warn"
            ).most_common(5)
            lines = [f"<span style='color:{c_warn}'><b>{n_warn:,} warnings</b></span>. Top types:<br>"]
            for msg, cnt in top:
                lines.append(f"&nbsp;&nbsp;• <b>{cnt:,}×</b> {self._esc(msg)}…")
            return "<br>".join(lines)

        # ── info findings ─────────────────────────────────────────────────────
        if "info" in ql:
            if n_info == 0:
                return "No informational findings in this capture."
            infos = [f for f in findings if f["severity"] == "info"]
            lines = [f"<b>{n_info} informational findings:</b><br>"]
            for f in infos[:10]:
                lines.append(f"&nbsp;&nbsp;• [{f.get('protocol','?')}] {self._esc(f['msg'])}")
            return "<br>".join(lines)

        # ── flows / conversations ─────────────────────────────────────────────
        if any_of("flow", "conversation", "connection", "busiest", "top talk"):
            if not flows:
                return "No flow data available."
            lines = [f"<b>Top {min(8, len(flows))} conversations:</b><br>"]
            for fl in flows[:8]:
                lines.append(
                    f"&nbsp;&nbsp;• {self._esc(fl['src'])} ↔ {self._esc(fl['dst'])}"
                    f"&nbsp;&nbsp;<b style='color:{self._accent}'>{fl['protocol']}</b>"
                    f"&nbsp;&nbsp;<b>{fl['packets']:,} pkts</b>"
                )
            return "<br>".join(lines)

        # ── protocols ─────────────────────────────────────────────────────────
        if any_of("protocol", "breakdown", "traffic type"):
            if not protos:
                return "No protocol data available."
            lines = ["<b>Protocol breakdown:</b><br>"]
            for proto, cnt in list(protos.items())[:10]:
                pct = cnt / total * 100 if total else 0
                lines.append(f"&nbsp;&nbsp;• <b>{proto}</b>: {cnt:,} pkts ({pct:.1f}%)")
            return "<br>".join(lines)

        # ── retransmission ────────────────────────────────────────────────────
        if any_of("retransmit", "retrans"):
            ret = [f for f in findings if "retransmit" in f["msg"].lower()]
            base = _PROTO_HELP["retransmission"]
            if ret:
                top = Counter(f["msg"] for f in ret).most_common(3)
                lines = [base, f"<br><b>{len(ret):,} retransmission events</b>. Top:"]
                for msg, cnt in top:
                    lines.append(f"&nbsp;&nbsp;• {cnt:,}× {self._esc(msg)}")
                return "<br>".join(lines)
            return base

        # ── TCP RST ───────────────────────────────────────────────────────────
        if any_of("rst", "reset", "tcp rst"):
            rst = [f for f in findings
                   if "rst" in f["msg"].lower() or "reset" in f["msg"].lower()]
            base = _PROTO_HELP["tcp rst"]
            if rst:
                return f"{base}<br><br>Found <b>{len(rst):,}</b> RST events in this capture."
            return base

        # ── ARP ───────────────────────────────────────────────────────────────
        if "arp" in ql:
            arp_warns = [f for f in findings
                         if f["severity"] == "warn" and "arp" in f.get("protocol", "").lower()]
            base = _PROTO_HELP["arp"]
            if arp_warns:
                ips = Counter(
                    m.group(1)
                    for f in arp_warns
                    for m in [re.search(r'(\d+\.\d+\.\d+\.\d+)', f["msg"])]
                    if m
                ).most_common(5)
                lines = [base, "<br><b>Most-queried missing IPs:</b>"]
                for ip, cnt in ips:
                    lines.append(f"&nbsp;&nbsp;• {ip} queried {cnt:,}×")
                return "<br>".join(lines)
            return base

        # ── named protocol explanations ───────────────────────────────────────
        for key, explanation in _PROTO_HELP.items():
            if key in ql:
                return self._esc(explanation)

        # ── fallback ──────────────────────────────────────────────────────────
        return (
            "I'm not sure about that. Try asking:<br>"
            "&nbsp;&nbsp;• <i>errors</i> &nbsp;• <i>warnings</i> &nbsp;• <i>flows</i><br>"
            "&nbsp;&nbsp;• <i>protocols</i> &nbsp;• <i>summary</i> &nbsp;• <i>top flows</i><br>"
            "Or type <b>help</b> to see all options."
        )
