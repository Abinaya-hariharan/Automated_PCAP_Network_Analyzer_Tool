"""Packet Inspector — click any finding or flow row to see full details."""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

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


class PacketInspector(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    # ── public ────────────────────────────────────────────────────────────────

    def inspect_finding(self, finding: dict):
        """Display a finding dict in the inspector."""
        sev   = finding.get("severity", "info")
        color = _SEV_FG.get(sev, _TEXT)
        proto = finding.get("protocol", "—")
        msg   = finding.get("msg", "")

        self._title.setText(
            f"<span style='color:{color};font-weight:800;'>"
            f"{'🔴' if sev=='error' else '🟠' if sev=='warn' else 'ℹ'} "
            f"{sev.upper()} &nbsp;</span>"
            f"<span style='color:{_SUBTEXT};font-size:12px;'>[{proto}]</span>"
        )

        rows = [
            ("Severity",  sev.upper(),  color),
            ("Protocol",  proto,        _ACCENT2),
            ("Message",   msg,          _TEXT),
            ("Category",  self._categorize(finding), _SUBTEXT),
            ("Impact",    self._impact(finding),     _SUBTEXT),
            ("Action",    self._action(finding),     _GREEN),
        ]
        self._populate_fields(rows)
        self._detail_text.setHtml(self._finding_detail_html(finding))

    def inspect_flow(self, flow: dict):
        """Display a flow dict in the inspector."""
        self._title.setText(
            f"<span style='color:{_ACCENT2};font-weight:800;'>📡 FLOW</span>"
        )
        src   = flow.get("src", "—")
        dst   = flow.get("dst", "—")
        proto = flow.get("protocol", "—")
        pkts  = flow.get("packets", 0)

        rows = [
            ("Source",       src,   _TEXT),
            ("Destination",  dst,   _TEXT),
            ("Protocol",     proto, _ACCENT2),
            ("Packets",      str(pkts), _GREEN),
            ("Direction",    "Bidirectional ↔", _SUBTEXT),
            ("Port (src)",   src.split(":")[-1] if ":" in src else "—", _SUBTEXT),
            ("Port (dst)",   dst.split(":")[-1] if ":" in dst else "—", _SUBTEXT),
            ("Service",      self._port_service(dst), _ACCENT2),
        ]
        self._populate_fields(rows)
        # Use plain text for flows (much faster than HTML rendering)
        self._detail_text.setPlainText(self._flow_detail_text(flow))

    def clear(self):
        self._title.setText("Click any row in Findings or Flows to inspect")
        self._fields_table.setRowCount(0)
        self._detail_text.clear()

    # ── UI build ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(10)

        # header
        self._title = QLabel("Click any row in Findings or Flows to inspect")
        self._title.setTextFormat(Qt.TextFormat.RichText)
        self._title.setStyleSheet(
            f"color:{_SUBTEXT};font-size:13px;font-weight:600;"
            f"border-bottom:1px solid {_BORDER};padding-bottom:8px;"
        )
        root.addWidget(self._title)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{_BORDER};width:2px;}}")

        # left: field table
        self._fields_table = QTableWidget(0, 2)
        self._fields_table.setHorizontalHeaderLabels(["Field", "Value"])
        self._fields_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._fields_table.horizontalHeader().resizeSection(0, 130)
        self._fields_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._fields_table.verticalHeader().setVisible(False)
        self._fields_table.setShowGrid(False)
        self._fields_table.setAlternatingRowColors(True)
        self._fields_table.setStyleSheet(
            f"QTableWidget{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;color:{_TEXT};}}"
            f"QTableWidget::item{{padding:8px 10px;}}"
            f"QHeaderView::section{{background:{_BG};color:{_SUBTEXT};"
            f"padding:7px 10px;border:none;border-bottom:1px solid {_BORDER};"
            f"font-weight:700;font-size:11px;}}"
        )

        # right: detailed explanation
        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setStyleSheet(
            f"QTextEdit{{background:{_SURFACE};border:1px solid {_BORDER};"
            f"border-radius:8px;padding:12px;font-size:12px;color:{_TEXT};}}"
        )
        self._detail_text.setPlaceholderText("Detailed explanation will appear here…")

        splitter.addWidget(self._fields_table)
        splitter.addWidget(self._detail_text)
        splitter.setSizes([350, 650])
        root.addWidget(splitter, 1)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _populate_fields(self, rows: list[tuple[str, str, str]]):
        t = self._fields_table
        t.setRowCount(len(rows))
        for i, (field, value, color) in enumerate(rows):
            f_item = QTableWidgetItem(field)
            f_item.setForeground(QColor(_SUBTEXT))
            v_item = QTableWidgetItem(value)
            v_item.setForeground(QColor(color))
            t.setItem(i, 0, f_item)
            t.setItem(i, 1, v_item)
            t.setRowHeight(i, 32)

    def _categorize(self, f: dict) -> str:
        msg = f.get("msg", "").lower()
        if "rst"         in msg: return "Connection Reset"
        if "retransmit"  in msg: return "Reliability Issue"
        if "arp"         in msg: return "Network Discovery"
        if "flood"       in msg: return "Denial of Service Pattern"
        if "port scan"   in msg: return "Reconnaissance"
        return f.get("protocol", "Network")

    def _impact(self, f: dict) -> str:
        sev = f.get("severity", "info")
        msg = f.get("msg", "").lower()
        if sev == "error":
            if "rst"  in msg: return "Connection dropped — application may retry or fail"
            if "flood" in msg: return "Network overload — other devices may be affected"
            return "Service disruption possible"
        if sev == "warn":
            if "arp"  in msg: return "Unreachable devices — routing may be incomplete"
            if "retransmit" in msg: return "Packet loss — throughput degraded"
            return "Potential performance degradation"
        return "Informational — no immediate impact"

    def _action(self, f: dict) -> str:
        msg = f.get("msg", "").lower()
        if "rst"         in msg: return "Investigate server/firewall logs for refused connections"
        if "retransmit"  in msg: return "Check network congestion or receiver buffer limits"
        if "arp"         in msg: return "Verify target IP is online and subnet mask is correct"
        if "flood"       in msg: return "Apply rate limiting or firewall rule on source IP"
        if "port scan"   in msg: return "Block source IP and review firewall policy"
        return "Monitor and investigate if pattern persists"

    def _port_service(self, dst: str) -> str:
        port_map = {
            "502": "Modbus TCP — Industrial PLC",
            "80":  "HTTP — Web",
            "443": "HTTPS — Secure Web",
            "137": "NetBIOS Name Service",
            "138": "NetBIOS Datagram",
            "1900": "SSDP / UPnP Discovery",
            "5355": "LLMNR — Local Name Resolution",
            "47808": "BACnet — Building Automation",
            "53":  "DNS",
            "22":  "SSH",
            "23":  "Telnet",
            "161": "SNMP",
        }
        if ":" in dst:
            port = dst.split(":")[-1]
            return port_map.get(port, f"Port {port}")
        return "—"

    def _finding_detail_html(self, f: dict) -> str:
        sev   = f.get("severity", "info")
        color = _SEV_FG.get(sev, _TEXT)
        msg   = f.get("msg", "")
        proto = f.get("protocol", "")

        explanations = {
            "TCP RST": (
                "<b>TCP RST (Reset)</b> means a connection was abruptly terminated by one side.<br><br>"
                "<b>Likely causes:</b><br>"
                "• Server refused the connection (port closed)<br>"
                "• Firewall dropped the session<br>"
                "• Application crashed mid-session<br>"
                "• Remote device went offline<br><br>"
                "<b>What to check:</b><br>"
                "• Server logs around the same timestamp<br>"
                "• Firewall rules for this IP/port<br>"
                "• Whether the service is running"
            ),
            "Retransmission": (
                "<b>TCP Retransmission</b> means a packet was resent because no ACK was received.<br><br>"
                "<b>Likely causes:</b><br>"
                "• Packet loss on the network<br>"
                "• Receiver buffer full<br>"
                "• High network latency<br><br>"
                "<b>What to check:</b><br>"
                "• Cable/switch quality<br>"
                "• Network utilization at that time<br>"
                "• Receiver CPU/memory load"
            ),
            "ARP": (
                "<b>ARP Unanswered</b> means a device broadcast 'Who has IP X?' and got no reply.<br><br>"
                "<b>Likely causes:</b><br>"
                "• Target device is offline<br>"
                "• Wrong subnet mask configured<br>"
                "• IP address not assigned to any device<br><br>"
                "<b>What to check:</b><br>"
                "• Is the target IP actually online?<br>"
                "• Is the subnet mask correct on the sender?"
            ),
        }

        # pick best explanation
        body = ""
        for key, expl in explanations.items():
            if key.lower() in msg.lower() or key.lower() in proto.lower():
                body = expl
                break
        if not body:
            body = f"<b>Details:</b><br>{msg}<br><br>Protocol: {proto}"

        return (
            f'<body style="background:{_SURFACE};font-family:Segoe UI;'
            f'font-size:12px;color:{_TEXT};">'
            f'<p style="color:{color};font-weight:700;margin-bottom:8px;">'
            f'{msg}</p>'
            f'{body}</body>'
        )

    def _flow_detail_html(self, f: dict) -> str:
        src   = f.get("src", "—")
        dst   = f.get("dst", "—")
        proto = f.get("protocol", "—")
        pkts  = f.get("packets", 0)
        svc   = self._port_service(dst)

        proto_desc = {
            "TCP":    "Transmission Control Protocol — reliable, ordered delivery",
            "UDP":    "User Datagram Protocol — fast, connectionless",
            "ARP":    "Address Resolution Protocol — maps IPs to MAC addresses",
            "MODBUS": "Modbus TCP — industrial device register read/write on port 502",
            "ICMP":   "Internet Control Message Protocol — ping and error messages",
        }

        return (
            f'<body style="background:{_SURFACE};font-family:Segoe UI;'
            f'font-size:12px;color:{_TEXT};">'
            f'<p style="color:{_ACCENT2};font-weight:700;margin-bottom:10px;">'
            f'{src}  →  {dst}</p>'
            f'<p><b>Protocol:</b> {proto} — '
            f'{proto_desc.get(proto, "Network protocol")}</p>'
            f'<p><b>Packets exchanged:</b> {pkts:,}</p>'
            f'<p><b>Service on destination:</b> {svc}</p>'
            f'<p style="margin-top:10px;color:{_SUBTEXT};">'
            f'This flow represents all packets between these two endpoints '
            f'on this protocol/port combination.</p>'
            f'</body>'
        )

    def _flow_detail_text(self, f: dict) -> str:
        """Plain text version of flow details (much faster than HTML)."""
        src   = f.get("src", "—")
        dst   = f.get("dst", "—")
        proto = f.get("protocol", "—")
        pkts  = f.get("packets", 0)
        svc   = self._port_service(dst)

        proto_desc = {
            "TCP":    "Transmission Control Protocol — reliable, ordered delivery",
            "UDP":    "User Datagram Protocol — fast, connectionless",
            "ARP":    "Address Resolution Protocol — maps IPs to MAC addresses",
            "MODBUS": "Modbus TCP — industrial device register read/write on port 502",
            "ICMP":   "Internet Control Message Protocol — ping and error messages",
        }

        return (
            f"{src}  →  {dst}\n\n"
            f"Protocol: {proto}\n"
            f"{proto_desc.get(proto, 'Network protocol')}\n\n"
            f"Packets exchanged: {pkts:,}\n"
            f"Service on destination: {svc}\n\n"
            f"This flow represents all packets between these two endpoints "
            f"on this protocol/port combination."
        )
