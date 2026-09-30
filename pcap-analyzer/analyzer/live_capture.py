"""Live packet capture engine with rule-based anomaly detection."""
from __future__ import annotations
import os
import time
import warnings
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import List

from PyQt6.QtCore import QThread, pyqtSignal

# ── scapy availability check ──────────────────────────────────────────────────
try:
    with warnings.catch_warnings():
        from cryptography.utils import CryptographyDeprecationWarning
        warnings.filterwarnings(
            "ignore",
            message=r"Diffie-Hellman over finite fields \(FFDH\) is deprecated.*",
            category=CryptographyDeprecationWarning,
        )
        from scapy.all import (
            AsyncSniffer, get_if_list, get_if_addr,
            IP, TCP, UDP, ARP, ICMP, Ether, wrpcap, Packet,
        )
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


# ── port to protocol mapping ──────────────────────────────────────────────────
_PORT_PROTO_MAP = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    502: "Modbus", 514: "Syslog", 1900: "SSDP", 5353: "mDNS", 5355: "LLMNR",
    47808: "BACnet", 102: "Siemens", 2404: "IEC", 34962: "EtherCAT",
}


def _identify_protocol(sport: int, dport: int, pkt_ip_proto: int = 0) -> str:
    """Identify protocol from ports and IP protocol number."""
    # Check common server ports (destination port is usually the service)
    for port in [dport, sport]:
        if port in _PORT_PROTO_MAP:
            return _PORT_PROTO_MAP[port]
    # Check if it's Modbus on any port (heuristic)
    if pkt_ip_proto == 17 and (sport == 502 or dport == 502):  # UDP proto 17
        return "Modbus"
    return "UDP"  # fallback


def get_interfaces() -> list[tuple[str, str]]:
    """Return list of (iface_name, ip_addr) pairs."""
    if not SCAPY_OK:
        return []
    result = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface) or ""
        except Exception:
            ip = ""
        result.append((iface, ip))
    return result


# ── anomaly rule ──────────────────────────────────────────────────────────────

RULE_TYPES = [
    ("tcp_rst",          "TCP RST detected"),
    ("ip_flood",         "IP flood (high packet rate from an IP)"),
    ("protocol_from_ip", "Specific protocol from a monitored IP"),
    ("arp_storm",        "ARP broadcast storm"),
    ("port_scan",        "Port scan (many ports from one IP)"),
    ("custom_pattern",   "Custom: any packet matching IP + Protocol"),
]


@dataclass
class AnomalyRule:
    name: str
    severity: str           # 'error' or 'warn'
    rule_type: str          # one of the RULE_TYPES keys
    ip: str = ""            # source IP filter (empty = any)
    protocol: str = ""      # protocol filter (empty = any)
    threshold: int = 50     # packets/connections threshold
    window: float = 1.0     # sliding time window (seconds)
    enabled: bool = True

    def describe(self) -> str:
        label = dict(RULE_TYPES).get(self.rule_type, self.rule_type)
        parts = [label]
        if self.ip:
            parts.append(f"IP={self.ip}")
        if self.protocol:
            parts.append(f"Proto={self.protocol}")
        if self.rule_type in ("ip_flood", "arp_storm", "port_scan"):
            parts.append(f">{self.threshold} in {self.window}s")
        return "  ·  ".join(parts)


# Default rules loaded when live capture starts
DEFAULT_RULES: list[AnomalyRule] = [
    AnomalyRule("TCP Reset", "error", "tcp_rst"),
    AnomalyRule("IP Flood", "error", "ip_flood", threshold=100, window=1.0),
    AnomalyRule("ARP Storm", "warn",  "arp_storm", threshold=1000, window=60.0),
    AnomalyRule("Port Scan", "warn",  "port_scan", threshold=20, window=2.0),
]


# ── live capture thread ───────────────────────────────────────────────────────

class LiveCapture(QThread):
    # dict with packet fields
    packet_received  = pyqtSignal(dict)
    # dict: {rule, severity, msg, packet_num, packet, context_before, context_after}
    anomaly_detected = pyqtSignal(dict)
    stats_updated    = pyqtSignal(dict)
    capture_error    = pyqtSignal(str)
    file_rotated     = pyqtSignal(str)   # emitted with saved filepath on each rotation

    CONTEXT_SIZE = 20

    def __init__(self, interface: str, rules: list[AnomalyRule],
                 rotation_dir: str = "", rotation_count: int = 0):
        super().__init__()
        self._iface          = interface
        self._rules          = [r for r in rules if r.enabled]
        self._sniffer        = None
        self._running        = False
        self._pkt_num        = 0
        self._ring: deque[dict] = deque(maxlen=self.CONTEXT_SIZE * 2 + 1)
        self._all_pkts: list[dict] = []
        self._pending: dict[int, dict] = {}
        self._ip_times: dict[str, list] = defaultdict(list)
        self._ip_ports: dict[str, set]  = defaultdict(set)
        self._stats = {
            "total": 0, "tcp": 0, "udp": 0, "arp": 0,
            "icmp": 0, "other": 0, "alerts": 0,
        }
        # file rotation
        self._rotation_dir   = rotation_dir
        self._rotation_count = rotation_count   # 0 = disabled
        self._rotation_buf: list = []            # raw scapy packets for current file
        self._rotation_file  = 0                 # file counter
        from datetime import datetime
        self._session_ts     = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── public ────────────────────────────────────────────────────────────────

    def run(self):
        if not SCAPY_OK:
            self.capture_error.emit(
                "Scapy is not installed. Run:  pip install scapy\n"
                "Also install Npcap (Windows) from https://npcap.com"
            )
            return
        self._running = True
        try:
            self._sniffer = AsyncSniffer(
                iface=self._iface,
                prn=self._process_packet,
                store=False,
            )
            self._sniffer.start()
            self._sniffer.join()          # blocks until stop() is called
        except Exception as e:
            self.capture_error.emit(str(e))

    def stop(self):
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        # flush any remaining packets to a final rotation file
        if self._rotation_count > 0 and self._rotation_buf:
            self._flush_rotation_file()

    def _flush_rotation_file(self):
        """Write buffered packets to a dated rotation file and clear buffer."""
        if not SCAPY_OK or not self._rotation_buf:
            return
        os.makedirs(self._rotation_dir, exist_ok=True)
        self._rotation_file += 1
        fname = f"capture_{self._session_ts}_{self._rotation_file:04d}.pcapng"
        path  = os.path.join(self._rotation_dir, fname)
        try:
            wrpcap(path, self._rotation_buf)
            self._rotation_buf = []
            self.file_rotated.emit(path)
        except Exception as e:
            self.capture_error.emit(f"Rotation save failed: {e}")

    def save_pcap(self, path: str):
        """Save all captured raw packets to a .pcap file."""
        if not SCAPY_OK or not self._all_pkts:
            return
        try:
            wrpcap(path, [p["_raw"] for p in self._all_pkts if "_raw" in p])
        except Exception as e:
            self.capture_error.emit(f"Save failed: {e}")

    # ── internal ──────────────────────────────────────────────────────────────

    def _process_packet(self, pkt):
        if not self._running:
            return
        self._pkt_num += 1
        info = self._extract(pkt, self._pkt_num)
        info["_raw"] = pkt
        self._ring.append(info)
        self._all_pkts.append(info)

        # file rotation
        if self._rotation_count > 0 and self._rotation_dir:
            self._rotation_buf.append(pkt)
            if len(self._rotation_buf) >= self._rotation_count:
                self._flush_rotation_file()

        # fill context for pending anomalies
        to_emit = []
        for num, ctx in list(self._pending.items()):
            ctx["after"].append(info)
            if len(ctx["after"]) >= self.CONTEXT_SIZE:
                to_emit.append(num)
        for num in to_emit:
            ctx = self._pending.pop(num)
            self.anomaly_detected.emit({**ctx["anomaly"],
                                        "context_before": ctx["before"],
                                        "context_after":  ctx["after"]})

        self._update_stats(info)
        self.packet_received.emit(info)

        # check rules
        anomaly = self._check_rules(pkt, info)
        if anomaly and self._pkt_num not in self._pending:
            self._stats["alerts"] += 1
            self._pending[self._pkt_num] = {
                "anomaly": {**anomaly, "packet_num": self._pkt_num, "packet": info},
                "before":  [p for p in self._ring][:-1][-self.CONTEXT_SIZE:],
                "after":   [],
            }

        if self._pkt_num % 100 == 0:
            self.stats_updated.emit(dict(self._stats))

    def _extract(self, pkt, num: int) -> dict:
        info: dict = {
            "num": num, "time": f"{pkt.time:.6f}",
            "src": "", "dst": "", "proto": "OTHER", "info": "",
            "len": len(pkt), "severity": "",
        }
        if IP in pkt:
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            if TCP in pkt:
                info["proto"] = "TCP"
                flags = []
                f = pkt[TCP].flags
                if f & 0x02: flags.append("SYN")
                if f & 0x10: flags.append("ACK")
                if f & 0x04: flags.append("RST")
                if f & 0x01: flags.append("FIN")
                if f & 0x08: flags.append("PSH")
                if f & 0x20: flags.append("URG")
                info["info"] = (
                    f"{pkt[TCP].sport}→{pkt[TCP].dport}"
                    + (f" [{','.join(flags)}]" if flags else "")
                )
                if f & 0x04:
                    info["severity"] = "error"
            elif UDP in pkt:
                proto = _identify_protocol(pkt[UDP].sport, pkt[UDP].dport, pkt[IP].proto)
                info["proto"] = proto
                info["info"] = f"{pkt[UDP].sport}→{pkt[UDP].dport}"
            elif ICMP in pkt:
                info["proto"] = "ICMP"
                _type_map = {0: "Echo Reply", 3: "Dest Unreachable",
                             8: "Echo Request", 11: "Time Exceeded"}
                icmp_type = pkt[ICMP].type
                info["info"] = _type_map.get(icmp_type, f"Type {icmp_type}")
                if icmp_type == 3:
                    info["severity"] = "error"
                elif icmp_type == 11:
                    info["severity"] = "warn"
            else:
                info["proto"] = pkt[IP].proto and f"IP/{pkt[IP].proto}" or "IP"
        elif ARP in pkt:
            info["proto"] = "ARP"
            info["src"]   = pkt[ARP].psrc
            info["dst"]   = pkt[ARP].pdst
            info["info"]  = "Who has?" if pkt[ARP].op == 1 else f"Reply: {pkt[ARP].psrc}"
        elif Ether in pkt:
            info["src"] = pkt[Ether].src
            info["dst"] = pkt[Ether].dst
        return info

    def _update_stats(self, info: dict):
        self._stats["total"] += 1
        p = info["proto"].lower()
        if p in self._stats:
            self._stats[p] += 1
        else:
            self._stats["other"] += 1

    def _check_rules(self, pkt, info: dict) -> dict | None:
        now = time.time()
        src = info["src"]

        for rule in self._rules:
            # ip filter
            if rule.ip and src != rule.ip:
                continue

            if rule.rule_type == "tcp_rst":
                if info["proto"] == "TCP" and "RST" in info["info"]:
                    return self._alert(rule, f"TCP RST  {src} → {info['dst']}  {info['info']}")

            elif rule.rule_type == "ip_flood":
                self._ip_times[src] = [
                    t for t in self._ip_times[src] if now - t < rule.window
                ]
                self._ip_times[src].append(now)
                if len(self._ip_times[src]) >= rule.threshold:
                    return self._alert(
                        rule,
                        f"IP Flood  {src} → {len(self._ip_times[src])} pkts "
                        f"in {rule.window}s"
                    )

            elif rule.rule_type == "arp_storm":
                if info["proto"] == "ARP":  # Any ARP packet, not just requests
                    key = "__arp__"
                    self._ip_times[key] = [
                        t for t in self._ip_times[key] if now - t < rule.window
                    ]
                    self._ip_times[key].append(now)
                    if len(self._ip_times[key]) >= rule.threshold:
                        return self._alert(
                            rule,
                            f"ARP Storm  {len(self._ip_times[key])} "
                            f"packets in {rule.window}s"
                        )

            elif rule.rule_type == "port_scan":
                if info["proto"] == "TCP" and TCP in pkt:
                    self._ip_ports[src].add(pkt[TCP].dport)
                    if len(self._ip_ports[src]) >= rule.threshold:
                        return self._alert(
                            rule,
                            f"Port Scan  {src} hit "
                            f"{len(self._ip_ports[src])} ports"
                        )

            elif rule.rule_type == "protocol_from_ip":
                if rule.protocol and info["proto"] != rule.protocol.upper():
                    continue
                return self._alert(rule, f"{info['proto']} from monitored IP {src}")

            elif rule.rule_type == "custom_pattern":
                if rule.protocol and info["proto"] != rule.protocol.upper():
                    continue
                return self._alert(rule, f"Custom match  {src} → {info['dst']}  {info['proto']}")

        return None

    @staticmethod
    def _alert(rule: AnomalyRule, msg: str) -> dict:
        return {"rule": rule.name, "severity": rule.severity, "msg": msg}
