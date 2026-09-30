"""Behavioral fingerprinting and similarity comparison between offline and live traffic."""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class BehaviorProfile:
    total_packets:      int   = 0
    top_src_ips:        list  = field(default_factory=list)   # [(ip, count)]
    top_dst_ips:        list  = field(default_factory=list)
    top_protocols:      list  = field(default_factory=list)   # [(proto, count)]
    top_ports:          list  = field(default_factory=list)   # [(port, count)]
    top_pairs:          list  = field(default_factory=list)   # [((src, dst), count)]
    error_types:        list  = field(default_factory=list)   # ["TCP RST", ...]
    error_count:        int   = 0
    warning_count:      int   = 0
    tcp_rst_rate:       float = 0.0   # RST events / total_packets
    arp_broadcast_rate: float = 0.0
    dominant_protocol:  str   = ""
    has_retransmission: bool  = False
    has_arp_storm:      bool  = False
    has_port_scan:      bool  = False


def from_report(report: dict) -> BehaviorProfile:
    """Build a BehaviorProfile from an offline analysis report dict."""
    findings  = report.get("findings", [])
    flows     = report.get("flows", [])
    protos    = report.get("protocol_summary", {})
    total     = report.get("total_packets", 1) or 1

    # IPs from flows
    src_ctr = Counter(f["src"].split(":")[0] for f in flows)
    dst_ctr = Counter(f["dst"].split(":")[0] for f in flows)
    pair_ctr = Counter((f["src"].split(":")[0], f["dst"].split(":")[0]) for f in flows)

    # error/warning classification
    errors   = [f for f in findings if f["severity"] == "error"]
    warnings = [f for f in findings if f["severity"] == "warn"]

    error_types = list({
        "TCP RST"        if "rst"             in f["msg"].lower() else
        "Retransmission" if "retransmit"      in f["msg"].lower() else
        "ARP Unanswered" if "arp"             in f["msg"].lower() else
        "Port Scan"      if "port scan"       in f["msg"].lower() else
        "IP Flood"       if "flood"           in f["msg"].lower() else
        f.get("protocol", "Unknown")
        for f in findings
    })

    rst_count = sum(1 for f in errors if "rst" in f["msg"].lower())
    arp_count = sum(1 for f in warnings if "arp" in f["msg"].lower())

    top_proto = max(protos, key=protos.get) if protos else ""

    # extract ports from flow src/dst  "ip:port"
    ports: list[int] = []
    for f in flows:
        for side in (f.get("src", ""), f.get("dst", "")):
            if ":" in side:
                try:
                    ports.append(int(side.split(":")[-1]))
                except ValueError:
                    pass

    return BehaviorProfile(
        total_packets      = total,
        top_src_ips        = src_ctr.most_common(10),
        top_dst_ips        = dst_ctr.most_common(10),
        top_protocols      = list(protos.items())[:10],
        top_ports          = Counter(ports).most_common(10),
        top_pairs          = pair_ctr.most_common(20),
        error_types        = error_types,
        error_count        = len(errors),
        warning_count      = len(warnings),
        tcp_rst_rate       = rst_count / total,
        arp_broadcast_rate = arp_count / total,
        dominant_protocol  = top_proto,
        has_retransmission = any("retransmit" in f["msg"].lower() for f in findings),
        has_arp_storm      = any("arp" in f["msg"].lower() for f in warnings),
        has_port_scan      = any("port scan" in f["msg"].lower() for f in findings),
    )


def from_live_stats(stats: dict, live_packets: list[dict]) -> BehaviorProfile:
    """Build a BehaviorProfile from accumulated live capture data."""
    total = max(stats.get("total", 1), 1)

    src_ctr   = Counter(p.get("src", "") for p in live_packets if p.get("src"))
    dst_ctr   = Counter(p.get("dst", "") for p in live_packets if p.get("dst"))
    pair_ctr  = Counter((p.get("src", ""), p.get("dst", "")) for p in live_packets
                        if p.get("src") and p.get("dst"))
    proto_ctr = Counter(p.get("proto", "") for p in live_packets if p.get("proto"))

    ports: list[int] = []
    for p in live_packets:
        info = p.get("info", "")
        if "→" in info:
            try:
                ports.append(int(info.split("→")[1].split()[0]))
            except (ValueError, IndexError):
                pass

    rst_count = sum(1 for p in live_packets
                    if p.get("proto") == "TCP" and "RST" in p.get("info", ""))
    arp_count = sum(1 for p in live_packets if p.get("proto") == "ARP")

    error_types = []
    if rst_count:        error_types.append("TCP RST")
    if arp_count > 30:   error_types.append("ARP Unanswered")

    top_proto = proto_ctr.most_common(1)[0][0] if proto_ctr else ""

    return BehaviorProfile(
        total_packets      = total,
        top_src_ips        = src_ctr.most_common(10),
        top_dst_ips        = dst_ctr.most_common(10),
        top_protocols      = proto_ctr.most_common(10),
        top_ports          = Counter(ports).most_common(10),
        top_pairs          = pair_ctr.most_common(20),
        error_types        = error_types,
        error_count        = rst_count,
        warning_count      = arp_count,
        tcp_rst_rate       = rst_count / total,
        arp_broadcast_rate = arp_count / total,
        dominant_protocol  = top_proto,
        has_retransmission = any("retransmit" in p.get("info","").lower() for p in live_packets),
        has_arp_storm      = arp_count > 30,
        has_port_scan      = False,
    )


# ── similarity scoring ────────────────────────────────────────────────────────

@dataclass
class SimilarityResult:
    overall:       float
    categories:    dict[str, float]
    matches:       list[str]          # simple strings (legacy)
    rich_matches:  list[dict]         # structured: {title, offline, live, icon, type}
    level:         str

    @property
    def level_color(self) -> str:
        return {"low": "#64748b", "medium": "#fbbf24",
                "high": "#fb923c", "critical": "#f87171"}.get(self.level, "#64748b")

    @property
    def level_icon(self) -> str:
        return {"low": "🟢", "medium": "🟡",
                "high": "🟠", "critical": "🔴"}.get(self.level, "⚪")


def _jaccard(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    return len(set_a & set_b) / len(union) if union else 0.0


def _rate_sim(a: float, b: float) -> float:
    """1.0 if equal rates, 0.0 if one is 10× the other."""
    if a == 0 and b == 0:
        return 1.0
    if a == 0 or b == 0:
        return 0.0
    ratio = min(a, b) / max(a, b)
    return ratio  # 1.0 = identical rate, 0.1 = 10× different


def compare(offline: BehaviorProfile, live: BehaviorProfile) -> SimilarityResult:
    cats: dict[str, float] = {}
    matches: list[str] = []
    rich: list[dict] = []

    def _off_counts(items): return {k: v for k, v in items}

    # 1. Protocol mix
    off_p = {p for p, _ in offline.top_protocols}
    liv_p = {p for p, _ in live.top_protocols}
    cats["Protocol Mix"] = _jaccard(off_p, liv_p)
    common_p = off_p & liv_p
    if offline.dominant_protocol == live.dominant_protocol and offline.dominant_protocol:
        matches.append(f"Same dominant protocol: {offline.dominant_protocol}")
    if common_p:
        off_pc = _off_counts(offline.top_protocols)
        liv_pc = _off_counts(live.top_protocols)
        proto_filter = " || ".join(p.lower() for p in sorted(common_p))
        rich.append({
            "icon": "📡", "title": "Shared Protocols",
            "offline": [f"{p}  —  {off_pc.get(p,0):,} packets" for p in sorted(common_p)],
            "live":    [f"{p}  —  {liv_pc.get(p,0):,} packets" for p in sorted(common_p)],
            "detail":  f"{len(common_p)} protocol(s) in common: {', '.join(sorted(common_p))}",
            "filter":  proto_filter,
        })

    # 2. Source IP overlap
    off_src = {ip for ip, _ in offline.top_src_ips}
    liv_src = {ip for ip, _ in live.top_src_ips}
    cats["Source IPs"] = _jaccard(off_src, liv_src)
    common_src = off_src & liv_src
    if common_src:
        matches.append(f"Common source IPs: {', '.join(list(common_src)[:4])}")
        off_sc = _off_counts(offline.top_src_ips)
        liv_sc = _off_counts(live.top_src_ips)
        ip_filter = " || ".join(f"ip.src == {ip} || ip.dst == {ip}" for ip in sorted(common_src)[:3])
        rich.append({
            "icon": "🖥", "title": "Same Source IPs Seen",
            "offline": [f"{ip}  —  {off_sc.get(ip,0):,} pkts" for ip in sorted(common_src)[:6]],
            "live":    [f"{ip}  —  {liv_sc.get(ip,0):,} pkts" for ip in sorted(common_src)[:6]],
            "detail":  f"{len(common_src)} IP(s) active in both captures",
            "filter":  ip_filter,
        })

    # 3. Destination IP overlap
    off_dst = {ip for ip, _ in offline.top_dst_ips}
    liv_dst = {ip for ip, _ in live.top_dst_ips}
    cats["Destination IPs"] = _jaccard(off_dst, liv_dst)
    common_dst = off_dst & liv_dst
    if common_dst:
        matches.append(f"Common dest IPs: {', '.join(list(common_dst)[:4])}")
        off_dc = _off_counts(offline.top_dst_ips)
        liv_dc = _off_counts(live.top_dst_ips)
        dst_filter = " || ".join(f"ip.dst == {ip}" for ip in sorted(common_dst)[:3])
        rich.append({
            "icon": "🎯", "title": "Same Destination IPs",
            "offline": [f"{ip}  —  {off_dc.get(ip,0):,} pkts" for ip in sorted(common_dst)[:6]],
            "live":    [f"{ip}  —  {liv_dc.get(ip,0):,} pkts" for ip in sorted(common_dst)[:6]],
            "detail":  f"{len(common_dst)} destination IP(s) in common",
            "filter":  dst_filter,
        })

    # 4. Port overlap
    off_ports = {p for p, _ in offline.top_ports}
    liv_ports = {p for p, _ in live.top_ports}
    cats["Port Usage"] = _jaccard(off_ports, liv_ports)
    common_ports = off_ports & liv_ports
    if common_ports:
        matches.append(f"Same ports active: {', '.join(str(p) for p in list(common_ports)[:6])}")
        off_prc = _off_counts(offline.top_ports)
        liv_prc = _off_counts(live.top_ports)
        port_filter = " || ".join(f"tcp.port == {p} || udp.port == {p}" for p in sorted(common_ports)[:3])
        rich.append({
            "icon": "🔌", "title": "Shared Ports",
            "offline": [f"Port {p}  —  {off_prc.get(p,0):,} times" for p in sorted(common_ports)[:6]],
            "live":    [f"Port {p}  —  {liv_prc.get(p,0):,} times" for p in sorted(common_ports)[:6]],
            "detail":  f"{len(common_ports)} port(s) active in both captures",
            "filter":  port_filter,
        })

    # 4b. Exact source-to-destination pair overlap
    off_pairs = {pair for pair, _ in offline.top_pairs}
    liv_pairs = {pair for pair, _ in live.top_pairs}
    cats["Source → Destination"] = _jaccard(off_pairs, liv_pairs)
    common_pairs = off_pairs & liv_pairs
    if common_pairs:
        off_pair_counts = _off_counts(offline.top_pairs)
        liv_pair_counts = _off_counts(live.top_pairs)
        rich.append({
            "icon": "↔", "title": "Same Source → Destination",
            "offline": [f"{src} → {dst}  —  {off_pair_counts.get((src, dst), 0):,} flows"
                        for src, dst in sorted(common_pairs)[:6]],
            "live": [f"{src} → {dst}  —  {liv_pair_counts.get((src, dst), 0):,} flows"
                     for src, dst in sorted(common_pairs)[:6]],
            "detail": f"{len(common_pairs)} exact source-to-destination pair(s) in common",
            "filter": "",
        })

    # 5. Error pattern overlap
    off_err = set(offline.error_types)
    liv_err = set(live.error_types)
    cats["Error Patterns"] = _jaccard(off_err, liv_err)
    common_err = off_err & liv_err
    if common_err:
        matches.append(f"Same error types: {', '.join(common_err)}")
        err_filter = " || ".join(
            "tcp.flags.reset==1" if e == "TCP RST" else
            "arp.opcode==1" if "ARP" in e else
            "tcp.analysis.retransmission" if "Retransmit" in e else "tcp"
            for e in common_err
        )
        rich.append({
            "icon": "🔴", "title": "Matching Error Patterns",
            "offline": list(common_err),
            "live":    list(common_err),
            "detail":  f"Both captures show: {', '.join(common_err)}",
            "filter":  err_filter,
        })

    # 6. TCP RST rate
    cats["TCP RST Rate"] = _rate_sim(offline.tcp_rst_rate, live.tcp_rst_rate)
    if offline.tcp_rst_rate > 0 and live.tcp_rst_rate > 0:
        off_pct = offline.tcp_rst_rate * 100
        liv_pct = live.tcp_rst_rate * 100
        matches.append(f"TCP RST in both (offline {off_pct:.2f}% vs live {liv_pct:.2f}%)")
        rich.append({
            "icon": "⚡", "title": "TCP RST Pattern",
            "offline": [f"RST rate: {off_pct:.2f}% of all packets"],
            "live":    [f"RST rate: {liv_pct:.2f}% of all packets"],
            "detail":  "Connections being forcibly reset in both captures",
            "filter":  "tcp.flags.reset==1",
        })

    # 7. ARP
    cats["ARP Behaviour"] = 1.0 if offline.has_arp_storm == live.has_arp_storm else 0.3
    if offline.has_arp_storm and live.has_arp_storm:
        matches.append("ARP broadcast storm in both")
        rich.append({
            "icon": "📢", "title": "ARP Broadcast Storm",
            "offline": ["High ARP broadcast traffic detected"],
            "live":    ["High ARP broadcast traffic detected"],
            "detail":  "Both captures show excessive ARP requests — device(s) unreachable",
            "filter":  "arp.opcode==1",
        })

    # 8. Retransmissions
    cats["Retransmissions"] = 1.0 if offline.has_retransmission == live.has_retransmission else 0.2
    if offline.has_retransmission and live.has_retransmission:
        matches.append("TCP retransmissions in both")
        rich.append({
            "icon": "🔁", "title": "TCP Retransmissions",
            "offline": ["Retransmission events detected"],
            "live":    ["Retransmission events detected"],
            "detail":  "Packet loss causing retransmissions in both captures",
            "filter":  "tcp.analysis.retransmission",
        })

    overall = sum(cats.values()) / len(cats) if cats else 0.0
    level = "critical" if overall >= 0.75 else "high" if overall >= 0.50 else "medium" if overall >= 0.25 else "low"

    return SimilarityResult(
        overall=overall, categories=cats,
        matches=matches, rich_matches=rich, level=level,
    )
