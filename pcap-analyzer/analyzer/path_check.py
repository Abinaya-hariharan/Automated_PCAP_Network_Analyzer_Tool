from __future__ import annotations

import os
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

from analyzer.capture import tshark_available_fields, tshark_fields


@dataclass(frozen=True)
class IssueType:
    key: str
    label: str
    severity: str


ISSUE_TYPES = (
    IssueType("tcp_reliability", "TCP retransmission, lost segment, duplicate ACK", "warning"),
    IssueType("tcp_reset", "TCP connection reset", "high"),
    IssueType("tcp_zero_window", "TCP zero window / receiver saturation", "high"),
    IssueType("icmp_failure", "ICMP unreachable or time exceeded", "high"),
    IssueType("http_error", "HTTP 4xx / 5xx response", "high"),
    IssueType("dns_failure", "DNS failure response", "medium"),
    IssueType("tls_alert", "TLS alert or deprecated TLS", "high"),
    IssueType("industrial_error", "Industrial protocol error or exception", "high"),
    IssueType("malformed_expert", "Malformed packet or Wireshark expert error", "high"),
    IssueType("request_flood", "High-rate request / packet flood", "critical"),
    IssueType("large_response", "Large packet / response amplification", "high"),
    IssueType("communication_gap", "Communication silence gap", "high"),
)

PROTOCOL_TYPES = (
    ("bacnet", "BACnet"),
    ("profinet", "PROFINET"),
    ("modbus", "Modbus"),
    ("ethernet_ip", "EtherNet/IP"),
)

_TLS_ALERT_LEVELS = {"1": "warning", "2": "fatal"}
_TLS_ALERT_DESCRIPTIONS = {
    "0": "close_notify",
    "10": "unexpected_message",
    "20": "bad_record_mac",
    "40": "handshake_failure",
    "42": "bad_certificate",
    "44": "certificate_revoked",
    "45": "certificate_expired",
    "46": "certificate_unknown",
    "47": "illegal_parameter",
    "48": "unknown_ca",
    "51": "decrypt_error",
    "70": "protocol_version",
    "80": "internal_error",
    "112": "unrecognized_name",
}

_FIELDS = [
    "frame.number", "frame.time_relative", "frame.len", "frame.protocols", "_ws.col.info",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission", "tcp.analysis.lost_segment",
    "tcp.analysis.duplicate_ack", "tcp.analysis.zero_window", "tcp.flags.reset",
    "icmp.type", "icmpv6.type", "http.response.code", "dns.flags.response", "dns.flags.rcode",
    "tls.alert_message", "tls.alert_message.level", "tls.alert_message.desc",
    "tls.handshake.version", "bacapp.type",
    "modbus.exception_code", "cip.genstat", "pn_io.status", "mqtt.reason_code",
    "ecat.alstatuscode", "_ws.expert.message", "_ws.expert.severity", "_ws.malformed",
]


_FIELD_GROUPS = {
    "tcp_reliability": (
        "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission", "tcp.analysis.lost_segment",
        "tcp.analysis.duplicate_ack",
    ),
    "tcp_reset": ("tcp.flags.reset",),
    "tcp_zero_window": ("tcp.analysis.zero_window",),
    "icmp_failure": ("icmp.type",),
    "http_error": ("http.response.code",),
    "dns_failure": ("dns.flags.response", "dns.flags.rcode"),
    "tls_alert": (
        "tls.alert_message", "tls.alert_message.level", "tls.alert_message.desc",
        "tls.handshake.version",
    ),
    "industrial_error": (
        "bacapp.type", "modbus.exception_code", "cip.genstat", "pn_io.status",
        "mqtt.reason_code", "ecat.alstatuscode",
    ),
    "malformed_expert": ("_ws.expert.message", "_ws.expert.severity", "_ws.malformed"),
}

_PROTOCOL_FILTERS = {
    "bacnet": '(frame.protocols contains "bacnet" || udp.port == 47808)',
    "profinet": '(frame.protocols contains "pn_io" || frame.protocols contains "pn_rt" || frame.protocols contains "pn_dcp")',
    "modbus": '(frame.protocols contains "modbus" || tcp.port == 502)',
    "ethernet_ip": '(frame.protocols contains "enip" || tcp.port == 44818 || udp.port == 2222)',
}

_PROTOCOL_FIELD_GROUP = {
    "bacnet": ("bacapp.type",),
    "profinet": ("pn_io.status",),
    "modbus": ("modbus.exception_code",),
    "ethernet_ip": ("cip.genstat",),
}


def _text(value: str | None) -> str:
    return (value or "").strip()


def _selected_fields(selected: set[str], available: frozenset[str]) -> list[str]:
    needed = {
        "frame.number", "frame.time_relative", "frame.len", "frame.protocols",
        "_ws.col.info",
    }
    for key in selected:
        needed.update(_FIELD_GROUPS.get(key, ()))
    return [field for field in _FIELDS if field in available and field in needed]


def _issue_for_row(row: dict[str, str], selected: set[str]) -> list[tuple[str, str]]:
    issues: list[tuple[str, str]] = []
    if "tcp_reliability" in selected and any(_text(row.get(f)) for f in _FIELD_GROUPS["tcp_reliability"]):
        issues.append(("tcp_reliability", "TCP reliability warning"))
    if "tcp_reset" in selected and _text(row.get("tcp.flags.reset")) in ("1", "true"):
        issues.append(("tcp_reset", "TCP connection reset"))
    if "tcp_zero_window" in selected and _text(row.get("tcp.analysis.zero_window")):
        issues.append(("tcp_zero_window", "TCP zero window"))
    if "icmp_failure" in selected and _text(row.get("icmp.type")) in ("3", "11"):
        issues.append(("icmp_failure", f"ICMP failure type {_text(row.get('icmp.type'))}"))
    if "http_error" in selected and _text(row.get("http.response.code")).startswith(("4", "5")):
        issues.append(("http_error", f"HTTP {_text(row.get('http.response.code'))}"))
    if "dns_failure" in selected and _text(row.get("dns.flags.response")) == "1" and _text(row.get("dns.flags.rcode")) not in ("", "0"):
        issues.append(("dns_failure", f"DNS failure rcode {_text(row.get('dns.flags.rcode'))}"))
    if "tls_alert" in selected and (_text(row.get("tls.alert_message")) or _text(row.get("tls.handshake.version")) in ("0x0301", "0x0302")):
        level = _text(row.get("tls.alert_message.level"))
        description = _text(row.get("tls.alert_message.desc"))
        detail = "TLS alert"
        if level:
            detail += f" level {_TLS_ALERT_LEVELS.get(level, level)}"
        if description:
            detail += f", description {_TLS_ALERT_DESCRIPTIONS.get(description, description)}"
        if not _text(row.get("tls.alert_message")):
            detail = f"Deprecated TLS {row.get('tls.handshake.version')}"
        issues.append(("tls_alert", detail))
    if "industrial_error" in selected:
        industrial_fields = ("bacapp.type", "modbus.exception_code", "cip.genstat", "pn_io.status", "mqtt.reason_code", "ecat.alstatuscode")
        if any(_text(row.get(field)) for field in industrial_fields):
            issues.append(("industrial_error", "Industrial protocol error/exception field present"))
    if "malformed_expert" in selected and any(_text(row.get(field)) for field in ("_ws.expert.message", "_ws.expert.severity", "_ws.malformed")):
        issues.append(("malformed_expert", _text(row.get("_ws.expert.message")) or "Malformed/expert diagnostic"))
    return issues


def check_path(
    pcap_path: str,
    source_ip: str,
    destination_ip: str,
    source_mac: str,
    destination_mac: str,
    selected: set[str],
    progress: Callable[[str], None] | None = None,
    protocols: set[str] | None = None,
    check_ping: bool = False,
    check_response: bool = False,
    address_family: str = "all",
) -> dict:
    protocols = protocols or set()
    if not selected and not check_ping and not check_response and not protocols:
        raise ValueError("Select at least one issue type, protocol, Ping, or Missing response check")
    if os.path.isdir(pcap_path):
        capture_files = sorted(
            os.path.join(root, name)
            for root, _, names in os.walk(pcap_path)
            for name in names
            if os.path.splitext(name)[1].lower() in (".pcap", ".pcapng")
        )
        all_events: list[dict] = []
        all_summary: dict[str, dict] = {}
        total_packets = 0
        available_fields: set[str] = set()
        max_workers = min(8, max(2, len(capture_files)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    check_path,
                    file_path, source_ip, destination_ip, source_mac, destination_mac,
                    selected, None, protocols, check_ping, check_response, address_family,
                ): (file_number, file_path)
                for file_number, file_path in enumerate(capture_files, 1)
            }
            completed = 0
            results = {}
            for future in as_completed(futures):
                file_number, file_path = futures[future]
                results[file_number] = (file_path, future.result())
                completed += 1
                if progress:
                    progress(
                        f"Completed file {completed} of {len(capture_files)}: "
                        f"{os.path.basename(file_path)}"
                    )

        for file_number in range(1, len(capture_files) + 1):
            file_path, result = results[file_number]
            total_packets += result["packet_count"]
            available_fields.update(result["available_fields"])
            for event in result["events"]:
                all_events.append({
                    **event,
                    "file_name": os.path.basename(file_path),
                    "file_path": file_path,
                    "file_number": file_number,
                })
            for item in result["summary"]:
                current = all_summary.setdefault(item["key"], {**item, "count": 0, "detected": False})
                current["count"] += item["count"]
                current["detected"] = current["detected"] or item["detected"]
        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_mac": source_mac,
            "destination_mac": destination_mac,
            "packet_count": total_packets,
            "summary": list(all_summary.values()),
            "events": all_events,
            "protocols": sorted(protocols),
            "check_ping": check_ping,
            "check_response": check_response,
            "available_fields": sorted(available_fields),
            "file_count": len(capture_files),
        }
    if progress:
        progress("Reading packets for the selected IP path")
    available = tshark_available_fields()
    fields = _selected_fields(selected, available)
    direction = ""
    if source_ip:
        direction += f"ip.src == {source_ip}"
    if destination_ip:
        direction += (" && " if direction else "") + f"ip.dst == {destination_ip}"
    if source_mac:
        direction += (" && " if direction else "") + f"eth.src == {source_mac}"
    if destination_mac:
        direction += (" && " if direction else "") + f"eth.dst == {destination_mac}"
    family_filter = {"ipv4": "ip", "ipv6": "ipv6"}.get(address_family)
    query_parts = [part for part in (family_filter, direction) if part]
    rows = tshark_fields(pcap_path, " && ".join(query_parts) or None, fields)

    events: list[dict] = []
    times: list[float] = []
    sizes: list[int] = []
    rate_window: deque[float] = deque()
    flood_count = 0
    large_count = 0
    gap_events: list[dict] = []
    response_events: list[dict] = []
    previous_time: float | None = None
    field_index = {field: index for index, field in enumerate(fields)}

    for raw in rows:
        row = {field: raw[index] if index < len(raw) else "" for field, index in field_index.items()}
        packet = _text(row.get("frame.number"))
        timestamp = None
        try:
            timestamp = float(_text(row.get("frame.time_relative")))
        except ValueError:
            pass
        if timestamp is not None:
            times.append(timestamp)
            if previous_time is not None and timestamp - previous_time >= 0.5 and "communication_gap" in selected:
                gap_events.append({"packet": packet, "time": timestamp, "detail": f"Gap of {timestamp - previous_time:.3f}s"})
            previous_time = timestamp
            rate_window.append(timestamp)
            while rate_window and timestamp - rate_window[0] > 0.1:
                rate_window.popleft()
            if len(rate_window) >= 100 and "request_flood" in selected:
                flood_count += 1
        try:
            size = int(_text(row.get("frame.len")) or 0)
        except ValueError:
            size = 0
        sizes.append(size)
        if size >= 1400 and "large_response" in selected:
            large_count += 1
        for key, detail in _issue_for_row(row, selected):
            events.append({"issue": key, "packet": packet, "time": timestamp, "detail": detail})

    if protocols or check_ping:
        response_events = _find_missing_responses(
            pcap_path, source_ip, destination_ip, source_mac, destination_mac,
            protocols, check_ping, check_response, available,
            address_family,
        )
        events.extend(response_events)

    if "request_flood" in selected and flood_count:
        events.append({"issue": "request_flood", "packet": "", "time": None, "detail": f"At least {flood_count} 100ms windows contained 100+ packets"})
    if "large_response" in selected and large_count:
        events.append({"issue": "large_response", "packet": "", "time": None, "detail": f"{large_count} packets were at least 1400 bytes"})
    for event in gap_events:
        events.append({"issue": "communication_gap", **event})

    labels = {item.key: item for item in ISSUE_TYPES}
    summary = []
    for key in selected:
        matching = [event for event in events if event["issue"] == key]
        item = labels[key]
        summary.append({"key": key, "label": item.label, "severity": item.severity, "count": len(matching), "detected": bool(matching)})
    missing_responses = [event for event in events if event["issue"] == "missing_response"]
    if check_ping or check_response:
        summary.append({
            "key": "missing_response",
            "label": "Requests without response",
            "severity": "critical",
            "count": len(missing_responses),
            "detected": bool(missing_responses),
        })
    summary.sort(key=lambda item: (not item["detected"], item["severity"], item["label"]))
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "packet_count": len(rows),
        "summary": summary,
        "events": events,
        "protocols": sorted(protocols),
        "check_ping": check_ping,
        "check_response": check_response,
        "available_fields": sorted(available),
    }


def _find_missing_responses(
    pcap_path: str,
    source_ip: str,
    destination_ip: str,
    source_mac: str,
    destination_mac: str,
    protocols: set[str],
    check_ping: bool,
    check_response: bool,
    available: frozenset[str],
    address_family: str = "all",
) -> list[dict]:
    fields = [field for field in (
        "frame.number", "frame.time_relative", "frame.len", "frame.protocols", "_ws.col.info", "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "icmp.type", "icmpv6.type", "ipv6.src", "ipv6.dst",
    ) if field in available]
    protocol_filter = " || ".join(_PROTOCOL_FILTERS[key] for key in protocols if key in _PROTOCOL_FILTERS)
    ping_filter = "icmp || icmpv6" if check_ping else ""
    protocol_filter = " || ".join(part for part in (protocol_filter, ping_filter) if part)
    if not protocol_filter:
        return []
    path_parts = []
    if source_ip and destination_ip:
        address_fields = "ipv6" if ":" in source_ip or ":" in destination_ip else "ip"
        path_parts.append(
            f"(({address_fields}.src == {source_ip} && {address_fields}.dst == {destination_ip}) || "
            f"({address_fields}.src == {destination_ip} && {address_fields}.dst == {source_ip}))"
        )
    elif source_ip:
        address_field = "ipv6.addr" if ":" in source_ip else "ip.addr"
        path_parts.append(f"{address_field} == {source_ip}")
    elif destination_ip:
        address_field = "ipv6.addr" if ":" in destination_ip else "ip.addr"
        path_parts.append(f"{address_field} == {destination_ip}")
    if source_mac and destination_mac:
        path_parts.append(f"((eth.src == {source_mac} && eth.dst == {destination_mac}) || (eth.src == {destination_mac} && eth.dst == {source_mac}))")
    family_filter = {"ipv4": "ip", "ipv6": "ipv6"}.get(address_family)
    query_parts = [f"({protocol_filter})"]
    if family_filter:
        query_parts.append(f"{family_filter}")
    query = " && ".join(query_parts + path_parts)
    rows = tshark_fields(pcap_path, query, fields)
    indexes = {field: index for index, field in enumerate(fields)}
    pending: dict[str, list[dict]] = {key: [] for key in protocols}
    pending["ping"] = []
    events = []
    for raw in rows:
        row = {field: raw[index] if index < len(raw) else "" for field, index in indexes.items()}
        try:
            timestamp = float(_text(row.get("frame.time_relative")))
        except ValueError:
            continue
        src, dst = _row_endpoints(row)
        forward = (not source_ip or src == source_ip) and (not destination_ip or dst == destination_ip)
        ping_type = _text(row.get("icmp.type"))
        pingv6_type = _text(row.get("icmpv6.type"))
        ping_request = ping_type == "8" or pingv6_type == "128"
        ping_reply = ping_type == "0" or pingv6_type == "129"
        details = _request_details(row, timestamp)
        if check_ping and (ping_type or pingv6_type):
            ping_label = "ICMPv6" if pingv6_type else "ICMP"
            packet_type = pingv6_type or ping_type
            type_labels = (
                {"1": "Destination unreachable", "2": "Packet too big", "3": "Time exceeded",
                  "4": "Parameter problem", "128": "Echo request", "129": "Echo reply",
                  "133": "Router Solicitation", "134": "Router Advertisement",
                  "135": "Neighbor Solicitation", "136": "Neighbor Advertisement",
                  "143": "Multicast Listener Report"}
                if pingv6_type else
                {"0": "Echo reply", "3": "Destination unreachable", "8": "Echo request",
                  "11": "Time exceeded", "4": "Source quench", "13": "Timestamp request",
                  "14": "Timestamp reply", "17": "Address mask request"}
            )
            ping_kind = type_labels.get(packet_type, f"ICMP type {packet_type}")
            events.append({
                "issue": "packet_evidence",
                **details,
                "protocol": ping_label,
                "detail": _text(row.get("_ws.col.info")) or f"{ping_label} {ping_kind}",
            })
        if check_ping and ping_request and (source_ip or destination_ip):
            pending["ping"].append(details)
        elif check_ping and ping_request and not _match_response(
            pending["ping"], timestamp, details["source"], details["destination"]
        ):
            pending["ping"].append(details)
        elif check_ping and ping_reply:
            _match_response(pending["ping"], timestamp, details["source"], details["destination"])
        if not check_response:
            for key in protocols:
                if _row_matches_protocol(row, key):
                    protocol_label = dict(PROTOCOL_TYPES).get(key, key)
                    info = _text(row.get("_ws.col.info"))
                    events.append({
                        "issue": "packet_evidence",
                        **details,
                        "protocol": protocol_label,
                        "detail": info or f"{protocol_label} packet",
                    })
            continue
        for key in protocols:
            if not _row_matches_protocol(row, key):
                continue
            protocol_label = dict(PROTOCOL_TYPES).get(key, key)
            info = _text(row.get("_ws.col.info"))
            events.append({
                "issue": "packet_evidence",
                **details,
                "protocol": protocol_label,
                "detail": info or f"{protocol_label} packet",
            })
            if source_ip or destination_ip:
                if forward:
                    pending[key].append(details)
                else:
                    _match_response(pending[key], timestamp, details["source"], details["destination"])
            elif not _match_response(
                pending[key], timestamp, details["source"], details["destination"]
            ):
                pending[key].append(details)
    if check_ping:
        for request in pending["ping"]:
            events.append({
                "issue": "missing_response", **request,
                "detail": "Ping request had no matching echo reply",
            })
    if check_response:
        for key in protocols:
            label = dict(PROTOCOL_TYPES).get(key, key)
            for request in pending[key]:
                events.append({
                    "issue": "missing_response", **request,
                    "detail": f"{label} request had no reverse-direction response within 5 seconds",
                })
    return events


def _request_details(row: dict[str, str], timestamp: float) -> dict:
    protocol = _text(row.get("frame.protocols")).split(":")[-1].upper() or "UNKNOWN"
    source, destination = _row_endpoints(row)
    return {
        "packet": _text(row.get("frame.number")),
        "time": timestamp,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "length": _text(row.get("frame.len")),
    }


def _row_endpoints(row: dict[str, str]) -> tuple[str, str]:
    return (
        _text(row.get("ip.src")) or _text(row.get("ipv6.src")),
        _text(row.get("ip.dst")) or _text(row.get("ipv6.dst")),
    )


def _match_response(
    pending: list[dict], timestamp: float, source: str = "", destination: str = ""
) -> bool:
    while pending and timestamp - pending[0]["time"] > 5:
        pending.pop(0)
    for index, request in enumerate(pending):
        if timestamp - request["time"] > 5:
            continue
        if not source or not destination or (
            request.get("source") == destination and request.get("destination") == source
        ):
            pending.pop(index)
            return True
    return False


def _row_matches_protocol(row: dict[str, str], key: str) -> bool:
    protocols = _text(row.get("frame.protocols")).lower()
    if key == "bacnet":
        return "bacnet" in protocols or _text(row.get("udp.srcport")) == "47808" or _text(row.get("udp.dstport")) == "47808"
    if key == "profinet":
        return any(tag in protocols for tag in ("pn_io", "pn_rt", "pn_dcp"))
    if key == "modbus":
        return "modbus" in protocols or _text(row.get("tcp.srcport")) == "502" or _text(row.get("tcp.dstport")) == "502"
    if key == "ethernet_ip":
        return "enip" in protocols or _text(row.get("tcp.srcport")) == "44818" or _text(row.get("tcp.dstport")) == "44818" or _text(row.get("udp.srcport")) == "2222" or _text(row.get("udp.dstport")) == "2222"
    return False
