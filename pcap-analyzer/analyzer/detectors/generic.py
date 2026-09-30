from __future__ import annotations
from analyzer.capture import tshark_fields

_ICMP_CODES = {
    '0': 'Net unreachable', '1': 'Host unreachable', '2': 'Protocol unreachable',
    '3': 'Port unreachable', '9': 'Network admin prohibited',
    '10': 'Host admin prohibited', '13': 'Comm admin prohibited',
}


def detect(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings = []
    _icmp_errors(pcap_path, findings, user_filter)
    _arp_unanswered(pcap_path, findings, user_filter)
    _malformed(pcap_path, findings, user_filter)
    return findings


def _icmp_errors(pcap_path, findings, user_filter):
    rows = tshark_fields(pcap_path, 'icmp.type == 3 || icmp.type == 11',
                         ['frame.number', 'frame.time_relative', 'ip.src', 'icmp.type', 'icmp.code'],
                         user_filter)
    for row in rows:
        num, t, src, icmp_type, code = (row + [''] * 5)[:5]
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        if icmp_type == '3':
            label = _ICMP_CODES.get(code, f'code {code}')
            findings.append({"severity": "error", "protocol": "ICMP", "pkt_num": num,
                "msg": f"Destination Unreachable ({label}) at {ts} from {src}"})
        elif icmp_type == '11':
            findings.append({"severity": "warn", "protocol": "ICMP", "pkt_num": num,
                "msg": f"Time Exceeded (TTL expired) at {ts} from {src}"})


def _arp_unanswered(pcap_path, findings, user_filter):
    requests = tshark_fields(pcap_path, 'arp.opcode == 1',
                              ['frame.number', 'frame.time_relative', 'arp.dst.proto_ipv4'], user_filter)
    replies   = tshark_fields(pcap_path, 'arp.opcode == 2',
                              ['arp.src.proto_ipv4'], user_filter)
    replied = {r[0] for r in replies if r}
    for row in requests:
        num, t, target = (row + ['', '', ''])[:3]
        if target and target not in replied:
            try:
                findings.append({"severity": "warn", "protocol": "ARP", "pkt_num": num,
                    "msg": f"Unanswered ARP request for {target} at {float(t):.3f}s"})
            except ValueError:
                pass


def _malformed(pcap_path, findings, user_filter):
    rows = tshark_fields(pcap_path, '_ws.malformed',
                         ['frame.number', 'frame.time_relative', 'frame.protocols'], user_filter)
    for row in rows:
        num, t, protos = (row + ['', '', ''])[:3]
        findings.append({"severity": "error", "protocol": protos.split(':')[-1].upper(), "pkt_num": num,
            "msg": f"Malformed packet ({protos}) at {float(t):.3f}s"})
