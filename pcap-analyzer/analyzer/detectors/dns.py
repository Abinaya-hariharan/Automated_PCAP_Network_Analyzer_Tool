from __future__ import annotations
from analyzer.capture import tshark_fields

_RCODES = {'2': ('error', 'SERVFAIL'), '3': ('warn', 'NXDOMAIN'), '5': ('error', 'REFUSED')}


def detect(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings = []
    rows = tshark_fields(pcap_path, 'dns.flags.response==1 && dns.flags.rcode > 0',
                         ['frame.number', 'frame.time_relative', 'ip.src', 'dns.qry.name', 'dns.flags.rcode'],
                         user_filter)
    for row in rows:
        num, t, src, qname, rcode = (row + [''] * 5)[:5]
        sev, label = _RCODES.get(rcode, ('warn', f'rcode={rcode}'))
        try:
            findings.append({"severity": sev, "protocol": "DNS", "pkt_num": num,
                "msg": f"DNS {label} for '{qname}' at {float(t):.3f}s from {src}"})
        except ValueError:
            findings.append({"severity": sev, "protocol": "DNS", "pkt_num": num,
                "msg": f"DNS {label} for '{qname}' from {src}"})

    rows = tshark_fields(pcap_path, 'dns.time > 0.5 && dns.flags.response==1',
                         ['frame.number', 'frame.time_relative', 'ip.src', 'dns.qry.name', 'dns.time'],
                         user_filter)
    for row in rows:
        num, t, src, qname, rt = (row + [''] * 5)[:5]
        try:
            findings.append({"severity": "warn", "protocol": "DNS", "pkt_num": num,
                "msg": f"Slow DNS {float(rt):.3f}s for '{qname}' from {src}"})
        except ValueError:
            pass
    return findings
