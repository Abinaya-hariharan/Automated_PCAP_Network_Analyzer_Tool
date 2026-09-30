from __future__ import annotations
from analyzer.capture import tshark_fields


def detect(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings = []
    rows = tshark_fields(pcap_path, 'http.response.code >= 400',
                         ['frame.number', 'frame.time_relative', 'ip.src', 'ip.dst',
                          'http.response.code', 'http.response.phrase'], user_filter)
    for row in rows:
        num, t, src, dst, code, phrase = (row + [''] * 6)[:6]
        sev = 'error' if code.startswith('5') else 'warn'
        try:
            findings.append({"severity": sev, "protocol": "HTTP", "pkt_num": num,
                "msg": f"HTTP {code} {phrase} at {float(t):.3f}s \u2014 {src} \u2192 {dst}"})
        except ValueError:
            findings.append({"severity": sev, "protocol": "HTTP", "pkt_num": num,
                "msg": f"HTTP {code} {phrase} \u2014 {src} \u2192 {dst}"})

    rows = tshark_fields(pcap_path, 'http.time > 1',
                         ['frame.number', 'frame.time_relative', 'ip.src', 'ip.dst', 'http.time'], user_filter)
    for row in rows:
        num, t, src, dst, rt = (row + [''] * 5)[:5]
        try:
            findings.append({"severity": "warn", "protocol": "HTTP", "pkt_num": num,
                "msg": f"Slow HTTP response {float(rt):.2f}s at {float(t):.3f}s \u2014 {src} \u2192 {dst}"})
        except ValueError:
            pass
    return findings
