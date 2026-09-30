from __future__ import annotations
from analyzer.capture import tshark_fields

_FLAG_MAP = {
    'tcp.analysis.retransmission':     ('warn',  'Retransmission'),
    'tcp.analysis.fast_retransmission':('warn',  'Fast retransmission'),
    'tcp.analysis.lost_segment':       ('warn',  'Lost segment'),
    'tcp.analysis.window_full':        ('warn',  'Window full (receiver buffer saturated)'),
    'tcp.analysis.zero_window':        ('error', 'Zero window (receiver cannot accept data)'),
    'tcp.analysis.duplicate_ack':      ('info',  'Duplicate ACK'),
}
_COMBINED = ' || '.join(_FLAG_MAP.keys())
_FIELDS   = ['frame.number', 'frame.time_relative', 'ip.src', 'ip.dst'] + list(_FLAG_MAP.keys())


def detect(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings = []
    rows = tshark_fields(pcap_path, _COMBINED, _FIELDS, user_filter)
    for row in rows:
        row += [''] * (len(_FIELDS) - len(row))
        num, t, src, dst = row[0], row[1], row[2], row[3]
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        for i, (field, (sev, label)) in enumerate(_FLAG_MAP.items(), start=4):
            if row[i]:
                findings.append({"severity": sev, "protocol": "TCP", "pkt_num": num,
                    "msg": f"{label} at {ts} \u2014 {src} \u2192 {dst}"})
    for row in tshark_fields(pcap_path, 'tcp.flags.reset==1',
                             ['frame.number', 'frame.time_relative', 'ip.src', 'ip.dst'], user_filter):
        num, t, src, dst = (row + ['', '', '', ''])[:4]
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        findings.append({"severity": "error", "protocol": "TCP", "pkt_num": num,
            "msg": f"RST \u2014 connection forcibly closed at {ts} \u2014 {src} \u2192 {dst}"})
    return findings

