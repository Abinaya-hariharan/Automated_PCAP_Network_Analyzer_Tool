from __future__ import annotations
from analyzer.capture import tshark_fields

_ALERT_DESCS = {
    '0': 'close_notify', '10': 'unexpected_message', '20': 'bad_record_mac',
    '40': 'handshake_failure', '42': 'bad_certificate', '44': 'certificate_revoked',
    '43': 'unsupported_certificate', '45': 'certificate_expired', '46': 'certificate_unknown',
    '47': 'illegal_parameter',
    '48': 'unknown_ca', '51': 'decrypt_error', '70': 'protocol_version',
    '80': 'internal_error', '112': 'unrecognized_name',
}


def detect(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings = []
    rows = tshark_fields(pcap_path, 'tls.alert_message',
                         ['frame.time_relative', 'ip.src', 'ip.dst',
                          'tls.alert_message.level', 'tls.alert_message.desc'], user_filter)
    for row in rows:
        t, src, dst, level, desc_code = (row + [''] * 5)[:5]
        label = _ALERT_DESCS.get(desc_code, f'code {desc_code}')
        sev = 'error' if level == '2' else 'warn'
        level_str = 'fatal' if level == '2' else 'warning'
        try:
            findings.append({"severity": sev, "protocol": "TLS",
                "msg": f"TLS {level_str} alert '{label}' at {float(t):.3f}s — {src} → {dst}"})
        except ValueError:
            findings.append({"severity": sev, "protocol": "TLS",
                "msg": f"TLS {level_str} alert '{label}' — {src} → {dst}"})

    rows = tshark_fields(pcap_path,
                         'tls.handshake.version == 0x0301 || tls.handshake.version == 0x0302',
                         ['frame.time_relative', 'ip.src', 'ip.dst', 'tls.handshake.version'],
                         user_filter)
    for row in rows:
        t, src, dst, ver = (row + [''] * 4)[:4]
        try:
            findings.append({"severity": "warn", "protocol": "TLS",
                "msg": f"Deprecated TLS {ver} at {float(t):.3f}s — {src} → {dst}"})
        except ValueError:
            pass
    return findings
