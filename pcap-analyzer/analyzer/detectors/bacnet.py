from __future__ import annotations
from analyzer.capture import tshark_fields


_BACNET_ERROR_CODES = {
    "31": "Unknown Object",
    "32": "Unknown Property",
    "37": "Value Out Of Range",
    "40": "Write Access Denied",
    "9": "Invalid Data Type",
    "16": "Missing Required Parameter",
}

_BACNET_ABORT_REASONS = {
    "51": "Buffer Overflow",
    "54": "Segmentation Not Supported",
}


def detect(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings = []
    rows = tshark_fields(pcap_path, 'bacapp.type == 5 || bacapp.type == 6 || bacapp.type == 7',
                         ['frame.number', 'frame.time_relative', 'ip.src', 'ip.dst', 'bacapp.type',
                          'bacapp.error_class', 'bacapp.error_code',
                          'bacapp.reject_reason', 'bacapp.abort_reason'], user_filter)
    for row in rows:
        num, t, src, dst, apdu_type, ec, ev, rr, ar = (row + [''] * 9)[:9]
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        if apdu_type == '5':
            code_label = _BACNET_ERROR_CODES.get(ev, ev or "?")
            findings.append({"severity": "error", "protocol": "BACnet",
                "pkt_num": num,
                "msg": f"APDU Error at {ts} - class={ec} code={ev} ({code_label}) from {src}"})
        elif apdu_type == '6':
            findings.append({"severity": "error", "protocol": "BACnet",
                "pkt_num": num,
                "msg": f"APDU Reject at {ts} - reason={rr} from {src} -> {dst}"})
        elif apdu_type == '7':
            abort_label = _BACNET_ABORT_REASONS.get(ar, ar or "?")
            findings.append({"severity": "error", "protocol": "BACnet",
                "pkt_num": num,
                "msg": f"APDU Abort at {ts} - reason={ar} ({abort_label}) from {src} -> {dst}"})

    rows = tshark_fields(pcap_path, 'bacnet.control.net_message == 1',
                         ['frame.number', 'frame.time_relative', 'bacnet.msg'], user_filter)
    for row in rows:
        num, t, msg = (row + ['', '', ''])[:3]
        try:
            findings.append({"severity": "info", "protocol": "BACnet",
                "pkt_num": num,
                "msg": f"NPDU network-layer message type={msg} at {float(t):.3f}s"})
        except ValueError:
            pass
    return findings
