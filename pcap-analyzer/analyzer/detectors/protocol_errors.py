from __future__ import annotations

from analyzer.capture import tshark_fields


_MODBUS_EXCEPTIONS = {
    0x01: ("error", "Illegal Function"),
    0x02: ("error", "Illegal Data Address"),
    0x03: ("error", "Illegal Data Value"),
    0x04: ("error", "Slave Device Failure"),
    0x05: ("warn", "Acknowledge"),
    0x06: ("warn", "Slave Device Busy"),
    0x08: ("error", "Memory Parity Error"),
    0x0A: ("error", "Gateway Path Unavailable"),
    0x0B: ("error", "Gateway Target Device Failed To Respond"),
}

_MQTT_REASON_CODES = {
    0x80: ("error", "Unspecified Error"),
    0x81: ("error", "Malformed Packet"),
    0x82: ("error", "Protocol Error"),
    0x84: ("error", "Unsupported Protocol Version"),
    0x85: ("error", "Client Identifier Not Valid"),
    0x86: ("error", "Bad Username Or Password"),
    0x87: ("error", "Not Authorized"),
    0x88: ("error", "Server Unavailable"),
    0x89: ("warn", "Server Busy"),
}

_ETHERCAT_AL_STATUS = {
    0x0001: ("error", "Unspecified Error"),
    0x0002: ("error", "No Memory"),
    0x0011: ("error", "Invalid Requested State Change"),
    0x0014: ("error", "No Valid Firmware"),
    0x0017: ("error", "Invalid Sync Manager Configuration"),
    0x001A: ("error", "Synchronization Error"),
    0x001B: ("error", "Sync Manager Watchdog"),
    0x0024: ("error", "Invalid Input Mapping"),
    0x0025: ("error", "Invalid Output Mapping"),
    0x0030: ("error", "Invalid DC Sync Configuration"),
}

_CIP_GENERAL_STATUS = {
    0x00: ("info", "Success"),
    0x01: ("error", "Connection Failure"),
    0x02: ("error", "Resource Unavailable"),
    0x04: ("error", "Path Segment Error"),
    0x05: ("error", "Path Destination Unknown"),
    0x08: ("error", "Service Not Supported"),
    0x09: ("error", "Invalid Attribute Value"),
    0x0E: ("error", "Attribute Not Settable"),
    0x10: ("error", "Device State Conflict"),
    0x14: ("error", "Attribute Not Supported"),
    0x16: ("error", "Object Does Not Exist"),
    0x20: ("error", "Invalid Parameter"),
}

_PROFINET_DIAG = {
    0x8000: ("error", "No Connection"),
    0x8001: ("error", "Connection Aborted"),
    0x8002: ("error", "Configuration Error"),
    0x8003: ("error", "Device Not Responding"),
    0x8004: ("error", "Mismatch Error (Configuration/GSDML mismatch)"),
}


def _safe_int(value: str) -> int | None:
    s = (value or "").strip().lower()
    if not s:
        return None
    try:
        if s.startswith("16#"):
            return int(s[3:], 16)
        return int(s, 0)
    except ValueError:
        return None


def _fmt_code(code: int, width: int = 2) -> str:
    return f"0x{code:0{width}X}"


def detect(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings: list[dict] = []
    _detect_modbus(pcap_path, findings, user_filter)
    _detect_mqtt(pcap_path, findings, user_filter)
    _detect_ethercat(pcap_path, findings, user_filter)
    _detect_cip(pcap_path, findings, user_filter)
    _detect_profinet(pcap_path, findings, user_filter)
    return findings


def _detect_modbus(pcap_path, findings: list[dict], user_filter):
    rows = tshark_fields(
        pcap_path,
        "modbus.exception_code",
        [
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "modbus.func_code",
            "modbus.exception_code",
        ],
        user_filter,
    )
    for row in rows:
        num, t, src, dst, func_code, exc_code = (row + [""] * 6)[:6]
        code = _safe_int(exc_code)
        if code is None:
            continue
        sev, msg = _MODBUS_EXCEPTIONS.get(code, ("error", f"Exception Code {_fmt_code(code)}"))
        fc = _safe_int(func_code)
        fc_txt = _fmt_code(fc) if fc is not None else (func_code or "?")
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        findings.append({
            "severity": sev,
            "protocol": "Modbus",
            "pkt_num": num,
            "msg": f"Modbus exception {_fmt_code(code)} ({msg}) at {ts} - {src} -> {dst} [func {fc_txt}]",
        })


def _detect_mqtt(pcap_path, findings: list[dict], user_filter):
    rows = tshark_fields(
        pcap_path,
        "mqtt.reason_code",
        [
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "mqtt.msgtype",
            "mqtt.reason_code",
        ],
        user_filter,
    )
    for row in rows:
        num, t, src, dst, msg_type, reason_code = (row + [""] * 6)[:6]
        code = _safe_int(reason_code)
        if code is None:
            continue
        sev, msg = _MQTT_REASON_CODES.get(code, ("warn", f"Reason Code {_fmt_code(code)}"))
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        findings.append({
            "severity": sev,
            "protocol": "MQTT",
            "pkt_num": num,
            "msg": f"MQTT reason {_fmt_code(code)} ({msg}) at {ts} - {src} -> {dst} [type {msg_type or '?'}]",
        })


def _detect_ethercat(pcap_path, findings: list[dict], user_filter):
    rows = tshark_fields(
        pcap_path,
        "ecat.alstatuscode",
        [
            "frame.number",
            "frame.time_relative",
            "eth.src",
            "eth.dst",
            "ecat.alstatuscode",
        ],
        user_filter,
    )
    for row in rows:
        num, t, src, dst, status = (row + [""] * 5)[:5]
        code = _safe_int(status)
        if code is None:
            continue
        sev, msg = _ETHERCAT_AL_STATUS.get(code, ("error", f"AL Status {_fmt_code(code, 4)}"))
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        findings.append({
            "severity": sev,
            "protocol": "EtherCAT",
            "pkt_num": num,
            "msg": f"EtherCAT AL status {_fmt_code(code, 4)} ({msg}) at {ts} - {src} -> {dst}",
        })


def _detect_cip(pcap_path, findings: list[dict], user_filter):
    rows = tshark_fields(
        pcap_path,
        "cip.genstat",
        [
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "cip.genstat",
            "cip.service",
        ],
        user_filter,
    )
    for row in rows:
        num, t, src, dst, status, service = (row + [""] * 6)[:6]
        code = _safe_int(status)
        if code is None or code == 0:
            continue
        sev, msg = _CIP_GENERAL_STATUS.get(code, ("error", f"General Status {_fmt_code(code)}"))
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        findings.append({
            "severity": sev,
            "protocol": "EtherNet/IP",
            "pkt_num": num,
            "msg": f"CIP status {_fmt_code(code)} ({msg}) at {ts} - {src} -> {dst} [service {service or '?'}]",
        })


def _detect_profinet(pcap_path, findings: list[dict], user_filter):
    rows = tshark_fields(
        pcap_path,
        "pn_io.status",
        [
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "pn_io.status",
        ],
        user_filter,
    )
    for row in rows:
        num, t, src, dst, status = (row + [""] * 5)[:5]
        code = _safe_int(status)
        if code is None:
            continue
        sev, msg = _PROFINET_DIAG.get(code, ("warn", f"Diagnostic {_fmt_code(code, 4)}"))
        try:
            ts = f"{float(t):.3f}s"
        except ValueError:
            ts = t
        findings.append({
            "severity": sev,
            "protocol": "PROFINET",
            "pkt_num": num,
            "msg": f"PROFINET diagnostic {_fmt_code(code, 4)} ({msg}) at {ts} - {src} -> {dst}",
        })