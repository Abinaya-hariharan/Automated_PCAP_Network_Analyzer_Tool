from __future__ import annotations
import os
import zipfile
import tempfile
import atexit
import shutil
from typing import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from analyzer.capture import (
    tshark_available_fields,
    tshark_fields,
    tshark_stat,
    get_packet_count,
)
from analyzer.flows import get_flows
from analyzer.smart_query import set_pcap

_TCP_FLAG_MAP = {
    'tcp.analysis.retransmission':      ('warn', 'Retransmission'),
    'tcp.analysis.fast_retransmission': ('warn', 'Fast retransmission'),
    'tcp.analysis.spurious_retransmission': ('warn', 'Spurious retransmission'),
    'tcp.analysis.lost_segment':        ('warn', 'Lost segment'),
    'tcp.analysis.window_full':         ('warn', 'Window full (receiver buffer saturated)'),
    'tcp.analysis.zero_window':         ('error', 'Zero window (receiver cannot accept data)'),
    'tcp.analysis.duplicate_ack':       ('info', 'Duplicate ACK'),
}
_DNS_RCODES = {'2': ('error', 'SERVFAIL'), '3': ('warn', 'NXDOMAIN'), '5': ('error', 'REFUSED')}
_TLS_ALERT_DESCS = {
    '0': 'close_notify', '10': 'unexpected_message', '20': 'bad_record_mac',
    '40': 'handshake_failure', '42': 'bad_certificate', '44': 'certificate_revoked',
    '45': 'certificate_expired', '46': 'certificate_unknown', '47': 'illegal_parameter',
    '48': 'unknown_ca', '51': 'decrypt_error', '70': 'protocol_version',
    '80': 'internal_error', '112': 'unrecognized_name',
}
_ICMP_CODES = {
    '0': 'Net unreachable', '1': 'Host unreachable', '2': 'Protocol unreachable',
    '3': 'Port unreachable', '9': 'Network admin prohibited',
    '10': 'Host admin prohibited', '13': 'Comm admin prohibited',
}
_MQTT_REASON_CODES = {
    '128': ('error', 'Unspecified Error'),
    '129': ('error', 'Malformed Packet'),
    '130': ('error', 'Protocol Error'),
    '132': ('error', 'Unsupported Protocol Version'),
    '133': ('error', 'Client Identifier Not Valid'),
    '134': ('error', 'Bad Username Or Password'),
    '135': ('error', 'Not Authorized'),
    '136': ('error', 'Server Unavailable'),
    '137': ('warn', 'Server Busy'),
}
_ETHERCAT_AL_STATUS = {
    '0x0001': ('error', 'Unspecified Error'),
    '0x0002': ('error', 'No Memory'),
    '0x0011': ('error', 'Invalid Requested State Change'),
    '0x0014': ('error', 'No Valid Firmware'),
    '0x0017': ('error', 'Invalid Sync Manager Configuration'),
    '0x001a': ('error', 'Synchronization Error'),
    '0x001b': ('error', 'Sync Manager Watchdog'),
    '0x0024': ('error', 'Invalid Input Mapping'),
    '0x0025': ('error', 'Invalid Output Mapping'),
    '0x0030': ('error', 'Invalid DC Sync Configuration'),
}
_CIP_GENERAL_STATUS = {
    '1': ('error', 'Connection Failure'),
    '2': ('error', 'Resource Unavailable'),
    '4': ('error', 'Path Segment Error'),
    '5': ('error', 'Path Destination Unknown'),
    '8': ('error', 'Service Not Supported'),
    '9': ('error', 'Invalid Attribute Value'),
    '14': ('error', 'Attribute Not Settable'),
    '16': ('error', 'Device State Conflict'),
    '20': ('error', 'Attribute Not Supported'),
    '22': ('error', 'Object Does Not Exist'),
    '32': ('error', 'Invalid Parameter'),
}

_MASTER_FIELDS = [
    'frame.number', 'frame.time_relative', 'ip.src', 'ip.dst', 'frame.protocols',
    'tcp.analysis.retransmission', 'tcp.analysis.fast_retransmission',
    'tcp.analysis.spurious_retransmission',
    'tcp.analysis.lost_segment', 'tcp.analysis.window_full',
    'tcp.analysis.zero_window', 'tcp.analysis.duplicate_ack',
    'tcp.flags.reset', 'tcp.flags.str',
    'tcp.srcport', 'tcp.dstport',
    'http.response.code', 'http.response.phrase', 'http.time',
    'dns.flags.response', 'dns.flags.rcode', 'dns.qry.name', 'dns.time',
    'tls.alert_message', 'tls.alert_message.level', 'tls.alert_message.desc', 'tls.handshake.version',
    'bacapp.type', 'bacapp.error_class', 'bacapp.error_code', 'bacapp.reject_reason', 'bacapp.abort_reason',
    'mqtt.reason_code', 'ecat.alstatuscode', 'cip.genstat', 'cip.service', 'pn_io.status',
    'modbus.exception_code', 'modbus.func_code', 'modbus.reference_num',
    'bacnet.control.net_message',
    'icmp.type', 'icmp.code',
    'arp.opcode', 'arp.dst.proto_ipv4', 'arp.src.proto_ipv4',
    '_ws.expert.message', '_ws.expert.severity',
    '_ws.malformed',
]

_MASTER_FILTER = (
    'tcp.analysis.retransmission || tcp.analysis.fast_retransmission || '
    'tcp.analysis.spurious_retransmission || '
    'tcp.analysis.lost_segment || tcp.analysis.window_full || tcp.analysis.zero_window || '
    'tcp.analysis.duplicate_ack || tcp.flags.reset==1 || '
    'modbus.exception_code || '
    'http.response.code >= 400 || http.time > 1 || '
    '(dns.flags.response==1 && dns.flags.rcode > 0) || '
    '(dns.time > 0.5 && dns.flags.response==1) || '
    'tls.alert_message || tls.handshake.version == 0x0301 || tls.handshake.version == 0x0302 || '
    'bacapp.type == 5 || bacapp.type == 6 || bacapp.type == 7 || '
    'cip.genstat || pn_io.status || '
    '((frame.protocols contains "pn_io" || frame.protocols contains "pn_dcp" || frame.protocols contains "pn_rt") && _ws.expert) || '
    'icmp.type == 3 || icmp.type == 11 || '
    'arp.opcode == 1 || arp.opcode == 2 || '
    '_ws.malformed'
)

_OPTIONAL_MASTER_FILTERS = {
    'mqtt.reason_code': 'mqtt.reason_code',
    'ecat.alstatuscode': 'ecat.alstatuscode',
    'bacnet.control.net_message': 'bacnet.control.net_message == 1',
}


def _safe_float(text: str) -> float | None:
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _safe_code(text: str) -> str:
    """Normalize tshark numeric protocol fields for lookup and display."""
    value = (text or '').strip().lower()
    if not value:
        return ''
    try:
        return str(int(value, 0))
    except ValueError:
        return value


def _tcp_rst_severity(total_rst: int, flow_rst: int) -> str:
    if flow_rst >= 20 or total_rst >= 200:
        return 'error'
    if flow_rst >= 4 or total_rst >= 20:
        return 'warn'
    return 'info'


def _tcp_retx_severity(total_retx: int, flow_retx: int, is_spurious: bool) -> str:
    if is_spurious and (flow_retx >= 10 or total_retx >= 100):
        return 'error'
    if flow_retx >= 4 or total_retx >= 40:
        return 'warn'
    return 'info'


def _detect_findings_single_pass(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    findings: list[dict] = []
    available = tshark_available_fields()
    fields = [field for field in _MASTER_FIELDS if field in available]
    filters = [_MASTER_FILTER]
    filters.extend(
        expression for field, expression in _OPTIONAL_MASTER_FILTERS.items()
        if field in available
    )
    master_filter = ' || '.join(filters)
    rows = tshark_fields(pcap_path, master_filter, fields, user_filter)

    arp_requests: list[tuple[str, str, str]] = []
    arp_replies: set[str] = set()
    rst_events: list[dict] = []
    retx_events: list[dict] = []
    flow_rst_counts: dict[tuple[str, str], int] = {}
    flow_retx_counts: dict[tuple[str, str], int] = {}

    for row in rows:
        row += [''] * (len(fields) - len(row))
        r = dict(zip(fields, row))

        num = r['frame.number']
        t = r['frame.time_relative']
        src = r['ip.src']
        dst = r['ip.dst']
        ts_val = _safe_float(t)
        ts = f"{ts_val:.3f}s" if ts_val is not None else t
        flow_key = (src or '', dst or '')

        # TCP analysis flags
        for field, (sev, label) in _TCP_FLAG_MAP.items():
            if r.get(field):
                if field in (
                    'tcp.analysis.retransmission',
                    'tcp.analysis.fast_retransmission',
                    'tcp.analysis.spurious_retransmission',
                    'tcp.analysis.lost_segment',
                ):
                    flow_retx_counts[flow_key] = flow_retx_counts.get(flow_key, 0) + 1
                    retx_events.append({
                        "pkt_num": num,
                        "flow_key": flow_key,
                        "src": src,
                        "dst": dst,
                        "ts": ts,
                        "label": label,
                        "is_spurious": field == 'tcp.analysis.spurious_retransmission',
                    })
                else:
                    findings.append({
                        "severity": sev,
                        "protocol": "TCP",
                        "pkt_num": num,
                        "msg": f"{label} at {ts} — {src} → {dst}",
                    })

        # TCP reset
        if str(r.get('tcp.flags.reset', '')).strip() in ('1', 'true', 'True'):
            flow_rst_counts[flow_key] = flow_rst_counts.get(flow_key, 0) + 1
            rst_events.append({
                "pkt_num": num,
                "flow_key": flow_key,
                "src": src,
                "dst": dst,
                "ts": ts,
            })

        # Modbus exceptions and likely missing responses on 502
        mb_exc = (r.get('modbus.exception_code') or '').strip()
        if mb_exc:
            findings.append({
                "severity": "error",
                "protocol": "MODBUS",
                "pkt_num": num,
                "msg": (
                    f"Modbus exception code {mb_exc} at {ts} — {src} → {dst} "
                    f"(func={r.get('modbus.func_code', '')}, ref={r.get('modbus.reference_num', '')})"
                ),
            })
        elif (r.get('tcp.srcport') == '502' or r.get('tcp.dstport') == '502') and (
            r.get('tcp.analysis.retransmission') or
            r.get('tcp.analysis.fast_retransmission') or
            r.get('tcp.analysis.spurious_retransmission')
        ):
            findings.append({
                "severity": "warn",
                "protocol": "MODBUS",
                "pkt_num": num,
                "msg": f"Likely Modbus response delay/loss at {ts} — retransmission on TCP/502 ({src} → {dst})",
            })

        # HTTP
        code = r.get('http.response.code', '')
        phrase = r.get('http.response.phrase', '')
        if code:
            sev = 'error' if code.startswith('5') else 'warn'
            if ts_val is not None:
                findings.append({"severity": sev, "protocol": "HTTP", "pkt_num": num,
                    "msg": f"HTTP {code} {phrase} at {ts} — {src} → {dst}"})
            else:
                findings.append({"severity": sev, "protocol": "HTTP", "pkt_num": num,
                    "msg": f"HTTP {code} {phrase} — {src} → {dst}"})
        http_time = _safe_float(r.get('http.time', ''))
        if http_time is not None and http_time > 1:
            findings.append({"severity": "warn", "protocol": "HTTP", "pkt_num": num,
                "msg": f"Slow HTTP response {http_time:.2f}s at {ts} — {src} → {dst}"})

        # DNS
        dns_resp = r.get('dns.flags.response', '')
        dns_rcode = r.get('dns.flags.rcode', '')
        dns_qname = r.get('dns.qry.name', '')
        if dns_resp == '1' and dns_rcode not in ('', '0'):
            sev, label = _DNS_RCODES.get(dns_rcode, ('warn', f'rcode={dns_rcode}'))
            if ts_val is not None:
                findings.append({"severity": sev, "protocol": "DNS", "pkt_num": num,
                    "msg": f"DNS {label} for '{dns_qname}' at {ts} from {src}"})
            else:
                findings.append({"severity": sev, "protocol": "DNS", "pkt_num": num,
                    "msg": f"DNS {label} for '{dns_qname}' from {src}"})
        dns_time = _safe_float(r.get('dns.time', ''))
        if dns_resp == '1' and dns_time is not None and dns_time > 0.5:
            findings.append({"severity": "warn", "protocol": "DNS", "pkt_num": num,
                "msg": f"Slow DNS {dns_time:.3f}s for '{dns_qname}' from {src}"})

        # TLS
        if r.get('tls.alert_message', ''):
            level = r.get('tls.alert_message.level', '')
            desc_code = r.get('tls.alert_message.desc', '')
            label = _TLS_ALERT_DESCS.get(desc_code, f'code {desc_code}')
            sev = 'error' if level == '2' else 'warn'
            level_str = 'fatal' if level == '2' else 'warning'
            if ts_val is not None:
                findings.append({"severity": sev, "protocol": "TLS",
                    "pkt_num": num,
                    "msg": f"TLS {level_str} alert '{label}' at {ts} — {src} → {dst}"})
            else:
                findings.append({"severity": sev, "protocol": "TLS",
                    "pkt_num": num,
                    "msg": f"TLS {level_str} alert '{label}' — {src} → {dst}"})
        if r.get('tls.handshake.version', '') in ('0x0301', '0x0302') and ts_val is not None:
            findings.append({"severity": "warn", "protocol": "TLS",
                "pkt_num": num,
                "msg": f"Deprecated TLS {r['tls.handshake.version']} at {ts} — {src} → {dst}"})

        # MQTT reason codes
        mqtt_code = _safe_code(r.get('mqtt.reason_code', ''))
        if mqtt_code:
            sev, label = _MQTT_REASON_CODES.get(
                mqtt_code, ('warn', f'Reason Code {mqtt_code}')
            )
            findings.append({"severity": sev, "protocol": "MQTT", "pkt_num": num,
                "msg": f"MQTT reason {mqtt_code} ({label}) at {ts} — {src} → {dst}"})

        # EtherCAT AL status
        ecat_code = r.get('ecat.alstatuscode', '').strip().lower()
        if ecat_code:
            if not ecat_code.startswith('0x'):
                try:
                    ecat_code = f"0x{int(ecat_code, 0):04x}"
                except ValueError:
                    pass
            sev, label = _ETHERCAT_AL_STATUS.get(
                ecat_code, ('error', f'AL Status {ecat_code}')
            )
            findings.append({"severity": sev, "protocol": "EtherCAT", "pkt_num": num,
                "msg": f"EtherCAT AL status {ecat_code} ({label}) at {ts} — {src} → {dst}"})

        # EtherNet/IP / CIP general status
        cip_code = _safe_code(r.get('cip.genstat', ''))
        if cip_code and cip_code != '0':
            sev, label = _CIP_GENERAL_STATUS.get(
                cip_code, ('error', f'General Status {cip_code}')
            )
            service = r.get('cip.service', '') or '?'
            findings.append({"severity": sev, "protocol": "EtherNet/IP", "pkt_num": num,
                "msg": f"CIP status {cip_code} ({label}) at {ts} — {src} → {dst} [service {service}]"})

        # PROFINET status field; expert diagnostics below provide richer text when present.
        pn_status = r.get('pn_io.status', '').strip()
        if pn_status:
            findings.append({"severity": "error", "protocol": "PROFINET", "pkt_num": num,
                "msg": f"PROFINET status {pn_status} at {ts} — {src} → {dst}"})

        # BACnet
        apdu_type = r.get('bacapp.type', '')
        if apdu_type == '5':
            findings.append({"severity": "error", "protocol": "BACnet",
                "pkt_num": num,
                "msg": f"APDU Error at {ts} — class={r.get('bacapp.error_class', '')} code={r.get('bacapp.error_code', '')} from {src}"})
        elif apdu_type == '6':
            findings.append({"severity": "error", "protocol": "BACnet",
                "pkt_num": num,
                "msg": f"APDU Reject at {ts} — reason={r.get('bacapp.reject_reason', '')} from {src} → {dst}"})
        elif apdu_type == '7':
            findings.append({"severity": "error", "protocol": "BACnet",
                "pkt_num": num,
                "msg": f"APDU Abort at {ts} — reason={r.get('bacapp.abort_reason', '')} from {src} → {dst}"})
        if str(r.get('bacnet.control.net_message', '')).strip() in ('1', 'true', 'True') and ts_val is not None:
            findings.append({"severity": "info", "protocol": "BACnet",
            "pkt_num": num,
            "msg": f"NPDU network-layer message at {ts} — {src} → {dst}"})

        # ICMP
        icmp_type = r.get('icmp.type', '')
        icmp_code = r.get('icmp.code', '')
        if icmp_type == '3':
            label = _ICMP_CODES.get(icmp_code, f'code {icmp_code}')
            findings.append({"severity": "error", "protocol": "ICMP", "pkt_num": num,
                "msg": f"Destination Unreachable ({label}) at {ts} from {src}"})
        elif icmp_type == '11':
            findings.append({"severity": "warn", "protocol": "ICMP", "pkt_num": num,
                "msg": f"Time Exceeded (TTL expired) at {ts} from {src}"})

        # PROFINET (expert-driven)
        proto_chain = (r.get('frame.protocols', '') or '').lower()
        is_profinet = any(tag in proto_chain for tag in ('pn_io', 'pn_dcp', 'pn_rt', 'pnio'))
        if is_profinet:
            exp_msg = (r.get('_ws.expert.message', '') or '').strip()
            exp_sev = (r.get('_ws.expert.severity', '') or '').strip().lower()
            if exp_msg:
                msg_l = exp_msg.lower()
                is_error = (
                    'error' in exp_sev or
                    exp_sev in ('error', '2097152') or
                    any(k in msg_l for k in (
                        'timeout', 'no response', 'invalid', 'mismatch',
                        'duplicate ip', 'alarm', 'lost', 'failure',
                    ))
                )
                sev = 'error' if is_error else 'warn'
                findings.append({
                    "severity": sev,
                    "protocol": "PROFINET",
                    "pkt_num": num,
                    "msg": f"Profinet diagnostic at {ts} — {exp_msg} ({src} → {dst})",
                })

        # ARP request/reply tracking
        arp_opcode = r.get('arp.opcode', '')
        if arp_opcode == '1':
            arp_requests.append((num, t, r.get('arp.dst.proto_ipv4', '')))
        elif arp_opcode == '2':
            src_ip = r.get('arp.src.proto_ipv4', '')
            if src_ip:
                arp_replies.add(src_ip)

        # Malformed
        if r.get('_ws.malformed', ''):
            proto = (r.get('frame.protocols', '').split(':')[-1]).upper() or 'UNKNOWN'
            findings.append({"severity": "error", "protocol": proto, "pkt_num": num,
                "msg": f"Malformed packet ({r.get('frame.protocols', '')}) at {ts}"})

    # Unanswered ARP requests
    for num, t, target in arp_requests:
        if target and target not in arp_replies:
            t_val = _safe_float(t)
            if t_val is not None:
                findings.append({"severity": "warn", "protocol": "ARP", "pkt_num": num,
                    "msg": f"Unanswered ARP request for {target} at {t_val:.3f}s"})

    total_rst = len(rst_events)
    for evt in rst_events:
        flow_rst = flow_rst_counts.get(evt['flow_key'], 1)
        sev = _tcp_rst_severity(total_rst, flow_rst)
        findings.append({
            "severity": sev,
            "protocol": "TCP",
            "pkt_num": evt['pkt_num'],
            "msg": f"RST — connection forcibly closed at {evt['ts']} — {evt['src']} → {evt['dst']}",
        })

    total_retx = len(retx_events)
    for evt in retx_events:
        flow_retx = flow_retx_counts.get(evt['flow_key'], 1)
        sev = _tcp_retx_severity(total_retx, flow_retx, evt['is_spurious'])
        findings.append({
            "severity": sev,
            "protocol": "TCP",
            "pkt_num": evt['pkt_num'],
            "msg": f"{evt['label']} at {evt['ts']} — {evt['src']} → {evt['dst']}",
        })

    return findings


def build_report(
    pcap_path: str,
    user_filter: str | None = None,
    progress_callback: Callable[[int, int, str], None] | None = None,
    set_context: bool = True,
) -> dict:
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    uf = user_filter.strip() if user_filter else None
    total_steps = 4
    done_steps = 0
    if progress_callback:
        progress_callback(done_steps, total_steps, os.path.basename(pcap_path))

    with ThreadPoolExecutor() as ex:
        flow_future     = ex.submit(get_flows, pcap_path, uf)
        proto_future    = ex.submit(_protocol_summary, pcap_path, uf)
        count_future    = ex.submit(get_packet_count, pcap_path, uf)
        findings_future = ex.submit(_detect_findings_single_pass, pcap_path, uf)

        findings = findings_future.result()
        done_steps += 1
        if progress_callback:
            progress_callback(done_steps, total_steps, "findings")

        flows         = flow_future.result()
        done_steps += 1
        if progress_callback:
            progress_callback(done_steps, total_steps, "flows")

        proto_summary = proto_future.result()
        done_steps += 1
        if progress_callback:
            progress_callback(done_steps, total_steps, "protocol_summary")

        total_packets = count_future.result()
        done_steps += 1
        if progress_callback:
            progress_callback(done_steps, total_steps, "packet_count")

    severity_order = {"error": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    # Set pcap path so smart_query can answer per-packet questions in Assistant.
    # Disabled for parallel multi-file aggregation to avoid global-state races.
    if set_context:
        set_pcap(pcap_path)

    return {
        "total_packets": total_packets,
        "flows":         flows,
        "findings":      findings,
        "protocol_summary": proto_summary,
        "user_filter":   uf or "",
    }


def build_multi_report(
    source_path: str,
    user_filter: str | None = None,
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> dict:
    """Analyze every .pcap/.pcapng file inside a zip archive or folder.

    Each finding is tagged with ``file_num`` (1-based) and ``file_name``.
    """
    uf = user_filter.strip() if user_filter else None

    # ── resolve PCAP list ──────────────────────────────────────────────────
    tmp_dir: str | None = None
    if zipfile.is_zipfile(source_path):
        tmp_dir = tempfile.mkdtemp(prefix="pcap_analyzer_")
        atexit.register(shutil.rmtree, tmp_dir, True)
        with zipfile.ZipFile(source_path, "r") as zf:
            zf.extractall(tmp_dir)
        base = tmp_dir
    elif os.path.isdir(source_path):
        base = source_path
    else:
        raise ValueError(f"Expected a .zip archive or folder, got: {source_path}")

    pcap_files: list[str] = []
    for root, _dirs, files in os.walk(base):
        for fname in sorted(files):
            if fname.lower().endswith((".pcap", ".pcapng")):
                pcap_files.append(os.path.join(root, fname))
    pcap_files.sort(key=lambda p: os.path.basename(p).lower())

    if not pcap_files:
        raise FileNotFoundError("No .pcap / .pcapng files found inside the archive or folder")

    if progress_callback:
        progress_callback(0, len(pcap_files), "")

    # ── analyse each file (parallel) ───────────────────────────────────────
    all_findings: list[dict] = []
    total_packets = 0
    all_flows: list[dict] = []
    all_protos: dict[str, int] = {}

    completed = 0
    results_by_num: dict[int, tuple[str, dict | None, Exception | None]] = {}
    max_workers = min(8, max(2, os.cpu_count() or 4))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {
            ex.submit(build_report, pcap_path, uf, None, False): (file_num, pcap_path)
            for file_num, pcap_path in enumerate(pcap_files, start=1)
        }
        for fut in as_completed(futs):
            file_num, pcap_path = futs[fut]
            file_name = os.path.basename(pcap_path)
            try:
                rep = fut.result()
                results_by_num[file_num] = (file_name, rep, None)
            except Exception as exc:
                results_by_num[file_num] = (file_name, None, exc)
            completed += 1
            if progress_callback:
                progress_callback(completed, len(pcap_files), file_name)

    # Consume parallel results in deterministic file order.
    for file_num in range(1, len(pcap_files) + 1):
        file_name, rep, exc = results_by_num[file_num]
        if exc is not None or rep is None:
            all_findings.append({
                "severity": "error", "protocol": "System",
                "pkt_num": "", "file_num": file_num,
                "file_name": file_name,
                "msg": f"Failed to analyse file: {exc}",
            })
            continue

        total_packets += rep["total_packets"]
        for f in rep["findings"]:
            f["file_num"] = file_num
            f["file_name"] = file_name
        all_findings.extend(rep["findings"])
        all_flows.extend(rep["flows"])
        for proto, cnt in rep["protocol_summary"].items():
            all_protos[proto] = all_protos.get(proto, 0) + cnt

    severity_order = {"error": 0, "warn": 1, "info": 2}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    return {
        "total_packets":    total_packets,
        "flows":            all_flows,
        "findings":         all_findings,
        "protocol_summary": dict(sorted(all_protos.items(), key=lambda x: x[1], reverse=True)),
        "user_filter":      uf or "",
        "multi_file":       True,
        "file_count":       len(pcap_files),
        "file_names":       [os.path.basename(p) for p in pcap_files],
        "file_paths":       list(pcap_files),
    }


def _protocol_summary(pcap_path: str, user_filter: str | None = None) -> dict:
    text = ''
    for stat_name in ('io,phs', 'phs'):
        try:
            text = tshark_stat(pcap_path, stat_name, user_filter)
            break
        except RuntimeError:
            continue
    counts = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            proto = parts[0].upper()
            counts[proto] = int(parts[1])
    if not counts:
        rows = tshark_fields(pcap_path, None, ['frame.protocols'], user_filter)
        for row in rows:
            proto = (row[0].split(':')[-1]).upper() if row else 'UNKNOWN'
            counts[proto] = counts.get(proto, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))
