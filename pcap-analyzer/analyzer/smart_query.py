"""Smart targeted tshark pre-queries for per-packet diagnostics."""
from __future__ import annotations
import re
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

_PCAP_FILE: str = ""


def set_pcap(path: str):
    global _PCAP_FILE
    _PCAP_FILE = path


def get_pcap() -> str:
    return _PCAP_FILE


def _find_tshark():
    import shutil, os
    t = shutil.which('tshark')
    if t:
        return t
    default = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(default):
        return default
    raise FileNotFoundError("tshark not found")


def _run(filter_expr: str, fields: list[str], limit: int = 20) -> list[list[str]]:
    if not _PCAP_FILE:
        return []
    args = [_find_tshark(), '-r', _PCAP_FILE, '-T', 'fields',
            '-E', 'separator=|', '-E', 'occurrence=f',
            '-Y', filter_expr, '-c', str(limit)]
    for f in fields:
        args += ['-e', f]
    r = subprocess.run(args, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return [line.split('|') for line in r.stdout.splitlines() if line.strip()]


def _run_pkt(frame_num: int, fields: list[str]) -> list[str] | None:
    if not _PCAP_FILE:
        return None
    # -c frame_num tells tshark to stop after reading that many packets,
    # so it never scans past the target frame in a large file.
    args = [_find_tshark(), '-r', _PCAP_FILE, '-T', 'fields',
            '-E', 'separator=|', '-E', 'occurrence=f',
            '-Y', f'frame.number=={frame_num}',
            '-c', str(frame_num)]
    for f in fields:
        args += ['-e', f]
    r = subprocess.run(args, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    for line in r.stdout.splitlines():
        if line.strip():
            return line.split('|')
    return None


def _capture_paths() -> list[str]:
    if os.path.isfile(_PCAP_FILE):
        return [_PCAP_FILE]
    if os.path.isdir(_PCAP_FILE):
        return sorted(
            os.path.join(root, name)
            for root, _, names in os.walk(_PCAP_FILE)
            for name in names
            if os.path.splitext(name)[1].lower() in (".pcap", ".pcapng")
        )
    return []


def _verbose_detail(frame_num: int, capture_path: str) -> str:
    args = [_find_tshark(), "-r", capture_path, "-Y",
            f"frame.number == {frame_num}", "-V", "-c", str(frame_num)]
    result = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60,
    )
    return result.stdout.strip()


def get_packet_detail(frame_num: int) -> dict:
    """Return a dict of decoded fields for one packet."""
    row = _run_pkt(frame_num, [
        'frame.number', 'frame.time_relative', 'frame.len',
        'ip.src', 'ip.dst', 'ip.proto',
        'tcp.srcport', 'tcp.dstport', 'tcp.flags',
        'tcp.seq', 'tcp.ack', 'tcp.len',
        'tcp.analysis.retransmission', 'tcp.analysis.zero_window',
        'tcp.analysis.lost_segment', 'tcp.flags.reset',
        'tcp.flags.syn', 'tcp.flags.fin', 'tcp.flags.ack',
        'udp.srcport', 'udp.dstport',
        'http.response.code', 'http.request.method', 'http.request.uri',
        'dns.qry.name', 'dns.flags.rcode', 'dns.flags.response',
        'frame.protocols',
    ])
    if not row:
        return {}
    keys = ['number', 'time', 'length', 'src', 'dst', 'ip_proto',
            'tcp_sport', 'tcp_dport', 'tcp_flags',
            'tcp_seq', 'tcp_ack', 'tcp_payload',
            'retransmission', 'zero_window', 'lost_segment', 'rst',
            'syn', 'fin', 'ack',
            'udp_sport', 'udp_dport',
            'http_code', 'http_method', 'http_uri',
            'dns_name', 'dns_rcode', 'dns_response',
            'protocols']
    row += [''] * (len(keys) - len(row))
    return dict(zip(keys, row))


def get_context_packets(frame_num: int, window: int = 8) -> list[dict]:
    """Return packets around frame_num for context."""
    start = max(1, frame_num - window)
    end   = frame_num + window
    if not _PCAP_FILE:
        return []
    args = [_find_tshark(), '-r', _PCAP_FILE, '-T', 'fields',
            '-E', 'separator=|', '-E', 'occurrence=f',
            '-Y', f'frame.number >= {start} && frame.number <= {end}',
            '-e', 'frame.number', '-e', 'frame.time_relative',
            '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.flags', '-e', 'frame.protocols']
    r = subprocess.run(args, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    result = []
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        row = line.split('|')
        row += [''] * 6
        flags = []
        try:
            fv = int(row[4], 16)
            if fv & 0x02: flags.append('SYN')
            if fv & 0x10: flags.append('ACK')
            if fv & 0x04: flags.append('RST')
            if fv & 0x01: flags.append('FIN')
            if fv & 0x08: flags.append('PSH')
        except ValueError:
            pass
        result.append({
            'num': row[0], 'time': row[1], 'src': row[2], 'dst': row[3],
            'flags': ','.join(flags), 'proto': row[5].split(':')[-1].upper(),
            'is_target': row[0] == str(frame_num),
        })
    return result


def get_context_for_question(question: str) -> str:
    """Detect packet numbers/IPs in question and inject relevant packet data."""
    if not _PCAP_FILE:
        return ""
    snippets = []
    ql = question.lower()

    # Extract packet numbers (handles "38th", "packet 38", "pkt 38")
    pkt_nums = [int(n) for n in re.findall(r"\b(\d+)(?:st|nd|rd|th)?\b", question)
                if 0 < int(n) < 10_000_000]

    # Extract IPs
    ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", question)

    capture_paths = _capture_paths()
    if not capture_paths:
        return ""

    # Fetch requested packets and their verbose Wireshark decode.
    def _fetch_pkt(num: int) -> tuple[int, dict, list[dict]]:
        for capture_path in capture_paths:
            global _PCAP_FILE
            original = _PCAP_FILE
            _PCAP_FILE = capture_path
            try:
                pkt = get_packet_detail(num)
                if pkt:
                    pkt["file_name"] = os.path.basename(capture_path)
                    pkt["verbose"] = _verbose_detail(num, capture_path)
                    ctx = get_context_packets(num, window=5)
                    return num, pkt, ctx
            finally:
                _PCAP_FILE = original
        return num, {}, []

    with ThreadPoolExecutor(max_workers=min(5, len(pkt_nums) or 1)) as ex:
        futures = {ex.submit(_fetch_pkt, num): num for num in pkt_nums[:5]}
        results = {}
        for fut in as_completed(futures):
            num, pkt, ctx = fut.result()
            results[num] = (pkt, ctx)

    for num in pkt_nums[:5]:
        pkt, ctx = results.get(num, ({}, []))
        if pkt:
            lines = [f"\nPacket #{num} full details:"]
            if pkt.get("file_name"):
                lines.append(f"  Source file: {pkt['file_name']}")
            for k, v in pkt.items():
                if v and k not in ('protocols', 'verbose'):
                    lines.append(f"  {k}: {v}")
            if pkt.get("verbose"):
                lines.append("\n  Full Wireshark decoded packet:\n" + pkt["verbose"][:16000])
            if ctx:
                lines.append(f"  Context (surrounding packets):")
                for p in ctx:
                    marker = " ← THIS PACKET" if p['is_target'] else ""
                    lines.append(
                        f"    #{p['num']} {p['time']}s  {p['src']}→{p['dst']}"
                        f"  [{p['proto']}] [{p['flags']}]{marker}")
            snippets.append("\n".join(lines))

    # IP-specific context
    if ips and not pkt_nums:
        for ip in ips[:2]:
            rows = _run(f"ip.src == {ip} || ip.dst == {ip}",
                        ['frame.number', 'frame.time_relative', 'ip.src',
                         'ip.dst', 'tcp.flags.reset', 'frame.protocols'], limit=15)
            if rows:
                lines = [f"\nPackets involving {ip}:"]
                for r in rows:
                    r += [''] * 6
                    rst = " [RST]" if r[4] == '1' else ""
                    lines.append(f"  #{r[0]} {r[1]}s  {r[2]}→{r[3]}  {r[5].split(':')[-1].upper()}{rst}")
                snippets.append("\n".join(lines))

    return "\n".join(snippets)
