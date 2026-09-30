from __future__ import annotations
import os
import subprocess
import shutil
from functools import lru_cache

_TSHARK_FALLBACK = r"C:\Program Files\Wireshark\tshark.exe"


def find_tshark() -> str:
    t = shutil.which('tshark')
    if t:
        return t
    if os.path.exists(_TSHARK_FALLBACK):
        return _TSHARK_FALLBACK
    raise FileNotFoundError("tshark not found — install Wireshark and add it to PATH")


@lru_cache(maxsize=1)
def tshark_available_fields() -> frozenset[str]:
    """Return field names supported by the installed tshark version."""
    r = subprocess.run(
        [find_tshark(), '-G', 'fields'], capture_output=True, text=True,
        encoding='utf-8', errors='replace'
    )
    if r.returncode != 0:
        raise RuntimeError(f"tshark field discovery failed: {(r.stderr or r.stdout).strip()}")
    fields = set()
    for line in r.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) > 2 and parts[0] == 'F':
            fields.add(parts[2])
    return frozenset(fields)


def _combine(user_filter: str | None, detector_filter: str | None) -> str | None:
    u = (user_filter or '').strip()
    d = (detector_filter or '').strip()
    if u and d:
        return f"({u}) && ({d})"
    return u or d or None


def tshark_fields(pcap_path: str, detector_filter: str | None,
                  fields: list[str], user_filter: str | None = None) -> list[list[str]]:
    """Single fast tshark pass; AND-combines user_filter with detector_filter."""
    combined = _combine(user_filter, detector_filter)
    args = [find_tshark(), '-r', pcap_path, '-T', 'fields',
            '-E', 'separator=\x01', '-E', 'occurrence=f']
    if combined:
        args += ['-Y', combined]
    for f in fields:
        args += ['-e', f]
    r = subprocess.run(args, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "unknown tshark error").strip()
        raise RuntimeError(f"tshark fields query failed: {detail}")
    rows = []
    for line in r.stdout.splitlines():
        if line.strip():
            rows.append(line.split('\x01'))
    return rows


def tshark_packet_detail(pcap_path: str, packet_number: str) -> str:
    """Return Wireshark's full decoded detail for one packet."""
    args = [find_tshark(), '-r', pcap_path, '-Y', f'frame.number == {packet_number}', '-V']
    r = subprocess.run(
        args, capture_output=True, text=True,
        encoding='utf-8', errors='replace'
    )
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "unknown tshark error").strip()
        raise RuntimeError(f"tshark packet detail query failed: {detail}")
    return r.stdout.strip()


def tshark_stat(pcap_path: str, stat: str, user_filter: str | None = None) -> str:
    """Run tshark -z <stat>, optionally pre-filtered."""
    args = [find_tshark(), '-r', pcap_path, '-q', '-z', stat]
    if user_filter:
        args += ['-Y', user_filter.strip()]
    r = subprocess.run(args, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return r.stdout


def get_packet_count(pcap_path: str, user_filter: str | None = None) -> int:
    if not user_filter:
        capinfos = shutil.which('capinfos') or r"C:\Program Files\Wireshark\capinfos.exe"
        if os.path.exists(capinfos):
            r = subprocess.run([capinfos, pcap_path], capture_output=True,
                               text=True, encoding='utf-8', errors='replace')
            for line in r.stdout.splitlines():
                if 'Number of packets' in line and '=' in line:
                    try:
                        return int(line.split('=')[1].strip().replace(',', ''))
                    except (ValueError, IndexError):
                        pass
                elif 'Number of packets' in line and ':' in line:
                    raw = line.split(':')[1].strip().split()[0].replace(',', '')
                    try:
                        mult = 1000 if line.strip().endswith('k') else 1
                        return int(float(raw.rstrip('k')) * mult)
                    except (ValueError, IndexError):
                        pass
    # filtered count or capinfos fallback: count via tshark
    rows = tshark_fields(pcap_path, None, ['frame.number'], user_filter)
    return len(rows)