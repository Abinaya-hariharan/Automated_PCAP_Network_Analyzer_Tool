from __future__ import annotations
from analyzer.capture import tshark_stat


def get_flows(pcap_path: str, user_filter: str | None = None) -> list[dict]:
    tcp_flows = _parse_conv(tshark_stat(pcap_path, 'conv,tcp', user_filter), 'TCP')
    udp_flows = _parse_conv(tshark_stat(pcap_path, 'conv,udp', user_filter), 'UDP')
    flows = tcp_flows + udp_flows
    flows.sort(
        key=lambda f: (
            -f.get('pair_total', f['packets']),
            f.get('pair_key', ''),
            0 if f.get('direction') == 'tx' else 1,
        )
    )
    return flows


def _parse_conv(text: str, proto: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        if '<->' not in line and '<=>' not in line:
            continue
        parts = line.split()
        try:
            sep = next(i for i, p in enumerate(parts) if p in ('<->', '<=>') )
        except StopIteration:
            continue
        if sep < 1 or sep + 1 >= len(parts):
            continue
        src = parts[sep - 1]
        dst = parts[sep + 1]
        nums = [int(p.replace(',', '')) for p in parts[sep + 2:] if p.replace(',', '').isdigit()]

        # tshark conv output typically has: A->B pkts, A->B bytes, B->A pkts, B->A bytes, ...
        if len(nums) >= 3:
            a_to_b = nums[0]
            b_to_a = nums[2]
        elif len(nums) >= 2:
            a_to_b = nums[0]
            b_to_a = nums[1]
        elif len(nums) == 1:
            a_to_b = nums[0]
            b_to_a = 0
        else:
            a_to_b = 0
            b_to_a = 0

        lo, hi = sorted((src, dst))
        pair_key = f"{proto}|{lo}|{hi}"
        pair_total = a_to_b + b_to_a

        rows.append({
            'src': src,
            'dst': dst,
            'protocol': proto,
            'packets': a_to_b,
            'direction': 'tx',
            'pair_key': pair_key,
            'pair_total': pair_total,
        })
        rows.append({
            'src': dst,
            'dst': src,
            'protocol': proto,
            'packets': b_to_a,
            'direction': 'rx',
            'pair_key': pair_key,
            'pair_total': pair_total,
        })
    return rows
