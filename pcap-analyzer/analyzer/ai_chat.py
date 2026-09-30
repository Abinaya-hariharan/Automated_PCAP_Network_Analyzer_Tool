"""Groq AI integration for the PCAP Assistant."""
import os, re, json, tempfile
from groq import Groq

_MODEL_CANDIDATES = [
    # Prefer models currently exposed by Groq; unavailable IDs are skipped below.
    "llama-3.3-70b-versatile",
    "openai/gpt-oss-120b",
    "qwen/qwen3-32b",
]
_DEPRECATED_MODELS = {
    "mixtral-8x7b-32768",
    "llama-3.1-8b-instant",
}
_TS_FILE = os.path.join(tempfile.gettempdir(), "pcap_analyzer_timestamps.json")
_CFG_KEY = os.path.join(os.path.dirname(__file__), '..', '.groq_key')


def _candidate_models() -> list[str]:
    env_model = (os.getenv("GROQ_MODEL") or "").strip()
    if env_model in _DEPRECATED_MODELS:
        env_model = ""
    if not env_model:
        return list(_MODEL_CANDIDATES)
    # Prefer explicit override first while still keeping safe fallbacks.
    return [env_model] + [m for m in _MODEL_CANDIDATES if m != env_model]


def _is_model_unavailable(err_text: str) -> bool:
    t = err_text.lower()
    hints = (
        "decommissioned",
        "no longer supported",
        "model not found",
        "does not exist",
        "invalid model",
        "unknown model",
    )
    return any(h in t for h in hints)


def save_key(key: str):
    with open(_CFG_KEY, 'w') as f:
        f.write(key.strip())


def load_key() -> str:
    try:
        with open(_CFG_KEY) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ''


def save_timestamps(timestamps: dict):
    with open(_TS_FILE, 'w') as f:
        json.dump({str(k): v for k, v in timestamps.items()}, f)


def _load_timestamps() -> dict:
    try:
        with open(_TS_FILE) as f:
            return {int(k): float(v) for k, v in json.load(f).items()}
    except (FileNotFoundError, ValueError, KeyError):
        return {}


def _extract_packet_nums(text: str) -> list:
    return [int(n) for n in re.findall(r"\b(\d+)(?:st|nd|rd|th)?\b", text)
            if 0 < int(n) < 10_000_000]


def _time_calc_snippet(packet_nums: list) -> str:
    ts = _load_timestamps()
    if not ts or len(packet_nums) < 2:
        return ""
    found = {n: ts[n] for n in packet_nums if n in ts}
    if len(found) < 2:
        return ""
    lines = ["\nTimestamps for requested packets:"]
    for n, t in sorted(found.items()):
        lines.append(f"  Packet {n}: {t:.6f}s")
    nums = sorted(found.keys())
    diff = found[nums[-1]] - found[nums[0]]
    lines.append(f"Time difference: {diff:.6f}s = {diff*1000:.3f} ms")
    return "\n".join(lines)


def _smart_context(question: str) -> str:
    """Run targeted tshark query for packet-specific questions."""
    try:
        from analyzer.smart_query import get_context_for_question
        return get_context_for_question(question)
    except Exception:
        return ""


def _build_context(report: dict) -> str:
    lines = []
    lines.append(f"Total packets: {report.get('total_packets', 0):,}")
    uf = report.get('user_filter', '')
    if uf:
        lines.append(f"Filter: {uf}")
    protos = report.get('protocol_summary', {})
    if protos:
        lines.append("Protocols: " + ", ".join(f"{p}({c})" for p, c in list(protos.items())[:6]))
    flows = report.get('flows', [])
    if flows:
        lines.append(f"\nTop flows ({len(flows)} total):")
        for fl in flows[:8]:
            lines.append(f"  {fl['src']} <-> {fl['dst']}  {fl['packets']} pkts")
    findings = report.get('findings', [])
    if findings:
        errors   = [f for f in findings if f['severity'] == 'error']
        warnings = [f for f in findings if f['severity'] == 'warn']
        lines.append(f"\nFindings: {len(errors)} errors, {len(warnings)} warnings")
        seen, uniq = set(), []
        for f in errors:
            key = re.sub(r'at \d+\.\d+s', '', f['msg'])
            if key not in seen:
                seen.add(key); uniq.append(f)
        for f in uniq[:30]:
            lines.append(f"  [ERROR] [{f['protocol']}] {f['msg']}")
        seen_w, uniq_w = set(), []
        for f in warnings:
            key = re.sub(r'at \d+\.\d+s', '', f['msg'])
            if key not in seen_w:
                seen_w.add(key); uniq_w.append(f)
        for f in uniq_w[:15]:
            lines.append(f"  [WARN] [{f['protocol']}] {f['msg']}")
    return "\n".join(lines)


def ask(question: str, report: dict, api_key: str, history: list) -> str:
    client   = Groq(api_key=api_key)
    pkt_nums = _extract_packet_nums(question)
    ts_note  = _time_calc_snippet(pkt_nums) if len(pkt_nums) >= 2 else ""
    smart    = _smart_context(question)
    system   = (
        "You are a senior network engineer and packet analysis expert.\n"
        "The user has uploaded a Wireshark capture file. Here is the full analysis:\n\n"
        + _build_context(report)
        + ts_note + smart
        + "\n\n"
        "RULES FOR YOUR ANSWERS:\n"
        "1. Be SPECIFIC — always reference actual IP addresses, packet numbers, ports, and error counts from the data above. Never say 'the device' — say '192.168.0.10'.\n"
        "2. Give ROOT CAUSE — explain WHY it is happening, not just what is happening.\n"
        "3. Give EXACT FIX STEPS — numbered, actionable steps a developer can execute immediately.\n"
        "4. Reference ACTUAL DATA — if there are 70 RST packets from 192.168.0.10 to port 21, say that exactly.\n"
        "5. If asked about a specific packet number, use the packet detail data provided above.\n"
        "6. Never give generic textbook answers — always tie your answer to the specific capture data.\n"
        "7. Structure every answer with: Observed evidence, likely cause, impact, and numbered next steps.\n"
        "8. Include exact values from the capture whenever available. If the data is unavailable, say so explicitly instead of inventing it.\n"
        "9. For packet questions, explain the relevant protocol fields and packet sequence in detail.\n"
        "10. Give a thorough answer of at least 3-5 sentences for troubleshooting questions."
    )
    messages = [{"role": "system", "content": system}]
    for turn in history:
        messages.append({"role": turn["role"], "content": turn["text"]})
    messages.append({"role": "user", "content": question})

    tried: list[str] = []
    last_err: Exception | None = None
    for model_name in _candidate_models():
        tried.append(model_name)
        try:
            resp = client.chat.completions.create(
                model=model_name, messages=messages, max_tokens=2048)
            return resp.choices[0].message.content
        except Exception as exc:
            last_err = exc
            if _is_model_unavailable(str(exc)):
                continue
            raise

    raise RuntimeError(
        "No available Groq model could be used. "
        f"Tried: {', '.join(tried)}. "
        f"Last error: {last_err}"
    )
