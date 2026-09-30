# PCAP Analyzer

A desktop network packet analysis tool built for analyzing Wireshark PCAP captures.  
Detects network and protocol anomalies across TCP, Modbus, DNS, TLS, HTTP, BACnet, ICMP, ARP, MQTT, EtherCAT, EtherNet/IP (CIP), and PROFINET traffic.

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.12 or later |
| Wireshark (`tshark`) | Any recent version; required for packet analysis |
| `capinfos` | Optional; packet counts fall back to `tshark` when it is unavailable |
| Npcap | Required on Windows for live capture only |

---

## Installation

1. Install Wireshark from https://www.wireshark.org/download.html  
   Make sure `tshark.exe` is on your system PATH, or installed at:  
   `C:\Program Files\Wireshark\`. If Wireshark is installed elsewhere, add its folder to PATH. `capinfos.exe` is optional because the tool can use `tshark` to count packets instead. For live capture on Windows, install Npcap from https://npcap.com.

2. Install Python dependencies:
   ```
   pip install PyQt6 scapy pyshark
   ```
## Running the Tool

```
cd pcap-analyzer
python main.py
```
---
## Features

### Offline Analysis
- Drop a `.pcap`, `.pcapng`, `.zip`, or folder of captures
- Optional Wireshark display filter (e.g. `tcp`, `modbus`, `ip.addr==192.168.1.10`)
- Click **Analyze** to run full analysis

### Findings Tab
Shows all detected issues sorted by severity:

| Severity | Color | Meaning |
|---|---|---|
| ERROR | Red | An error-level condition was detected; investigate |
| WARN | Orange | A possible issue was detected; review |
| INFO | Blue | Informational observation |

### Detection Coverage

| Protocol | What is detected |
|---|---|
| TCP | Retransmissions, fast and spurious retransmissions, RST activity, zero window, window full, lost segments, duplicate ACK |
| MODBUS | Exception codes and TCP retransmissions on port 502, which may indicate delay or packet loss |
| HTTP | 4xx/5xx responses, slow responses (>1s) |
| DNS | NXDOMAIN, SERVFAIL, REFUSED, slow responses (>0.5s) |
| TLS | Fatal/warning alerts, deprecated TLS versions (1.0, 1.1) |
| BACnet | APDU Error, Reject, Abort, NPDU network-layer messages |
| IPv4 ICMP | Destination unreachable, TTL exceeded |
| ARP | Requests whose target IP has no ARP reply observed in the capture |
| MQTT | Error and warning reason codes |
| EtherCAT | AL status errors |
| EtherNet/IP (CIP) | General status errors |
| PROFINET | Status and expert diagnostic errors |
| General | Malformed-packet indications reported by Wireshark/tshark |

### Severity Scoring
Severity is assigned by each detector's rules. Some protocol errors receive a severity directly; TCP RST and retransmission findings also consider event counts. These counts are not measured over a time window, so the scoring does not represent an event rate. Severity is a triage aid and does not by itself prove root cause or impact.

### Other Tabs
- **Summary** — Overview of the analyzed capture
- **Flows** — Top TCP/UDP conversations by packet count
- **Protocols** — Protocol distribution chart
- **Query** — Build and run custom tshark display filters
- **Compare** — Compare traffic behavior between two PCAP captures, or between a PCAP capture and live traffic
- **Freeze** — Run a path check for selected protocols between source and destination devices
- **Live** — Capture live traffic and compare behavior in real time

### Calculator

| Mode | Enter | What it shows | Use it for |
|---|---|---|---|
| Consecutive packets | Two adjacent packet numbers, e.g. `847` and `848` | The two packets, their time difference, and summary statistics such as bytes and throughput | Checking the gap between a packet and the next packet |
| Packet range | A starting and ending packet number, e.g. `100` to `500` | Every packet in the inclusive range, per-packet timing differences, and summary statistics such as packet count, bytes, packets per second, and throughput | Reviewing traffic across a section of the capture |

### Multi-file Analysis
Drop a `.zip` archive or a folder containing multiple PCAP files.  
Files are analyzed in parallel using up to 8 workers; this is a concurrency limit, not a limit on the number of files. Each finding is tagged with its source file number and filename.

---

## Export

Click **Export Findings** after analysis to save ERROR and WARN findings as:
- `.txt` — Plain text log
- `.csv` — Spreadsheet-compatible
- `.html` — Formatted report

INFO findings are not included in exported reports.

---

## Key Project Files

```
pcap-analyzer/
├── main.py                  Entry point
├── requirements.txt         Python dependencies
├── analyzer/
│   ├── capture.py           tshark/capinfos subprocess layer
│   ├── live_capture.py      Live packet capture
│   ├── path_check.py        Network path-check logic
│   ├── report.py            Main detection and analysis engine
│   ├── flows.py             TCP/UDP conversation extraction
│   └── behavior.py          Behavioral profiling for comparison
└── ui/
    ├── main_window.py        Main application window
    ├── compare_panel.py      Behavior comparison panel
    ├── live_panel.py         Live capture panel
   ├── path_check_panel.py   Freeze/path-check interface
    ├── packet_inspector.py   Packet detail inspector
    ├── query_builder.py      Custom query builder
    └── calculator.py         Packet calculator
```
