"""Per-packet deep fix recommendations based on protocol standards."""
from __future__ import annotations
import re

# ── known port → service mapping ───────────────────────────────────────────────
_PORT_SERVICES = {
    '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
    '53': 'DNS', '80': 'HTTP', '102': 'ISO-TSAP (S7/PLC)',
    '443': 'HTTPS', '502': 'Modbus TCP', '4840': 'OPC-UA',
    '20000': 'DNP3', '47808': 'BACnet/IP',
}

# ── fix database keyed by condition ───────────────────────────────────────────

_FIXES = {
    'tcp_rst': {
        'title': 'TCP RST — Connection Forcibly Closed',
        'severity': 'critical',
        'root_cause': (
            "The destination device sent a RST (Reset) flag, "
            "immediately terminating the connection without a graceful shutdown. "
            "This means the destination **actively rejected** the connection."
        ),
        'causes': [
            "The service/application on the destination port is not running",
            "A firewall rule is blocking or resetting the connection",
            "The server process crashed or restarted mid-session",
            "The port is closed / not listening on the destination",
            "Access control list (ACL) on the device rejected the source IP",
        ],
        'fix_steps': [
            "1. Verify the service is running on the destination:\n"
            "   → Windows: `netstat -an | findstr :<port>`\n"
            "   → Linux:   `ss -tlnp | grep <port>`",
            "2. Test connectivity manually:\n"
            "   → `telnet <dst_ip> <dst_port>`\n"
            "   → If it fails immediately: port is closed",
            "3. Check firewall rules on the destination device",
            "4. Check device/server logs for crash or rejection reason",
            "5. For Modbus (port 502): verify slave Modbus service is enabled and\n"
            "   the client IP is in the allowed list",
        ],
        'reference': 'https://oneuptime.com/blog/post/2026-03-20-diagnose-tcp-rst-packets/view',
    },

    'tcp_retransmission': {
        'title': 'TCP Retransmission — Packet Loss Detected',
        'severity': 'warning',
        'root_cause': (
            "The sender did not receive an ACK for a previously sent packet within "
            "the timeout period, so it resent the data. This indicates packet loss "
            "somewhere between the two devices."
        ),
        'causes': [
            "Poor cable quality or loose connector",
            "Switch port errors (duplex mismatch, CRC errors)",
            "Network congestion — link is saturated",
            "Faulty network card (NIC) or driver issue",
            "Wireless interference (if using Wi-Fi)",
        ],
        'fix_steps': [
            "1. Check switch port error counters:\n"
            "   → Look for CRC errors, input/output errors on the switch port",
            "2. Verify cable quality — replace cable and retest",
            "3. Check for duplex mismatch:\n"
            "   → Both ends should be Full Duplex at same speed",
            "4. Monitor link utilization — if >70%, consider QoS or bandwidth upgrade",
            "5. Update NIC driver on both source and destination",
        ],
        'reference': 'https://medium.com/obkio/resolving-network-failures-its-not-down-but-it-s-slow-253ef53090b5',
    },

    'tcp_zero_window': {
        'title': 'TCP Zero Window — Receiver Buffer Saturated',
        'severity': 'critical',
        'root_cause': (
            "The receiving device's TCP buffer is completely full. It cannot accept "
            "any more data and is telling the sender to pause transmission."
        ),
        'causes': [
            "Application on receiver is processing data too slowly",
            "TCP receive buffer is too small for the data rate",
            "High CPU load on the receiving device",
            "Memory shortage on the receiving device",
        ],
        'fix_steps': [
            "1. Reduce polling/sending rate from the source device",
            "2. Check CPU and memory usage on the receiving device",
            "3. Increase TCP receive buffer size:\n"
            "   → Windows: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\n"
            "   → Set TcpWindowSize = 65535 or higher",
            "4. Upgrade device firmware if available",
            "5. If Modbus/BACnet: add delay between consecutive requests",
        ],
        'reference': 'https://intronetworks.cs.luc.edu/1/html/tcp.html',
    },

    'tcp_syn_no_response': {
        'title': 'TCP SYN — No Response (Connection Timeout)',
        'severity': 'critical',
        'root_cause': (
            "A SYN packet was sent to initiate a connection but no SYN-ACK "
            "was received. The destination either dropped the packet or is unreachable."
        ),
        'causes': [
            "Destination device is offline or unreachable",
            "Firewall silently dropping the SYN (no RST sent)",
            "Wrong IP address or port in configuration",
            "Routing issue — packet not reaching destination",
        ],
        'fix_steps': [
            "1. Ping the destination: `ping <dst_ip>`",
            "2. If ping works but port fails: firewall is blocking it",
            "3. Verify the destination IP and port in your configuration",
            "4. Check routing: `tracert <dst_ip>` to find where it drops",
            "5. Check firewall rules on the destination",
        ],
        'reference': 'https://intronetworks.cs.luc.edu/1/html/tcp.html',
    },

    'modbus_exception': {
        'title': 'Modbus Exception Response',
        'severity': 'critical',
        'root_cause': "The Modbus slave device returned an exception code indicating it could not process the request.",
        'causes': [],
        'fix_steps': [],
        'reference': 'https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf',
    },

    'icmp_unreachable': {
        'title': 'ICMP Destination Unreachable',
        'severity': 'critical',
        'root_cause': "A router or the destination device reported that it cannot deliver the packet.",
        'causes': [
            "Port is closed on destination (code 3: Port unreachable)",
            "Host is offline or wrong subnet (code 1: Host unreachable)",
            "Firewall administratively blocking (code 13)",
        ],
        'fix_steps': [
            "1. Check the ICMP code for specific reason (port, host, network, etc.)",
            "2. For port unreachable: verify the service is running on that port",
            "3. For host unreachable: check device is powered and on correct subnet",
            "4. For administratively prohibited: review firewall policy",
        ],
        'reference': 'https://www.rfc-editor.org/rfc/rfc792',
    },

    'dns_nxdomain': {
        'title': 'DNS NXDOMAIN — Hostname Not Found',
        'severity': 'warning',
        'root_cause': "The DNS server confirmed the queried hostname does not exist in DNS.",
        'causes': [
            "Hostname is misspelled in application configuration",
            "DNS record was deleted or not yet created",
            "Wrong DNS server being queried",
        ],
        'fix_steps': [
            "1. Verify the hostname spelling in application config",
            "2. Check if DNS record exists:\n"
            "   → `nslookup <hostname>`\n"
            "   → `Resolve-DnsName <hostname>`",
            "3. If DNS record is missing: add an A record in the DNS server",
            "4. Temporary workaround: add entry to hosts file\n"
            "   → C:\\Windows\\System32\\drivers\\etc\\hosts",
        ],
        'reference': 'https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml',
    },

    'generic': {
        'title': 'Packet Diagnostic',
        'severity': 'info',
        'root_cause': "Packet analyzed — no specific known issue pattern matched.",
        'causes': [],
        'fix_steps': [
            "Review the packet's source, destination, protocol, and flags",
            "Compare with surrounding packets for context",
            "Check application logs on both source and destination devices",
        ],
        'reference': '',
    },
}


def diagnose_packet(pkt: dict) -> dict:
    """
    Given a packet detail dict from smart_query.get_packet_detail(),
    return a fix recommendation dict.
    """
    if not pkt:
        return {'error': 'Packet not found in capture file.'}

    num      = pkt.get('number', '?')
    src      = pkt.get('src', '?')
    dst      = pkt.get('dst', '?')
    sport    = pkt.get('tcp_sport', pkt.get('udp_sport', ''))
    dport    = pkt.get('tcp_dport', pkt.get('udp_dport', ''))
    protos   = pkt.get('protocols', '')

    def _flag(key): return pkt.get(key, '').lower() in ('1', 'true', 'yes')

    rst   = _flag('rst')
    syn   = _flag('syn')
    fin   = _flag('fin')
    retx  = _flag('retransmission')
    zwin  = _flag('zero_window')
    lost  = _flag('lost_segment')
    http_code = pkt.get('http_code', '')
    dns_rcode = pkt.get('dns_rcode', '')
    dns_resp  = pkt.get('dns_response', '')

    service = _PORT_SERVICES.get(dport, _PORT_SERVICES.get(sport, f'port {dport or sport}'))

    # ── match condition ────────────────────────────────────────────────────────
    if rst:
        fix = dict(_FIXES['tcp_rst'])
        fix['packet_summary'] = (
            f"Packet #{num}:  {src}:{sport} → {dst}:{dport}  [RST, ACK]\n"
            f"Service on port {dport}: {service}"
        )
        fix['context_note'] = (
            f"Port {dport} ({service}) on {dst} rejected the connection from {src}. "
            f"Check if {service} is running on {dst}."
        )
        return fix

    if retx:
        fix = dict(_FIXES['tcp_retransmission'])
        fix['packet_summary'] = f"Packet #{num}: {src} → {dst} [Retransmission]"
        fix['context_note']   = f"Original packet was lost between {src} and {dst}."
        return fix

    if zwin:
        fix = dict(_FIXES['tcp_zero_window'])
        fix['packet_summary'] = f"Packet #{num}: {dst} sent Zero Window to {src}"
        fix['context_note']   = f"Device {dst} cannot accept more data right now."
        return fix

    if syn and not pkt.get('ack'):
        fix = dict(_FIXES['tcp_syn_no_response'])
        fix['packet_summary'] = f"Packet #{num}: {src} → {dst}:{dport} [SYN]"
        fix['context_note']   = (
            f"SYN sent to {dst}:{dport} ({service}). "
            f"Check the next few packets to see if SYN-ACK was received."
        )
        return fix

    if http_code and int(http_code or 0) >= 400:
        code = int(http_code)
        sev  = 'critical' if code >= 500 else 'warning'
        meanings = {
            400: "Client sent malformed request data.",
            401: "Authentication required — credentials missing or wrong.",
            403: "Client lacks permission to access this resource.",
            404: "Resource not found on the server.",
            500: "Server-side crash or internal error.",
            502: "Upstream server returned invalid response.",
            503: "Server overloaded or down for maintenance.",
        }
        return {
            'title': f'HTTP {code} Error',
            'severity': sev,
            'packet_summary': f"Packet #{num}: HTTP {code} from {src} to {dst}",
            'root_cause': meanings.get(code, f"HTTP error {code}."),
            'context_note': '',
            'causes': [],
            'fix_steps': [
                f"1. Check server logs on {src} for the specific error",
                "2. Verify the request URL and parameters are correct",
                "3. Check server resource availability (disk, memory, CPU)",
            ],
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status',
        }

    if dns_resp == '1' and dns_rcode not in ('', '0'):
        rcode_map = {'2': 'SERVFAIL', '3': 'NXDOMAIN', '5': 'REFUSED'}
        label = rcode_map.get(dns_rcode, f'rcode={dns_rcode}')
        fix = dict(_FIXES['dns_nxdomain'])
        fix['title'] = f'DNS {label}'
        fix['packet_summary'] = f"Packet #{num}: DNS {label} for '{pkt.get('dns_name', '?')}'"
        fix['context_note']   = f"Hostname '{pkt.get('dns_name', '?')}' could not be resolved."
        return fix

    if 'icmp' in protos.lower():
        fix = dict(_FIXES['icmp_unreachable'])
        fix['packet_summary'] = f"Packet #{num}: ICMP from {src} to {dst}"
        fix['context_note']   = ''
        return fix

    # fallback
    fix = dict(_FIXES['generic'])
    fix['packet_summary'] = (
        f"Packet #{num}: {src}:{sport} → {dst}:{dport}  "
        f"[{protos.split(':')[-1].upper()}]"
    )
    fix['context_note'] = ''
    return fix
