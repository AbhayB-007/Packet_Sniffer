"""
display.py — Colorized Terminal Output for Packet Sniffer
Handles all formatted printing with protocol-color coding.
"""

import textwrap
import os

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_SUPPORTED = True
except ImportError:
    COLOR_SUPPORTED = False

# ─────────────────────────────────────────────
#  Color helpers — degrade gracefully if colorama is missing
# ─────────────────────────────────────────────

_NO_COLOR = os.environ.get('NO_COLOR', '')  # respect NO_COLOR env var

def _c(code):
    if not COLOR_SUPPORTED or _NO_COLOR:
        return ''
    return code

C = {
    'reset':   _c('\033[0m'),
    'bold':    _c('\033[1m'),
    'dim':     _c('\033[2m'),

    # Protocol colors
    'eth':     _c('\033[37m'),          # white
    'arp':     _c('\033[95m'),          # magenta
    'ipv4':    _c('\033[36m'),          # cyan
    'ipv6':    _c('\033[96m'),          # bright cyan
    'tcp':     _c('\033[94m'),          # bright blue
    'udp':     _c('\033[92m'),          # bright green
    'icmp':    _c('\033[93m'),          # yellow
    'http':    _c('\033[35m'),          # magenta
    'dns':     _c('\033[96m'),          # bright cyan
    'data':    _c('\033[90m'),          # dark gray
    'label':   _c('\033[90m'),          # dark gray
    'sep':     _c('\033[90m'),          # dark gray
    'error':   _c('\033[91m'),          # bright red
    'success': _c('\033[92m'),          # bright green
    'header':  _c('\033[1m\033[36m'),   # bold cyan
    'count':   _c('\033[1m\033[97m'),   # bold white
}


# ─────────────────────────────────────────────
#  Structural helpers
# ─────────────────────────────────────────────

LINE_WIDTH = 88

def _sep(char='─'):
    print(C['sep'] + char * LINE_WIDTH + C['reset'])


def print_banner():
    """Print the startup banner."""
    print()
    _sep('═')
    print(C['header'] +
          '  ██████╗ ██╗  ██╗███████╗████████╗    '
          '███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ ' + C['reset'])
    print(C['header'] +
          '  ██╔══██╗██║ ██╔╝██╔════╝╚══██╔══╝    '
          '██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗' + C['reset'])
    print(C['header'] +
          '  ██████╔╝█████╔╝ █████╗     ██║       '
          '███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝' + C['reset'])
    print(C['header'] +
          '  ██╔═══╝ ██╔═██╗ ██╔══╝     ██║       '
          '╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗' + C['reset'])
    print(C['header'] +
          '  ██║     ██║  ██╗███████╗   ██║       '
          '███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║' + C['reset'])
    print(C['header'] +
          '  ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝       '
          '╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝' + C['reset'])
    _sep('═')
    print(f"  {C['label']}Press Ctrl+C to stop capture{C['reset']}")
    _sep('═')
    print()


def print_active_filters(args):
    """Print active capture filters if any are set."""
    filters = []
    if args.protocol != 'all':
        filters.append(f"Protocol: {C['bold']}{args.protocol.upper()}{C['reset']}")
    if args.port:
        filters.append(f"Port: {C['bold']}{args.port}{C['reset']}")
    if args.src_ip:
        filters.append(f"Src IP: {C['bold']}{args.src_ip}{C['reset']}")
    if args.dst_ip:
        filters.append(f"Dst IP: {C['bold']}{args.dst_ip}{C['reset']}")
    if args.count:
        filters.append(f"Max packets: {C['bold']}{args.count}{C['reset']}")
    if args.log:
        filters.append(f"Logging to: {C['bold']}{args.log}{C['reset']}")

    if filters:
        print(f"  {C['label']}Active filters —{C['reset']} " + '   '.join(filters))
        _sep()
        print()


def packet_header(count, os_name):
    """Print the per-packet header line."""
    _sep()
    print(f"  {C['count']}Packet #{count}{C['reset']}"
          f"  {C['label']}│{C['reset']}"
          f"  {C['label']}OS: {os_name}{C['reset']}")
    _sep()


def print_summary(count, log_path=None):
    """Print capture-complete summary."""
    print()
    _sep('═')
    print(f"  {C['success']}Capture stopped.{C['reset']}  "
          f"{C['count']}{count}{C['reset']} packets displayed.")
    if log_path:
        print(f"  {C['label']}Log saved →{C['reset']} {log_path}")
    _sep('═')
    print()


# ─────────────────────────────────────────────
#  Protocol printers
# ─────────────────────────────────────────────

def print_ethernet(dest_mac, src_mac, proto_label):
    print(f"  {C['eth']}[ETH]{C['reset']}"
          f"  {C['label']}Dst:{C['reset']} {dest_mac}"
          f"  {C['label']}Src:{C['reset']} {src_mac}"
          f"  {C['label']}Proto:{C['reset']} {proto_label}")


def print_arp(operation, sender_mac, sender_ip, target_mac, target_ip):
    print(f"  {C['arp']}[ARP]{C['reset']}"
          f"  {C['bold']}{operation}{C['reset']}"
          f"   {sender_ip} {C['label']}({sender_mac}){C['reset']}"
          f"  →  {target_ip} {C['label']}({target_mac}){C['reset']}")


def print_ipv4(version, header_len, ttl, proto, src, dst):
    PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 89: 'OSPF'}
    proto_name = PROTO_NAMES.get(proto, f'Proto({proto})')
    print(f"  {C['ipv4']}[IPv4]{C['reset']}"
          f"  v{version}"
          f"  {C['bold']}{src}{C['reset']}"
          f"  →  {C['bold']}{dst}{C['reset']}"
          f"  {C['label']}Proto:{C['reset']} {proto_name}"
          f"  {C['label']}TTL:{C['reset']} {ttl}"
          f"  {C['label']}HLen:{C['reset']} {header_len}B")


def print_ipv6(src, dst, next_header, hop_limit):
    print(f"  {C['ipv6']}[IPv6]{C['reset']}"
          f"  {C['bold']}{src}{C['reset']}"
          f"  →  {C['bold']}{dst}{C['reset']}"
          f"  {C['label']}NextHdr:{C['reset']} {next_header}"
          f"  {C['label']}HopLim:{C['reset']} {hop_limit}")


def print_icmp(icmp_type, code, checksum):
    from parsers import ICMP_TYPES
    type_name = ICMP_TYPES.get(icmp_type, f'Type {icmp_type}')
    print(f"  {C['icmp']}[ICMP]{C['reset']}"
          f"  {C['bold']}{type_name}{C['reset']}"
          f"  {C['label']}Code:{C['reset']} {code}"
          f"  {C['label']}Checksum:{C['reset']} {checksum:#06x}")


def print_tcp(src_port, dst_port, seq, ack, flags):
    urg, ack_f, psh, rst, syn, fin = flags
    flag_names = [n for n, v in [('URG', urg), ('ACK', ack_f), ('PSH', psh),
                                  ('RST', rst), ('SYN', syn), ('FIN', fin)] if v]
    flag_str = ' '.join(flag_names) if flag_names else 'none'
    print(f"  {C['tcp']}[TCP]{C['reset']}"
          f"  {C['bold']}{src_port}{C['reset']}"
          f"  →  {C['bold']}{dst_port}{C['reset']}"
          f"  {C['label']}Seq:{C['reset']} {seq}"
          f"  {C['label']}Ack:{C['reset']} {ack}"
          f"  {C['label']}Flags:{C['reset']} [{flag_str}]")


def print_udp(src_port, dst_port, size):
    print(f"  {C['udp']}[UDP]{C['reset']}"
          f"  {C['bold']}{src_port}{C['reset']}"
          f"  →  {C['bold']}{dst_port}{C['reset']}"
          f"  {C['label']}Length:{C['reset']} {size}B")


def print_http(http_data):
    if http_data.get('type') == 'request':
        method = http_data.get('method', '?')
        path   = http_data.get('path', '?')
        host   = http_data.get('headers', {}).get('Host', '')
        print(f"  {C['http']}[HTTP]{C['reset']}"
              f"  {C['bold']}{method}{C['reset']} {path}"
              + (f"  {C['label']}Host:{C['reset']} {host}" if host else ''))
        ua = http_data.get('headers', {}).get('User-Agent', '')
        if ua:
            print(f"  {C['label']}       User-Agent:{C['reset']} {ua[:80]}")
    else:
        status = http_data.get('status', '?')
        print(f"  {C['http']}[HTTP]{C['reset']}"
              f"  {C['bold']}{status}{C['reset']}")


def print_dns(dns_data):
    direction = 'Response' if dns_data['is_response'] else 'Query'
    rcode_map = {0: 'OK', 1: 'FormErr', 2: 'ServFail', 3: 'NXDomain', 5: 'Refused'}
    rcode_str = rcode_map.get(dns_data.get('rcode', 0), str(dns_data.get('rcode', '')))
    print(f"  {C['dns']}[DNS]{C['reset']}"
          f"  {C['bold']}{direction}{C['reset']}"
          f"  {C['label']}TxID:{C['reset']} {dns_data['transaction_id']:#06x}"
          f"  {C['label']}Answers:{C['reset']} {dns_data['answer_count']}"
          f"  {C['label']}RCode:{C['reset']} {rcode_str}")
    for q in dns_data.get('questions', []):
        print(f"         {C['label']}Query:{C['reset']}"
              f"  {q['name']}"
              f"  {C['label']}({q['type']}){C['reset']}")


def print_raw_data(data, label='Data', max_lines=3):
    """Print raw payload bytes as hex, truncated to max_lines."""
    if not data:
        return
    if isinstance(data, bytes):
        hex_str = ' '.join(f'{b:02x}' for b in data)
    else:
        hex_str = str(data)
    width = LINE_WIDTH - 12
    lines = textwrap.wrap(hex_str, width)
    print(f"  {C['data']}[{label}]{C['reset']}")
    for line in lines[:max_lines]:
        print(f"    {C['data']}{line}{C['reset']}")
    if len(lines) > max_lines:
        print(f"    {C['dim']}... {len(data)} bytes total{C['reset']}")


def print_error(msg):
    print(f"\n  {C['error']}[ERROR]{C['reset']} {msg}\n")
