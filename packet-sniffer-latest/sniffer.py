"""
sniffer.py — Main Entry Point for Packet Sniffer
Cross-platform (Windows + Linux) real-time network packet analyzer.

Usage:
  Windows  (Admin CMD)  :  python sniffer.py [options]
  Linux    (sudo)       :  sudo python3 sniffer.py [options]

Options:
  --protocol {tcp,udp,icmp,arp,all}    Filter by protocol        (default: all)
  --port     PORT                      Filter by port number
  --src-ip   IP                        Filter by source IP
  --dst-ip   IP                        Filter by destination IP
  --count    N                         Stop after N packets      (default: unlimited)
  --log      FILE.json                 Save packets to JSON log
  --no-data                            Hide raw payload output
"""

import os
import sys
import socket
import argparse

import parsers as P
import display  as D
from logger import PacketLogger


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='sniffer',
        description='🕵️  Packet Sniffer — real-time cross-platform network analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python sniffer.py
  python sniffer.py --protocol tcp --port 443
  python sniffer.py --protocol dns
  python sniffer.py --src-ip 192.168.1.10
  python sniffer.py --count 100 --log capture.json
  python sniffer.py --protocol icmp --no-data
        """,
    )
    parser.add_argument('--protocol', default='all',
                        choices=['tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'all'],
                        help='Filter by protocol (default: all)')
    parser.add_argument('--port',   type=int, default=None, metavar='PORT',
                        help='Filter by TCP/UDP port number')
    parser.add_argument('--src-ip', type=str, default=None, metavar='IP',
                        help='Filter: only show packets from this source IP')
    parser.add_argument('--dst-ip', type=str, default=None, metavar='IP',
                        help='Filter: only show packets to this destination IP')
    parser.add_argument('--count',  type=int, default=0, metavar='N',
                        help='Stop after N matching packets (0 = unlimited)')
    parser.add_argument('--log',    type=str, default=None, metavar='FILE',
                        help='Save captured packets to a JSON log file')
    parser.add_argument('--no-data', action='store_true',
                        help='Hide raw payload bytes in output')
    return parser.parse_args()


# ─────────────────────────────────────────────
#  Socket creation (with clear error messages)
# ─────────────────────────────────────────────

def create_socket() -> socket.socket:
    """
    Open a raw socket appropriate for the current OS.
    Windows — AF_INET  / SOCK_RAW / IPPROTO_IP  (requires Administrator)
    Linux   — PF_PACKET/ SOCK_RAW / ETH_P_ALL    (requires root / CAP_NET_RAW)
    """
    try:
        if os.name == 'nt':
            # Bind to the machine's own IP so we see all inbound traffic
            host = socket.gethostbyname(socket.gethostname())
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((host, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode — captures all packets, not just ours
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # ETH_P_ALL (0x0003) captures every Ethernet frame regardless of protocol
            sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                                    socket.htons(0x0003))
        return sniffer

    except PermissionError:
        D.print_error(
            'Permission denied.\n'
            '  • Windows: re-run Command Prompt as Administrator\n'
            '  • Linux  : prefix command with sudo   (sudo python3 sniffer.py)'
        )
        sys.exit(1)
    except OSError as exc:
        D.print_error(f'Could not create raw socket: {exc}')
        sys.exit(1)


def release_socket(sniffer: socket.socket) -> None:
    """Turn off promiscuous mode (Windows) and close the socket."""
    if os.name == 'nt':
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
    sniffer.close()


# ─────────────────────────────────────────────
#  Packet filter
# ─────────────────────────────────────────────

def passes_filter(args, *, protocol=None, src_ip=None, dst_ip=None,
                  src_port=None, dst_port=None) -> bool:
    """
    Return True if a packet matches the user-supplied filters.
    All supplied filters must match (AND logic).
    """
    # Protocol filter — 'dns' and 'http' are detected at the app layer,
    # so we let UDP/TCP through and decide later.
    if args.protocol not in ('all', 'dns', 'http'):
        if protocol and args.protocol.lower() != protocol.lower():
            return False

    if args.src_ip  and src_ip  != args.src_ip:
        return False
    if args.dst_ip  and dst_ip  != args.dst_ip:
        return False
    if args.port:
        if src_port != args.port and dst_port != args.port:
            return False
    return True


# ─────────────────────────────────────────────
#  Per-protocol handlers
# ─────────────────────────────────────────────

def handle_tcp(ip_payload, args, src_ip, dst_ip,
               show_eth, eth_args, os_label, packet_log) -> bool:
    """Parse and display a TCP segment. Returns True if packet was shown."""
    tcp = P.tcp_segment(ip_payload)
    if tcp is None:
        return False

    src_port, dst_port = tcp[0], tcp[1]
    payload = tcp[10]

    # Detect HTTP before applying the protocol filter
    http_data = None
    if src_port in (80, 8080) or dst_port in (80, 8080):
        http_data = P.http_request(payload)

    # Apply --protocol http filter
    if args.protocol == 'http' and http_data is None:
        return False

    if not passes_filter(args, protocol='tcp', src_ip=src_ip, dst_ip=dst_ip,
                         src_port=src_port, dst_port=dst_port):
        return False

    flags = (tcp[4], tcp[5], tcp[6], tcp[7], tcp[8], tcp[9])
    D.print_tcp(src_port, dst_port, tcp[2], tcp[3], flags)

    if http_data:
        D.print_http(http_data)
    elif payload and not args.no_data:
        D.print_raw_data(payload, 'TCP payload')

    packet_log.update({
        'protocol': 'TCP', 'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port,
        'flags': {'URG': tcp[4], 'ACK': tcp[5], 'PSH': tcp[6],
                  'RST': tcp[7], 'SYN': tcp[8], 'FIN': tcp[9]},
    })
    return True


def handle_udp(ip_payload, args, src_ip, dst_ip,
               show_eth, eth_args, os_label, packet_log) -> bool:
    """Parse and display a UDP segment. Returns True if packet was shown."""
    udp = P.udp_segment(ip_payload)
    if udp is None:
        return False

    src_port, dst_port, size, udp_payload = udp

    # Detect DNS before filter
    dns_data = None
    if src_port == 53 or dst_port == 53:
        dns_data = P.dns_packet(udp_payload)

    # Apply --protocol dns filter
    if args.protocol == 'dns' and dns_data is None:
        return False

    if not passes_filter(args, protocol='udp', src_ip=src_ip, dst_ip=dst_ip,
                         src_port=src_port, dst_port=dst_port):
        return False

    D.print_udp(src_port, dst_port, size)

    if dns_data:
        D.print_dns(dns_data)
    elif udp_payload and not args.no_data:
        D.print_raw_data(udp_payload, 'UDP payload')

    packet_log.update({
        'protocol': 'UDP', 'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port,
    })
    if dns_data:
        packet_log['dns'] = {
            'is_response': dns_data['is_response'],
            'questions': [q['name'] for q in dns_data.get('questions', [])],
        }
    return True


def handle_icmp(ip_payload, args, src_ip, dst_ip, packet_log) -> bool:
    """Parse and display an ICMP packet. Returns True if packet was shown."""
    if not passes_filter(args, protocol='icmp', src_ip=src_ip, dst_ip=dst_ip):
        return False

    # FIX: parse from ip_payload (the IPv4 payload), NOT from the raw frame
    icmp = P.icmp_packet(ip_payload)
    if icmp is None:
        return False

    D.print_icmp(icmp[0], icmp[1], icmp[2])

    if icmp[3] and not args.no_data:
        D.print_raw_data(icmp[3], 'ICMP payload')

    packet_log.update({
        'protocol': 'ICMP', 'src_ip': src_ip, 'dst_ip': dst_ip,
        'icmp_type': icmp[0], 'code': icmp[1], 'checksum': icmp[2],
    })
    return True


# ─────────────────────────────────────────────
#  IPv4 dispatcher
# ─────────────────────────────────────────────

def process_ipv4(raw, args, displayed, os_label,
                 logger, show_eth=False, eth_args=None) -> int:
    """
    Parse an IPv4 packet, dispatch to the correct L4 handler.
    Returns the updated displayed-packet counter.
    """
    ipv4 = P.ipv4_packet(raw)
    if ipv4 is None:
        return displayed

    version, header_len, ttl, proto, src_ip, dst_ip, ip_payload = ipv4

    # ── build a shared log dict; handlers fill in their fields ──
    packet_log: dict = {}

    shown   = False
    proto_n = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto)

    if proto == 6:      # TCP
        ipv4_printer = lambda: D.print_ipv4(version, header_len, ttl, proto, src_ip, dst_ip)
        shown = handle_tcp(ip_payload, args, src_ip, dst_ip,
                           show_eth, eth_args, os_label, packet_log)
    elif proto == 17:   # UDP
        ipv4_printer = lambda: D.print_ipv4(version, header_len, ttl, proto, src_ip, dst_ip)
        shown = handle_udp(ip_payload, args, src_ip, dst_ip,
                           show_eth, eth_args, os_label, packet_log)
    elif proto == 1:    # ICMP
        ipv4_printer = lambda: D.print_ipv4(version, header_len, ttl, proto, src_ip, dst_ip)
        shown = handle_icmp(ip_payload, args, src_ip, dst_ip, packet_log)
    else:
        # Unknown / unsupported L4 — skip
        return displayed

    if not shown:
        return displayed

    # ── print header lines before the protocol detail ──
    displayed += 1
    D.packet_header(displayed, os_label)
    if show_eth and eth_args:
        D.print_ethernet(*eth_args)
    D.print_ipv4(version, header_len, ttl, proto, src_ip, dst_ip)

    # Re-call the correct display function now that we know we're printing
    if proto == 6:
        tcp = P.tcp_segment(ip_payload)
        if tcp:
            flags = (tcp[4], tcp[5], tcp[6], tcp[7], tcp[8], tcp[9])
            D.print_tcp(tcp[0], tcp[1], tcp[2], tcp[3], flags)
            http_data = P.http_request(tcp[10]) if (tcp[0] in (80,8080) or tcp[1] in (80,8080)) else None
            if http_data:
                D.print_http(http_data)
            elif tcp[10] and not args.no_data:
                D.print_raw_data(tcp[10], 'TCP payload')

    elif proto == 17:
        udp = P.udp_segment(ip_payload)
        if udp:
            src_port, dst_port, size, udp_payload = udp
            D.print_udp(src_port, dst_port, size)
            if src_port == 53 or dst_port == 53:
                dns = P.dns_packet(udp_payload)
                if dns:
                    D.print_dns(dns)
            elif udp_payload and not args.no_data:
                D.print_raw_data(udp_payload, 'UDP payload')

    elif proto == 1:
        icmp = P.icmp_packet(ip_payload)
        if icmp:
            D.print_icmp(icmp[0], icmp[1], icmp[2])
            if icmp[3] and not args.no_data:
                D.print_raw_data(icmp[3], 'ICMP payload')

    if logger and packet_log:
        logger.log(packet_log)

    return displayed


# ─────────────────────────────────────────────
#  Main capture loop
# ─────────────────────────────────────────────

def main():
    args    = build_args()
    os_name = 'Windows' if os.name == 'nt' else 'Linux'

    D.print_banner()
    D.print_active_filters(args)

    sniffer = create_socket()
    logger  = PacketLogger(args.log) if args.log else None
    displayed = 0

    try:
        while True:
            try:
                raw_data, _ = sniffer.recvfrom(65535)
            except OSError:
                break

            # ── Windows: raw socket delivers the IP packet directly ──
            if os.name == 'nt':
                displayed = process_ipv4(
                    raw_data, args, displayed, os_name, logger,
                    show_eth=False,
                )

            # ── Linux/Mac: raw socket delivers the full Ethernet frame ──
            else:
                eth = P.ethernet_frame(raw_data)
                if eth is None:
                    continue
                dest_mac, src_mac, eth_proto, eth_payload = eth

                # ARP  (0x0806)
                if eth_proto == 0x0806:
                    if not passes_filter(args, protocol='arp'):
                        continue
                    arp = P.arp_packet(eth_payload)
                    if arp is None:
                        continue
                    displayed += 1
                    D.packet_header(displayed, os_name)
                    D.print_ethernet(dest_mac, src_mac, f'ARP (0x{eth_proto:04x})')
                    D.print_arp(arp[4], arp[5], arp[6], arp[7], arp[8])
                    if logger:
                        logger.log({'protocol': 'ARP', 'operation': arp[4],
                                    'sender_ip': arp[6], 'target_ip': arp[8]})

                # IPv4 (0x0800)
                elif eth_proto == 0x0800:
                    displayed = process_ipv4(
                        eth_payload, args, displayed, os_name, logger,
                        show_eth=True,
                        eth_args=(dest_mac, src_mac, f'IPv4 (0x{eth_proto:04x})'),
                    )

                # IPv6 (0x86DD)
                elif eth_proto == 0x86DD:
                    if args.protocol not in ('all',):
                        continue
                    ipv6 = P.ipv6_packet(eth_payload)
                    if ipv6 is None:
                        continue
                    version, payload_len, next_hdr, hop_limit, src, dst, _ = ipv6
                    displayed += 1
                    D.packet_header(displayed, os_name)
                    D.print_ethernet(dest_mac, src_mac, f'IPv6 (0x{eth_proto:04x})')
                    D.print_ipv6(src, dst, next_hdr, hop_limit)
                    if logger:
                        logger.log({'protocol': 'IPv6', 'src_ip': src, 'dst_ip': dst})

                # Anything else — skip silently
                else:
                    continue

            # ── Stop after --count packets ──
            if args.count and displayed >= args.count:
                print(f'\n  Capture limit of {args.count} packets reached.')
                break

    except KeyboardInterrupt:
        pass  # handled in finally

    finally:
        if logger:
            logger.close()
        release_socket(sniffer)
        D.print_summary(displayed, args.log)


if __name__ == '__main__':
    main()
