"""
parsers.py — Protocol Parsers for Packet Sniffer
Handles: Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, HTTP
"""

import struct
import socket


# ─────────────────────────────────────────────
#  LAYER 2 — DATA LINK
# ─────────────────────────────────────────────

def ethernet_frame(data):
    """Unpack an Ethernet II frame."""
    if len(data) < 14:
        return None
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    """Format raw bytes as a human-readable MAC address."""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()


def arp_packet(data):
    """
    Unpack an ARP packet.
    Returns: (htype, ptype, hlen, plen, operation, sender_mac, sender_ip, target_mac, target_ip)
    """
    if len(data) < 28:
        return None
    htype, ptype, hlen, plen, oper = struct.unpack('! H H B B H', data[:8])
    sender_mac = get_mac_addr(data[8:14])
    sender_ip  = ipv4_addr(data[14:18])
    target_mac = get_mac_addr(data[18:24])
    target_ip  = ipv4_addr(data[24:28])
    operation  = 'Request' if oper == 1 else 'Reply'
    return htype, ptype, hlen, plen, operation, sender_mac, sender_ip, target_mac, target_ip


# ─────────────────────────────────────────────
#  LAYER 3 — NETWORK
# ─────────────────────────────────────────────

def ipv4_packet(data):
    """
    Unpack an IPv4 packet.
    Returns: (version, header_length, ttl, protocol, src_ip, dst_ip, payload)
    """
    if len(data) < 20:
        return None
    version_header_length = data[0]
    version       = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_addr(src), ipv4_addr(target), data[header_length:]


def ipv4_addr(addr):
    """Format raw bytes as a dotted IPv4 address string."""
    return '.'.join(map(str, addr))


def ipv6_packet(data):
    """
    Unpack an IPv6 packet.
    Returns: (version, payload_length, next_header, hop_limit, src_ip, dst_ip, payload)
    """
    if len(data) < 40:
        return None
    version_tc_fl    = struct.unpack('! I', data[:4])[0]
    version          = version_tc_fl >> 28
    payload_length, next_header, hop_limit = struct.unpack('! H B B', data[4:8])
    src = format_ipv6(data[8:24])
    dst = format_ipv6(data[24:40])
    return version, payload_length, next_header, hop_limit, src, dst, data[40:]


def format_ipv6(addr):
    """Format raw 16-byte sequence as a compressed IPv6 address string."""
    return ':'.join('{:04x}'.format(int.from_bytes(addr[i:i+2], 'big')) for i in range(0, 16, 2))


def icmp_packet(data):
    """
    Unpack an ICMP packet.
    Returns: (type, code, checksum, payload)
    """
    if len(data) < 4:
        return None
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


ICMP_TYPES = {
    0:  'Echo Reply',
    3:  'Destination Unreachable',
    5:  'Redirect',
    8:  'Echo Request',
    9:  'Router Advertisement',
    11: 'Time Exceeded',
    12: 'Parameter Problem',
}


# ─────────────────────────────────────────────
#  LAYER 4 — TRANSPORT
# ─────────────────────────────────────────────

def tcp_segment(data):
    """
    Unpack a TCP segment.
    Returns: (src_port, dst_port, seq, ack, urg, ack_f, psh, rst, syn, fin, payload)
    """
    if len(data) < 14:
        return None
    src_port, dst_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset    = (offset_reserved_flags >> 12) * 4
    flag_urg  = (offset_reserved_flags & 32)  >> 5
    flag_ack  = (offset_reserved_flags & 16)  >> 4
    flag_psh  = (offset_reserved_flags & 8)   >> 3
    flag_rst  = (offset_reserved_flags & 4)   >> 2
    flag_syn  = (offset_reserved_flags & 2)   >> 1
    flag_fin  =  offset_reserved_flags & 1
    return (src_port, dst_port, sequence, acknowledgement,
            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
            data[offset:])


def udp_segment(data):
    """
    Unpack a UDP segment.
    Returns: (src_port, dst_port, length, payload)
    """
    if len(data) < 8:
        return None
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dst_port, size, data[8:]


# ─────────────────────────────────────────────
#  LAYER 7 — APPLICATION
# ─────────────────────────────────────────────

def http_request(data):
    """
    Try to parse HTTP/1.x request or response data.
    Returns a dict with method/path/headers, or None if not HTTP text.
    """
    HTTP_METHODS = ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'HTTP/')
    try:
        text = data.decode('utf-8', errors='ignore')
        first_line = text.split('\r\n')[0] if '\r\n' in text else text.split('\n')[0]
        if not any(first_line.startswith(m) for m in HTTP_METHODS):
            return None
        lines = text.split('\r\n')
        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                k, v = line.split(': ', 1)
                headers[k.strip()] = v.strip()
            elif line == '':
                break
        parts = first_line.split(' ', 2)
        if first_line.startswith('HTTP/'):
            return {'type': 'response', 'status': first_line, 'headers': headers}
        return {'type': 'request', 'method': parts[0], 'path': parts[1] if len(parts) > 1 else '?',
                'version': parts[2] if len(parts) > 2 else '', 'headers': headers}
    except Exception:
        return None


def dns_packet(data):
    """
    Parse a DNS packet (queries and responses).
    Returns a structured dict, or None on failure.
    """
    if len(data) < 12:
        return None
    try:
        trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('! H H H H H H', data[:12])
        is_response  = bool((flags >> 15) & 1)
        opcode       = (flags >> 11) & 0xF
        rcode        = flags & 0xF

        questions = []
        offset = 12
        for _ in range(qdcount):
            name, offset = _parse_dns_name(data, offset)
            if offset + 4 <= len(data):
                qtype, qclass = struct.unpack('! H H', data[offset:offset + 4])
                offset += 4
                questions.append({'name': name, 'type': _dns_type_str(qtype)})

        return {
            'transaction_id': trans_id,
            'is_response':    is_response,
            'opcode':         opcode,
            'rcode':          rcode,
            'questions':      questions,
            'answer_count':   ancount,
        }
    except Exception:
        return None


def _parse_dns_name(data, offset):
    """Walk the DNS wire-format label sequence, following compression pointers."""
    labels  = []
    visited = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:       # compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = _parse_dns_name(data, pointer)
            labels.append(name)
            offset += 2
            break
        else:
            offset += 1
            end = offset + length
            labels.append(data[offset:end].decode('utf-8', errors='replace'))
            offset = end
    return '.'.join(labels), offset


def _dns_type_str(qtype):
    return {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
            15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'}.get(qtype, str(qtype))
