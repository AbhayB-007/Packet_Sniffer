import os
import socket
import struct
import textwrap

TAB_1 = '\t -> ' 
TAB_2 = '\t\t - ' 
TAB_3 = '\t\t\t - ' 
TAB_4 = '\t\t\t\t - ' 

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    # host to listen on
    host = 'localhost'

   # create a raw socket and bind it to the public interface acc. to the OS
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP     
        
        # creating a raw socket    
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((host, 0))

        # we want the IP headers included in the capture
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # if we're using Windows, turn off promiscuous mode
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    else:
        # In case of Unix based operating system
        socket_protocol = socket.ntohs(0x0800)

        # creating a raw socket    
        sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket_protocol)

    # reading packets
    i = 1
    while True:
        raw_data, addr = sniffer.recvfrom(65535)    
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("---------------------------------------------------------------------------------------------------------")
        print(DATA_TAB_4 + 'Sniffed Packet No. -->', i)
        print(DATA_TAB_4 + 'Operating System -->', (lambda: 'Unix Based', lambda: 'Windows') [os.name == 'nt']())  
        print("---------------------------------------------------------------------------------------------------------") 
        print('Ethernet Frame :')
        print('1). Destination MAC : {}\n2). Source MAC : {}\n3). Protocol : {}'.format(dest_mac, src_mac, eth_proto))
        print("---------------------------------------------------------------------------------------------------------")
        i+=1
 
        # IPv4
        if eth_proto == 8 or os.name == 'nt':            
            ipv4 = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet: ')
            print(TAB_2 + ('1). Version: {}\n' + TAB_2 + '2). Header Length: {}\n' + TAB_2 + '3). TTL: {}').format(ipv4[0], ipv4[1], ipv4[2]))
            print(TAB_2 + ('4). Protocol: {}\n ' + TAB_2 + '5). Source: {}\n ' + TAB_2 + '6). Target: {}').format(ipv4[3], ipv4[4], ipv4[5]))


        # TCP
        if ipv4[4] == 6  or os.name == 'nt':
            tcp = tcp_segment(ipv4[6])
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + ('1). Source Port: {}\n' + TAB_2 + '2). Destination Port: {}\n' + TAB_2 + '3). Sequence: {}\n' + TAB_2 + '4). Acknowledgment: {}').format(tcp[0], tcp[1], tcp[2], tcp[3]))
            print(TAB_2 + 'Flags:')
            print(TAB_3 + 'URG: {},  ACK: {},  PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
            print(TAB_3 + 'RST: {},  SYN: {},  FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
            if len(tcp[10]) > 0:
                # HTTP
                if tcp[0] == 80 or tcp[1] == 80:
                    print(TAB_2 + 'HTTP Data:')
                    try:
                        http = HTTP(tcp[10])
                        http_info = str(http[10]).split('\n')
                        for line in http_info:
                            print(DATA_TAB_3 + str(line))
                    except:
                        print(format_multi_line(DATA_TAB_3, tcp[10]))
                else:
                    print(TAB_2 + 'TCP Data:')
                    print(format_multi_line(DATA_TAB_3, tcp[10]))

        #ICMP
        if ipv4[4] == 1 or os.name == 'nt':
            icmp = icmp_packet(data)
            print(TAB_1 + 'ICMP Packet: ')
            print(TAB_2 + ('1). Type: {}\n' + TAB_2 + '2). Code: {}\n ' + TAB_2 + '3). Checksum: {},').format(icmp[0], icmp[1],
    icmp[2]))
            print(TAB_2 + 'ICMP Data: ')
            print(format_multi_line(DATA_TAB_3, data))
        
        # UDP
        if ipv4[4] == 17  or os.name == 'nt':
            udp = udp_segment(ipv4[6])
            print(TAB_1 + 'UDP Segment:')
            print(TAB_2 + ('1). Source Port: {}\n ' + TAB_2 + '2). Destination Port: {}\n ' + TAB_2 + '3). Length: {}').format(udp[0], udp[1], udp[2]))
    
# Unpack ethernet frame
def ethernet_frame(data):    
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formated MAC  address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()    
    return mac_addr

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Return properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP segment
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpack UCP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()