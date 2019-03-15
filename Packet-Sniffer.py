#! /usr/local/bin/python3.5

import socket
import struct
import threading
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def run(id):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if (True):
            print('\n Ethernet Frame: ' + id)
            #src_port, dest_port, length, data = udp_seg(data)
            #print("WE DIS LONG BOIS: " + str(length))
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

            # After this point you can access dest_mac and src_mac

            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
                print("WE DIS LONG BOIS: " + str(len(data)))
                print(TAB_1 + "IPV4 Packet:")
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # At this point you can access src and target as IP 

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserv_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >>4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats the output line
def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

#Threading code that doesn't work

threads = []

def main():
    run("Thread 1")
   #  process = threading.Thread(target = run, args = ["Thread 1"])
   # #process1 = threading.Thread(target = run, args = ["Thread 2"])
   #  process.start()
   #  #process1.start()
   #  threads.append(process)
   #  #threads.append(process1)

   #  for process in threads:
   #      process.join()

main()