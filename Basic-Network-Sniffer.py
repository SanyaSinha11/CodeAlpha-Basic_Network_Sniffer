#!/usr/bin/env python3
__author__ = "Sanya-Sinha"

import socket
import struct
import os
import subprocess


print ("Host: ", socket.gethostname())

#protocol number to name mapping
prtcl_map = {
    1 : "ICMP",
    6 : "TCP",
    17 : "UDP",
    89 : "OSPF",
}

#creating a raw socket to capture all packets
def raw_socket():
    try:
        network_sniff = socket.socket(socket.AF_INET,  socket.SOCK_RAW, socket.IPPROTO_TCP)
        return network_sniff
    except socket.error as e:
        print (f"Failed in creating a raw socket: {e}")
        return None

#binding socket with default network interface (0.0.0.0)
def bind_socket(network_sniff):
    network_sniff.bind(("0.0.0.0", 0))  #allows sniffer to capture all network traffic on the system

#configuring socket to include IP headers in captured packets and enable promiscuous mode
def config_socket(network_sniff):
    network_sniff.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #enabling promiscuous mode to capture all the traffic (Windows only)
    if os.name == 'nt':
        if hasattr(socket, 'SIO_RCVALL'):
           network_sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
           print ("Promiscuous mode enabled.")
        else:
           print ("Promiscuous mode is not supported on this version of Windows.")
    else:
        interface = 'eth0'
        subprocess.call(['sudo', 'ip', 'link', 'set', interface, 'promisc', 'on'])
        print (f"Promiscuous mode enabled on {interface}.")

#extract MAC addresses and protocol type from ethernet frame
def extrct_ethFrame(data):
    dst_mac, src_mac, prtcl = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dst_mac), format_mac(src_mac), socket.ntohs(prtcl), data[14:]

#convert MAC addresses from binary to human readable format
def format_mac(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

#extract header files from IPv4 packet
def extrct_ipPacket(data):
    vrsn_hLength = data[0] #version header length
    vrsn = vrsn_hLength >> 4
    hLength = (vrsn_hLength & 15) * 4 #header length
    ttl, prtcl, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return vrsn, hLength, ttl, prtcl, ipv4(src), ipv4(target), data[hLength:]

#convert binary IP addresses to human readable string
def ipv4(addr):
    return '.'.join(map(str, addr))


#Capturing and displaying the packets
def cap_pckts(network_sniff):
    try:
        while True: #start capturing the packets
             rawData, addr = network_sniff.recvfrom(65535) 

             eth = extrct_ethFrame(rawData)      
             print ("\nEthernet Frame: ")
             print (f"Destination MAC: {eth[0]}, Source MAC: {eth[1]}, Protocol: {eth[2]}")

             if True:  
                ipv4_pckt = extract_ipPacket(eth[3])
                prtcl_name = prtcl_map.get(ipv4_pckt[3], f"Unknown ({ipv4_pckt[3]})")
                print (f"IPv4 Packet: Version: {ipv4_pckt[0]}, Header Length: {ipv4_pckt[1]}, TTL: {ipv4_pckt[2]}")
                print (f"Protocol: {prtcl_name}, Source IP: {ipv4_pckt[4]}, Destination IP: {ipv4_pckt[5]}")
    except KeyboardInterrupt:
        print ("\nPacket capturing stopped.")

#Combine all the functions 
def main():
    #socket configuration
    network_sniff = raw_socket()
    if network_sniff is not None:
        bind_socket(network_sniff)
        config_socket(network_sniff)

        #capture packets
        cap_pckts(network_sniff)
    else:
        print ("Failed to initialize sniffer.")

if __name__ == "__main__":
    main()
