import dpkt
from struct import *
import binascii
import socket

def analysis_pcap_arp(file):
    f = open(file, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for (ts, buf) in pcap:
        ethernet_header = buf[0:14]
        ethernet_detailed = unpack("!6s6s2s", ethernet_header)

        arp_header = buf[14:42]
        arp_detailed = unpack("2s2s1s1s2s6s4s6s4s", arp_header)
        
        ethertype = ethernet_detailed[2]
        # print(ethertype)
        if ethertype != b'\x08\x06':
            continue

        print("**************** ETHERNET FRAME ****************")
        print("Target MAC:      ", str(binascii.hexlify(ethernet_detailed[0], ':'), 'utf-8'))
        print("Sender MAC:      ", str(binascii.hexlify(ethernet_detailed[1], ':'), 'utf-8'))
        print("Type:            ", str(binascii.hexlify(ethertype), 'utf-8'))
        print("************************************************")
        print("****************** ARP HEADER ******************")
        print("Hardware type:   ", str(binascii.hexlify(arp_detailed[0]), 'utf-8'))
        print("Protocol type:   ", str(binascii.hexlify(arp_detailed[1]), 'utf-8'))
        print("Hardware size:   ", str(binascii.hexlify(arp_detailed[2]), 'utf-8'))
        print("Protocol size:   ", str(binascii.hexlify(arp_detailed[3]), 'utf-8'))
        print("Opcode:          ", str(binascii.hexlify(arp_detailed[4]), 'utf-8'))
        print("Sender MAC:      ", str(binascii.hexlify(arp_detailed[5], ':'), 'utf-8'))
        print("Sender IP:       ", socket.inet_ntoa(arp_detailed[6]))
        print("Target MAC:      ", str(binascii.hexlify(arp_detailed[7], ':'), 'utf-8'))
        print("Target IP:       ", socket.inet_ntoa(arp_detailed[8]))
        print("************************************************\n")


analysis_pcap_arp('assignment3_my_arp.pcap')