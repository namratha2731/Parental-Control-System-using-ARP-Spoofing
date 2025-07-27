#!/usr/bin/env python3
import socket
# import re
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    # if packet.haslayer(http.HTTPRequest):
    ip_addr = packet.sprintf("%IP.dst%")
    if(ip_addr[0:3] != "172"):
        try:
            host_ip = socket.gethostbyaddr(ip_addr)
        except:
            host_ip = ("host not found", "")

        print(ip_addr, host_ip[0])


sniff("wlo1")
