#!/usr/bin/env python

import requests
import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    ip_mac_address_list = {}
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    # print(answered_list.summary())

    for element in answered_list:
        ip_mac_address_list[element[1].psrc] = element[1].hwsrc

    return ip_mac_address_list


router_ip = scapy.conf.route.route("0.0.0.0")[2]
print(router_ip)
# print("172.31.16.1.1/24")
ips_to_macs = scan("172.31.19.1/24")


for elm in ips_to_macs:
    print(elm, end=" has mac: ")
    print(ips_to_macs[elm], end=" vender= ")

    print((requests.get("https://api.macvendors.com/" +
          ips_to_macs[elm])).content.decode())
