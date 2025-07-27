#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers.dns import DNSQR, DNSRR, DNS
from scapy.layers.inet import IP, UDP
import argparse
from time import sleep
import sys
from arp_spoof import scan, spoof


def process_packet(packet, blocked_domains):
    if packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode()
        if any(domain in qname for domain in blocked_domains):
            print(f"[!] Blocked access to: {qname}")
            return True
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--blocklist", required=True,
                        help="Path to file containing domains to block")
    args = parser.parse_args()

    # Read blocked domains
    with open(args.blocklist) as f:
        blocked_domains = [line.strip() for line in f if line.strip()]

    print("[*] Starting parental control system...")
    print("[*] Blocked domains:", blocked_domains)

    try:
        # Start packet capture
        scapy.sniff(
            filter="udp port 53",
            prn=lambda pkt: process_packet(pkt, blocked_domains),
            store=0
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping DNS monitoring...")
        sys.exit(0)


if __name__ == "__main__":
    main()


def enable_ipforwarding():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:  # enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)


def scan(ip):
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    ip_mac_address_list = {}
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=2, verbose=False)[0]

    for element in answered_list:
        ip_mac_address_list[element[1].psrc] = element[1].hwsrc

    return ip_mac_address_list


def spoof(target_ip, target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def spoof_devices():
    packets_count = 0

    while 1:
        spoof(device_ips[device_index-1],
              ips_to_macs[device_ips[device_index-1]], router_ip)
        spoof(router_ip, ips_to_macs[router_ip], device_ips[device_index-1])
        # print(f"\r[+] packet sent: {packets_count}", end="")
        packets_count = packets_count + 1
        sleep(0.5)


def get_host_by_ip(host_name):
    return socket.gethostbyname(host_name)


def ip_address_list(file_name):

    ips_list = []
    try:
        f = open(file_name, "r")
        for elm in f:
            ips_list.append(get_host_by_ip(elm.replace("\n", "")))
        f.close()
    except:
       print("""\033[91m[-] Host address not found or File not found\033[00m""")
       f.close()
       exit(1)
    return ips_list


block_list = ip_address_list(block_list_file.blocklist)


blocking_site = " "


def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())
    # print(scapy_packet[scapy.IP].dst)
    if scapy_packet[scapy.IP].dst in block_list:
        packet.drop()
        print("\033c")
        site_name = socket.gethostbyaddr(scapy_packet[scapy.IP].dst)
        print(f"[*] recently blocked site: {site_name[0]}", end="")

    else:
        packet.accept()


def traffic_analyzer():
    subprocess.call("sudo iptables --flush", shell=True)

    subprocess.call(
        "sudo iptables --append FORWARD -j NFQUEUE --queue-num 6", shell=True)
    traffic_queue = netfilterqueue.NetfilterQueue()
    traffic_queue.bind(6, process_packet)
    traffic_queue.run()


enable_ipforwarding()

router_ip = scapy.conf.route.route("0.0.0.0")[2]
# local_ip = scapy.get_if_addr(scapy.conf.iface)


if router_ip[-1:-3:-1] == "1.":
    print(router_ip[0:len(router_ip)-1:1]+"1/24")
    ips_to_macs = scan(router_ip[0:len(router_ip)-1:1]+"1/24")
    # ips_to_macs = scan(router_ip[0:len(router_ip)-1:1]+"1/24")

else:
    print("""\033[91m [-] can't do ARP spoof to this network
    try again connecting to router or access point \033[00m""")
    exit(0)

SoNo = 1
device_ips = []
for elm in ips_to_macs:
    print(f"[{SoNo}]\033[96m {elm}", end=" has mac: ")
    print(ips_to_macs[elm], end=" vender= ")

    print((requests.get("https://api.macvendors.com/" +
          ips_to_macs[elm])).content.decode(), end="\033[00m \n")
    device_ips.append(elm)
    SoNo = SoNo+1

device_index = int(input("\033[92m[?] Select the device >> \033[00m"))
print(device_ips[device_index-1])

print("\033c")  # to clear screen


try:

    process_spoof_devices = multiprocessing.Process(target=spoof_devices)
    process_traffic_analyzer = multiprocessing.Process(target=traffic_analyzer)

    process_spoof_devices.start()

    process_traffic_analyzer.start()

except KeyboardInterrupt:
    process_spoof_devices.terminate()
    process_traffic_analyzer.terminate()
    subprocess.call("sudo iptables --flush", shell=True)
