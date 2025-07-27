#!/usr/bin/env python3
from struct import pack
import scapy.all as scapy
import netfilterqueue
import subprocess


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet[scapy.IP].dst)
    packet.accept()


    # if scapy_packet.haslayer(scapy.TCP_SERVICES):
    #     print(scapy_packet.show())
    #     pass
    # elif scapy_packet.haslayer(scapy.UDP_SERVICES):
    #     pass
    # else:

    #     #print(scapy_packet.show())
    #     packet.accept()

# subprocess.call(["ls", "-l"])
# subprocess.call("exit 1", shell=True)
def traffic_analyzer():
    try:
        subprocess.call("sudo iptables --append FORWARD -j NFQUEUE --queue-num 6", shell=True)

        traffic_queue = netfilterqueue.NetfilterQueue()
        traffic_queue.bind(6,process_packet)
        traffic_queue.run()

    except KeyboardInterrupt:
        subprocess.call("sudo iptables --flush", shell=True)
        pass
        

    
traffic_analyzer()

