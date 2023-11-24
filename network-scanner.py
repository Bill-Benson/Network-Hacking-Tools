#!/usr/bin/env python

"""
This script performs an ARP scan on the given IP address or IP range and prints the results.
"""

import argparse
import re
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def perform_arp_scan(ip):
    """
    Perform an ARP scan on the given IP address or IP range.
    Returns a list of dictionaries containing the IP and MAC address pairs.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered_list = srp(packet, timeout=1, verbose=False)[0]
    scan_results = []
    for element in answered_list:
        result_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        scan_results.append(result_dict)
    return scan_results


def print_results(result_list):
    """
    Print the scan results in a formatted table.
    """
    print("------------------------------------------")
    print("IP \t\t|\tMAC Address")
    print("------------------------------------------")
    for result in result_list:
        print(f"{result['IP']}\t\t{result['MAC']}")


def get_arguments():
    """
    Parse command-line arguments and return the IP range.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", dest="ip_range", help="IP / IP range")
    options = parser.parse_args()
    ip_range = str(options.ip_range)

    # Check if the IP address is valid
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    if not re.match(ip_pattern, ip_range):
        parser.error("Invalid IP/IP Range format.")

    return ip_range


if __name__ == "__main__":
    ip_range = get_arguments()
    scan_results = perform_arp_scan(ip_range)
    print_results(scan_results)
