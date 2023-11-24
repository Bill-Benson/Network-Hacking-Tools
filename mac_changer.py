#!/usr/bin/env python

import argparse
import re
import subprocess


def main():
    """
    Main function to change the MAC address of the specified interface.
    """
    options = get_arguments()
    change_mac(options.interface, options.new_mac)
    current_mac = get_current_mac(options.interface)

    # Check if the MAC address has been changed
    if current_mac:
        if current_mac == options.new_mac:
            print(f"MAC address has been successfully changed to {current_mac}.")
        else:
            print("MAC address did not get changed.")
    else:
        print("Failed to retrieve MAC address.")


def change_mac(interface, new_mac):
    """
    Change the MAC address of the given interface to the specified MAC address.

    Args:
        interface (str): Name of the interface.
        new_mac (str): New MAC address.

    Returns:
        None
    """
    try:
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["ifconfig", interface, "hw", "ether", new_mac], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while changing MAC address: {e}")
        return


def get_current_mac(interface):
    """
    Retrieve the current MAC address of the given interface.

    Args:
        interface (str): Name of the interface.

    Returns:
        str: Current MAC address, or None if retrieval failed.
    """
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface], text=True)
        mac_address_search = re.search(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", ifconfig_result)
        if mac_address_search:
            return mac_address_search.group(0)
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while retrieving MAC address: {e}")
    return None


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_argument("-m", "--mac", dest="new_mac", help="New MAC address")

    options = parser.parse_args()

    if not options.interface or not options.new_mac:
        parser.error("Please specify both an interface and a MAC address. Use --help for more info.")

    # Check if the MAC address is valid
    mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if not re.match(mac_pattern, options.new_mac):
        parser.error("Invalid MAC address format.")

    return options


if __name__ == "__main__":
    main()
