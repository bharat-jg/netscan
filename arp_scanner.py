#!/usr/bin/env python3
"""
ARP Network Scanner
Discovers all devices on the local network using ARP requests.
This method can find devices even if they have firewalls that block other scan types.
"""

import sys
import os
import argparse
from scapy.all import ARP, Ether, srp
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Suppress Scapy's verbose logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

def check_privileges():
    """Check for root/administrator privileges needed for raw socket access."""
    if os.name == "posix" and os.geteuid() != 0:
        logger.warning("This script works best with root privileges on Linux/macOS.")
        return False
    elif os.name == "nt" and os.system("net session >nul 2>&1") != 0:
        logger.warning("This script requires administrator privileges on Windows.")
        return False
    return True

def arp_scan(network_range: str, timeout: int = 4):
    """
    Performs an ARP scan on the given network range.

    Args:
        network_range (str): The network range in CIDR notation (e.g., 192.168.1.0/24).
        timeout (int): The timeout for each ARP request.

    Returns:
        list: A list of dictionaries, each containing the IP and MAC of a discovered device.
    """
    logger.info(f"Starting ARP scan for network: {network_range}")
    
    # Create an ARP request packet
    arp_request = ARP(pdst=network_range)
    
    # Create an Ethernet broadcast frame
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the Ethernet frame and ARP request
    arp_packet = broadcast_frame / arp_request
    
    try:
        # Send the packet and receive responses
        answered_list, _ = srp(arp_packet, timeout=timeout, verbose=False)
    except PermissionError:
        logger.error("Permission denied. Please run this script with administrator/root privileges.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return []

    discovered_devices = []
    for sent, received in answered_list:
        discovered_devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
        
    logger.info(f"Scan complete. Found {len(discovered_devices)} devices.")
    return discovered_devices

def print_results(devices: list):
    """Prints the discovered devices in a formatted table."""
    if not devices:
        print("\n❌ No devices found.")
        print("   • Ensure you are running on the correct network.")
        print("   • Try increasing the timeout if the network is slow.")
        return

    print(f"\n✅ ARP Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*40}")
    print(f"{'IP Address':<18} {'MAC Address':<20}")
    print(f"{'-'*17} {'-'*19}")
    
    for device in devices:
        print(f"{device['ip']:<18} {device['mac']:<20}")
        
    print(f"{'='*40}")
    print(f"Total devices found: {len(devices)}")

def main():
    parser = argparse.ArgumentParser(description='ARP Network Scanner')
    parser.add_argument('--network', '-n', default='192.168.1.0/24',
                       help='Network range in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('--timeout', '-t', type=int, default=2,
                       help='Timeout for ARP requests in seconds (default: 2)')
    
    args = parser.parse_args()
    
    print("🌐 ARP Network Scanner")
    print(f"{'='*40}")
    
    # Check for necessary privileges
    if not check_privileges():
        print("\nFor best results, please run this script as an administrator or with sudo.")
    
    print(f"Scanning network: {args.network}")
    print(f"{'='*40}")
    
    start_time = datetime.now()
    devices = arp_scan(args.network, args.timeout)
    end_time = datetime.now()
    
    scan_duration = (end_time - start_time).total_seconds()
    
    print_results(devices)
    print(f"\nScan completed in {scan_duration:.1f} seconds.")

if __name__ == "__main__":
    main()
