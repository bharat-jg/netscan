#!/usr/bin/env python3
"""
Enhanced Network Discovery Scanner
Combines ARP scan for host discovery with Reverse DNS for hostname resolution.
"""

import sys
import os
import argparse
import socket
from scapy.all import ARP, Ether, srp
from datetime import datetime
import logging
import threading
from queue import Queue

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

def check_privileges():
    """Check for root/administrator privileges."""
    if os.name == "nt" and os.system("net session >nul 2>&1") != 0:
        logger.warning("This script requires administrator privileges for a reliable ARP scan.")
        return False
    return True

def arp_scan(network_range: str, timeout: int = 4) -> list:
    """Performs an ARP scan and returns a list of live IPs."""
    logger.info(f"Starting ARP scan for network: {network_range}")
    arp_request = ARP(pdst=network_range)
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast_frame / arp_request
    
    try:
        answered_list, _ = srp(arp_packet, timeout=timeout, verbose=False)
    except PermissionError:
        logger.error("Permission denied. Please run with administrator/root privileges.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An ARP scan error occurred: {e}")
        return []

    live_hosts = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered_list]
    logger.info(f"ARP scan found {len(live_hosts)} live hosts.")
    return live_hosts

def get_hostname(ip: str) -> str:
    """Performs a reverse DNS lookup to get the hostname for an IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "N/A" # Hostname not found
    except Exception as e:
        return f"Error: {e}"

def worker(queue, results):
    """Worker thread to process IPs from the queue."""
    while not queue.empty():
        host = queue.get()
        hostname = get_hostname(host['ip'])
        results.append({'ip': host['ip'], 'mac': host['mac'], 'hostname': hostname})
        queue.task_done()

def main():
    parser = argparse.ArgumentParser(description='Enhanced Network Discovery Scanner')
    parser.add_argument('--network', '-n', default='192.168.1.0/24',
                       help='Network range in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('--timeout', '-t', type=int, default=4,
                       help='Timeout for ARP requests in seconds (default: 4)')
    parser.add_argument('--threads', '-w', type=int, default=20,
                       help='Number of threads for DNS lookups (default: 20)')
    
    args = parser.parse_args()
    
    print("🌐 Enhanced Network Discovery")
    print(f"{'='*40}")
    check_privileges()
    print(f"Scanning network: {args.network}")
    print(f"{'='*40}")
    
    start_time = datetime.now()
    
    # Step 1: Discover live hosts with ARP scan
    live_hosts = arp_scan(args.network, args.timeout)
    
    if not live_hosts:
        print("\n❌ No live hosts found via ARP. Cannot proceed with hostname lookups.")
        return

    # Step 2: Resolve hostnames using threading for speed
    logger.info(f"Resolving hostnames for {len(live_hosts)} hosts...")
    q = Queue()
    for host in live_hosts:
        q.put(host)
        
    results = []
    threads = []
    for _ in range(min(args.threads, len(live_hosts))):
        t = threading.Thread(target=worker, args=(q, results))
        t.start()
        threads.append(t)
        
    q.join() # Block until all tasks are done

    end_time = datetime.now()
    scan_duration = (end_time - start_time).total_seconds()

    # Print results
    print(f"\n✅ Enhanced Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Hostname'}")
    print(f"{'-'*17} {'-'*19} {'-'*20}")
    
    # Sort results by IP address for readability
    sorted_results = sorted(results, key=lambda x: [int(y) for y in x['ip'].split('.')])
    
    for device in sorted_results:
        print(f"{device['ip']:<18} {device['mac']:<20} {device['hostname']}")
        
    print(f"{'='*60}")
    print(f"Total devices found: {len(sorted_results)}")
    print(f"\nScan completed in {scan_duration:.1f} seconds.")

if __name__ == "__main__":
    main()
