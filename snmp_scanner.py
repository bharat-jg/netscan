#!/usr/bin/env python3
"""
SNMP Network Scanner - Main Script
Command-line interface for network discovery and device information gathering
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.snmp_scanner import SNMPScanner
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description='SNMP Network Scanner')
    parser.add_argument('--network', '-n', required=True, 
                       help='Network range in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('--communities', '-c', nargs='+', default=['public', 'private'],
                       help='SNMP community strings (default: public private)')
    parser.add_argument('--timeout', '-t', type=int, default=3,
                       help='SNMP timeout in seconds (default: 3)')
    parser.add_argument('--retries', '-r', type=int, default=1,
                       help='SNMP retries (default: 1)')
    parser.add_argument('--workers', '-w', type=int, default=50,
                       help='Maximum concurrent workers (default: 50)')
    parser.add_argument('--output', '-o', choices=['csv', 'json', 'both'], default='both',
                       help='Output format (default: csv)')
    parser.add_argument('--filename', '-f', default='network_scan',
                       help='Output filename prefix (default: network_scan)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    print(f"🌐 SNMP Network Scanner")
    print(f"{'='*50}")
    print(f"Network Range: {args.network}")
    print(f"Communities: {', '.join(args.communities)}")
    print(f"Timeout: {args.timeout}s, Retries: {args.retries}")
    print(f"Workers: {args.workers}")
    print(f"{'='*50}")
    
    # Initialize scanner
    scanner = SNMPScanner(
        communities=args.communities,
        timeout=args.timeout,
        retries=args.retries
    )
    
    # Progress callback
    def show_progress(current, total):
        percent = (current / total) * 100
        print(f"\r🔍 Scanning... {current}/{total} ({percent:.1f}%)", end='', flush=True)
    
    # Perform scan
    start_time = datetime.now()
    print("🚀 Starting network scan...")
    
    devices = scanner.scan_network(
        args.network, 
        max_workers=args.workers, 
        progress_callback=show_progress
    )

    # add local device scan to the devices variable
    devices.append(scanner.scan_single_device(
        '127.0.0.1'
    ))

    end_time = datetime.now()
    scan_duration = (end_time - start_time).total_seconds()
    
    print(f"\n✅ Scan completed in {scan_duration:.1f} seconds")
    
    if not devices:
        print("❌ No SNMP devices found!")
        print("\n💡 Troubleshooting tips:")
        print("   • Ensure SNMP is enabled on target devices")
        print("   • Check community strings are correct")
        print("   • Verify firewall allows UDP port 161")
        print("   • Try different SNMP communities")
        return
    
    # Print summary
    scanner.print_device_summary(devices)
    
    # Export results
    print(f"\n📊 Exporting results...")
    
    if args.output in ['csv', 'both']:
        csv_file = scanner.export_to_csv(devices, args.filename)
        print(f"✅ CSV exported: {csv_file}")
    
    if args.output in ['json', 'both']:
        json_file = scanner.export_to_json(devices, args.filename)
        print(f"✅ JSON exported: {json_file}")
    
    print(f"\n🎉 Network scan completed successfully!")

if __name__ == "__main__":
    main()
