#!/usr/bin/env python3
"""
Quick SNMP Device Test
Test specific devices or small ranges quickly
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.snmp_scanner import SNMPScanner

def test_devices():
    print("🔍 Quick SNMP Device Test")
    print("="*40)
    
    # Initialize scanner
    scanner = SNMPScanner(communities=['public', 'private'])
    
    # Test specific devices that we know work
    test_ips = [
        "127.0.0.1",      # Localhost
        "192.168.1.5",    # Known working device
        "192.168.1.6",    # Your machine
    ]
    
    found_devices = []
    
    for ip in test_ips:
        print(f"\n📡 Testing {ip}...")
        device = scanner.scan_single_device(ip)
        if device:
            found_devices.append(device)
            print(f"✅ Found: {device.device_name} ({device.device_type})")
            print(f"   OS: {device.os_details}")
            print(f"   MAC: {', '.join(device.mac_addresses[:2])}")
            if device.cpu_usage > 0:
                print(f"   CPU: {device.cpu_usage:.1f}%")
        else:
            print(f"❌ No SNMP response")
    
    if found_devices:
        print(f"\n🎉 Successfully found {len(found_devices)} devices!")
        
        # Export results
        timestamp = scanner.export_to_csv(found_devices, "quick_test")
        print(f"📊 Results saved to: {timestamp}")
    else:
        print(f"\n❌ No devices found. Check SNMP configuration.")

if __name__ == "__main__":
    test_devices()
