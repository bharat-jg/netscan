#!/usr/bin/env python3
"""
Simple SNMP Test - Debug Version
"""

print("Starting simple SNMP test...")

try:
    print("1. Testing imports...")
    from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
    print("✅ pysnmp imported successfully")
    
    print("2. Testing core scanner import...")
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.snmp_scanner import SNMPScanner
    print("✅ Core scanner imported successfully")
    
    print("3. Creating scanner instance...")
    scanner = SNMPScanner(communities=['public', 'private'])
    print("✅ Scanner created successfully")
    
    print("4. Testing single device scan...")
    device = scanner.scan_single_device("127.0.0.1")
    if device:
        print(f"✅ Found device: {device.device_name} at {device.ip}")
    else:
        print("❌ No device found at 127.0.0.1")
    
    print("Test completed!")
    
except Exception as e:
    print(f"❌ Error occurred: {e}")
    import traceback
    traceback.print_exc()
