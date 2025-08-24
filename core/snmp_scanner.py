#!/usr/bin/env python3
"""
SNMP Network Scanner - Core Module
Comprehensive SNMP-based network device discovery and information gathering
"""

from pysnmp.hlapi import (
    getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget, 
    ContextData, ObjectType, ObjectIdentity
)
import ipaddress
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import logging
import csv
import json
import os
import subprocess
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SNMPDevice:
    """Class to represent an SNMP device with all its information"""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.community = ""
        self.device_name = ""
        self.device_type = ""
        self.mac_addresses = []
        self.os_details = ""
        self.status = "Unknown"
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        self.total_memory = 0
        self.uptime = ""
        self.location = ""
        self.contact = ""
        self.interfaces = []
        self.sys_descr = ""
        self.sys_object_id = ""
        self.vendor = ""
        self.last_updated = datetime.now()

class SNMPScanner:
    """Main SNMP Scanner class"""
    
    # SNMP OIDs for comprehensive device information
    SYSTEM_OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',        # System description
        'sysObjectID': '1.3.6.1.2.1.1.2.0',     # System object identifier
        'sysUpTime': '1.3.6.1.2.1.1.3.0',       # System uptime
        'sysContact': '1.3.6.1.2.1.1.4.0',      # System contact
        'sysName': '1.3.6.1.2.1.1.5.0',         # System name/hostname
        'sysLocation': '1.3.6.1.2.1.1.6.0',     # System location
    }

    PERFORMANCE_OIDS = {
        'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',     # CPU usage percentage
        'hrMemorySize': '1.3.6.1.2.1.25.2.2.0',          # Total memory
        'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',       # Memory usage
        'hrSystemUptime': '1.3.6.1.2.1.25.1.1.0',        # System uptime
    }

    INTERFACE_OIDS = {
        'ifNumber': '1.3.6.1.2.1.2.1.0',                  # Number of interfaces
        'ifDescr': '1.3.6.1.2.1.2.2.1.2',                 # Interface descriptions
        'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',          # MAC addresses
        'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',           # Interface status
    }

    # Device type patterns
    DEVICE_PATTERNS = {
        'windows': ['windows', 'microsoft'],
        'linux': ['linux', 'ubuntu', 'centos', 'redhat'],
        'cisco': ['cisco', 'ios'],
        'hp': ['hp', 'hewlett', 'procurve'],
        'dell': ['dell', 'powerconnect'],
        'juniper': ['juniper', 'junos'],
        'netgear': ['netgear'],
        'printer': ['printer', 'laserjet', 'deskjet', 'officejet'],
        'switch': ['switch', 'catalyst', 'procurve'],
        'router': ['router', 'ios'],
        'firewall': ['firewall', 'fortigate', 'palo alto']
    }

    def __init__(self, communities=['public', 'private'], timeout=3, retries=1):
        self.communities = communities
        self.timeout = timeout
        self.retries = retries
        self.devices = []
        self.scan_progress = 0
        self.total_ips = 0

    def snmp_get(self, host: str, community: str, oid: str) -> Optional[str]:
        """Perform SNMP GET operation"""
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                return None
            elif errorStatus:
                return None
            else:
                for varBind in varBinds:
                    return str(varBind[1])
        except Exception:
            return None

    def snmp_walk(self, host: str, community: str, oid: str) -> List[Tuple[str, str]]:
        """Perform SNMP WALK operation"""
        results = []
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                maxRows=50
            ):
                if errorIndication:
                    break
                elif errorStatus:
                    break
                else:
                    for varBind in varBinds:
                        results.append((str(varBind[0]), str(varBind[1])))
        except Exception:
            pass
        return results

    def snmp_walk_values(self, host: str, community: str, oid: str):
        """Perform SNMP WALK and return raw values (not stringified)."""
        values = []
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                maxRows=50
            ):
                if errorIndication or errorStatus:
                    break
                for name, val in varBinds:
                    values.append(val)
        except Exception:
            pass
        return values

    @staticmethod
    def _format_mac_bytes(raw: bytes) -> Optional[str]:
        """Format raw bytes into MAC string if valid."""
        if not raw or len(raw) < 6:
            return None
        mac = ':'.join(f"{b:02x}" for b in raw)
        if mac == '00:00:00:00:00:00':
            return None
        return mac.upper()

    def _get_local_arp_mac(self, ip: str) -> Optional[str]:
        """Try to resolve MAC from local ARP cache as a fallback (no admin required)."""
        try:
            if os.name == 'nt':
                out = subprocess.check_output(['arp', '-a'], encoding='utf-8', errors='ignore')
                m = re.search(rf'^\s*{re.escape(ip)}\s+([0-9A-Fa-f\-:]+)', out, flags=re.M)
                if m:
                    return m.group(1).replace('-', ':').upper()
            else:
                out = subprocess.check_output(['arp', '-n', ip], encoding='utf-8', errors='ignore')
                m = re.search(r'((?:[0-9a-f]{2}:){5}[0-9a-f]{2})', out, flags=re.I)
                if m:
                    return m.group(1).upper()
        except Exception:
            return None
        return None

    def test_snmp_connectivity(self, host: str) -> Optional[str]:
        """Test SNMP connectivity and return working community"""
        for community in self.communities:
            result = self.snmp_get(host, community, self.SYSTEM_OIDS['sysDescr'])
            if result:
                return community
        return None

    def get_device_details(self, host: str, community: str) -> Optional[SNMPDevice]:
        """Get comprehensive device details"""
        device = SNMPDevice(host)
        device.community = community
        
        # Get system information
        for name, oid in self.SYSTEM_OIDS.items():
            value = self.snmp_get(host, community, oid)
            if value:
                if name == 'sysDescr':
                    device.sys_descr = value
                    device.os_details = value
                elif name == 'sysName':
                    device.device_name = value
                elif name == 'sysLocation':
                    device.location = value
                elif name == 'sysContact':
                    device.contact = value
                elif name == 'sysUpTime':
                    device.uptime = value
                elif name == 'sysObjectID':
                    device.sys_object_id = value

        # If no device name, use IP
        if not device.device_name:
            device.device_name = host

        # Set status as online if we got system description
        device.status = "Online" if device.sys_descr else "Offline"

        # Get MAC addresses (robust): prefer raw OctetString via SNMP IF-MIB, fallback to local ARP
        mac_addresses: List[str] = []

        # Try raw values from IF-MIB::ifPhysAddress
        try:
            raw_vals = self.snmp_walk_values(host, community, self.INTERFACE_OIDS['ifPhysAddress'])
            for v in raw_vals:
                raw = None
                # pysnmp OctetString has asOctets()
                if hasattr(v, 'asOctets'):
                    try:
                        raw = v.asOctets()
                    except Exception:
                        raw = None
                # If not available, try to parse from pretty string repr
                if raw is None:
                    s = str(v)
                    if s.startswith('0x') and len(s) >= 14:
                        try:
                            raw = bytes.fromhex(s[2:])
                        except Exception:
                            raw = None
                    elif re.fullmatch(r'(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}', s):
                        mac_addresses.append(s.replace('-', ':').upper())
                        continue

                if raw:
                    mac = self._format_mac_bytes(raw)
                    if mac:
                        mac_addresses.append(mac)
        except Exception:
            pass

        # Fallback: resolve via local ARP cache for this host
        if not mac_addresses:
            fallback_mac = self._get_local_arp_mac(host)
            if fallback_mac:
                mac_addresses.append(fallback_mac)

        # Deduplicate while preserving order
        seen = set()
        de_duped = []
        for m in mac_addresses:
            if m and m not in seen:
                seen.add(m)
                de_duped.append(m)
        device.mac_addresses = de_duped

        # Get interface information
        interface_names = []
        interface_walk = self.snmp_walk(host, community, self.INTERFACE_OIDS['ifDescr'])
        for oid, value in interface_walk:
            if value and value.strip():
                interface_names.append(value)
        device.interfaces = interface_names

        # Get CPU usage
        cpu_values = []
        cpu_walk = self.snmp_walk(host, community, self.PERFORMANCE_OIDS['hrProcessorLoad'])
        for oid, value in cpu_walk:
            try:
                cpu_val = float(value)
                if 0 <= cpu_val <= 100:
                    cpu_values.append(cpu_val)
            except:
                pass
        
        if cpu_values:
            device.cpu_usage = sum(cpu_values) / len(cpu_values)

        # Get memory information
        total_memory = self.snmp_get(host, community, self.PERFORMANCE_OIDS['hrMemorySize'])
        if total_memory:
            try:
                device.total_memory = int(total_memory)
            except:
                device.total_memory = 0

        # Get memory usage
        storage_walk = self.snmp_walk(host, community, self.PERFORMANCE_OIDS['hrStorageUsed'])
        if storage_walk and device.total_memory > 0:
            for oid, used_value in storage_walk:
                if used_value:
                    try:
                        used_kb = int(used_value)
                        usage_pct = (used_kb / device.total_memory) * 100
                        if 0 < usage_pct <= 100:
                            device.memory_usage = usage_pct
                            break
                    except:
                        pass

        # Determine device type and vendor
        sys_descr_lower = device.sys_descr.lower()
        device.device_type = "Unknown Device"
        device.vendor = "Unknown"
        
        for device_type, patterns in self.DEVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern in sys_descr_lower:
                    if device_type == 'windows':
                        device.device_type = 'Windows Computer'
                        device.vendor = 'Microsoft'
                    elif device_type == 'linux':
                        device.device_type = 'Linux Server'
                        device.vendor = 'Linux'
                    elif device_type == 'cisco':
                        device.device_type = 'Cisco Device'
                        device.vendor = 'Cisco'
                    elif device_type == 'hp':
                        device.device_type = 'HP Device'
                        device.vendor = 'HP'
                    elif device_type == 'printer':
                        device.device_type = 'Network Printer'
                    break
            if device.vendor != "Unknown":
                break

        return device

    def scan_single_device(self, host: str) -> Optional[SNMPDevice]:
        """Scan a single device"""
        community = self.test_snmp_connectivity(host)
        if community:
            return self.get_device_details(host, community)
        return None

    def scan_network(self, network: str, max_workers: int = 50, progress_callback=None) -> List[SNMPDevice]:
        """Scan entire network range"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            ip_list = [str(ip) for ip in net.hosts()]
        except Exception as e:
            logger.error(f"Invalid network range: {e}")
            return []

        self.total_ips = len(ip_list)
        self.scan_progress = 0
        self.devices = []
        
        logger.info(f"Starting SNMP scan of {self.total_ips} IPs in {network}")
        
        def scan_worker(ip):
            device = self.scan_single_device(ip)
            if device:
                self.devices.append(device)
                logger.info(f"Found SNMP device: {ip} ({device.device_name})")
            
            self.scan_progress += 1
            if progress_callback:
                progress_callback(self.scan_progress, self.total_ips)

        # Use threading for concurrent scanning
        threads = []
        semaphore = threading.Semaphore(max_workers)
        
        def thread_wrapper(ip):
            with semaphore:
                scan_worker(ip)

        for ip in ip_list:
            thread = threading.Thread(target=thread_wrapper, args=(ip,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        logger.info(f"Scan completed. Found {len(self.devices)} SNMP devices.")
        return self.devices

    def export_to_csv(self, devices: List[SNMPDevice], filename: str) -> str:
        """Export devices to CSV file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"data/{filename}_{timestamp}.csv"

        # Ensure maximum compatibility with Excel by using UTF-8 with BOM
        os.makedirs('data', exist_ok=True)
        with open(filepath, 'w', newline='', encoding='utf-8-sig') as csvfile:
            fieldnames = [
                'IP Address', 'Device Name', 'Device Type', 'Vendor', 'MAC Addresses',
                'OS Details', 'Status', 'CPU Usage (%)', 'Memory Usage (%)',
                'Total Memory (KB)', 'Uptime', 'Location', 'Contact',
                'SNMP Community', 'Interfaces', 'Last Updated'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for device in devices:
                writer.writerow({
                    'IP Address': device.ip,
                    'Device Name': device.device_name,
                    'Device Type': device.device_type,
                    'Vendor': device.vendor,
                    'MAC Addresses': ', '.join(device.mac_addresses),
                    'OS Details': device.os_details,
                    'Status': device.status,
                    'CPU Usage (%)': f"{device.cpu_usage:.1f}",
                    'Memory Usage (%)': f"{device.memory_usage:.1f}",
                    'Total Memory (KB)': device.total_memory,
                    'Uptime': device.uptime,
                    'Location': device.location,
                    'Contact': device.contact,
                    'SNMP Community': device.community,
                    'Interfaces': ', '.join(device.interfaces[:3]),  # Limit to first 3
                    'Last Updated': device.last_updated.strftime("%Y-%m-%d %H:%M:%S")
                })

        return filepath

    def export_to_json(self, devices: List[SNMPDevice], filename: str) -> str:
        """Export devices to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"data/{filename}_{timestamp}.json"
        os.makedirs('data', exist_ok=True)

        device_list = []
        for device in devices:
            device_dict = {
                'ip_address': device.ip,
                'device_name': device.device_name,
                'device_type': device.device_type,
                'vendor': device.vendor,
                'mac_addresses': device.mac_addresses,
                'os_details': device.os_details,
                'status': device.status,
                'cpu_usage': round(device.cpu_usage, 2),
                'memory_usage': round(device.memory_usage, 2),
                'total_memory': device.total_memory,
                'uptime': device.uptime,
                'location': device.location,
                'contact': device.contact,
                'snmp_community': device.community,
                'interfaces': device.interfaces,
                'sys_descr': device.sys_descr,
                'sys_object_id': device.sys_object_id,
                'last_updated': device.last_updated.isoformat()
            }
            device_list.append(device_dict)

        with open(filepath, 'w', encoding='utf-8') as jsonfile:
            json.dump({
                'scan_timestamp': datetime.now().isoformat(),
                'total_devices': len(devices),
                'devices': device_list
            }, jsonfile, indent=2, ensure_ascii=False)

        return filepath

    def print_device_summary(self, devices: List[SNMPDevice]):
        """Print a summary of discovered devices"""
        print(f"\n{'='*80}")
        print(f"SNMP NETWORK SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")
        print(f"Total devices found: {len(devices)}")
        print(f"{'='*80}")
        
        for i, device in enumerate(devices, 1):
            print(f"\n[{i}] Device: {device.device_name} ({device.ip})")
            print(f"    Type: {device.device_type}")
            print(f"    Vendor: {device.vendor}")
            print(f"    Status: {device.status}")
            print(f"    OS: {device.os_details}")
            if device.mac_addresses:
                print(f"    MAC: {', '.join(device.mac_addresses[:2])}")
            if device.cpu_usage > 0:
                print(f"    CPU Usage: {device.cpu_usage:.1f}%")
            if device.memory_usage > 0:
                print(f"    Memory Usage: {device.memory_usage:.1f}%")
            if device.location:
                print(f"    Location: {device.location}")
        
        print(f"\n{'='*80}")
