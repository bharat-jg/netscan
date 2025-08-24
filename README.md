# 🌐 SNMP Network Scanner

A lightweight, efficient SNMP-based network discovery tool for comprehensive device information gathering.

## ✨ Features

- **🔍 Network Discovery**: Scan entire network ranges using CIDR notation
- **📊 Device Details**: Comprehensive information collection (IP, MAC, device type, OS, performance metrics)
- **⚡ High Performance**: Multi-threaded scanning with configurable concurrency
- **📁 Multiple Formats**: Export results to CSV and JSON
- **🔧 Configurable**: Customizable SNMP communities, timeouts, and retry settings
- **💻 Cross-Platform**: Works on Windows, Linux, and macOS

## 🚀 Quick Start

### Installation

```bash
# Clone or download the project
cd netscan

# Activate virtual environment
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

**Scan entire network:**

```bash
python snmp_scanner.py --network 192.168.1.0/24
```

**Quick test specific devices:**

```bash
python quick_test.py
```

**Advanced scanning:**

```bash
python snmp_scanner.py --network 192.168.1.0/24 --communities public private --workers 100 --output both
```

## 📋 Command Line Options

| Option              | Description                           | Default          |
| ------------------- | ------------------------------------- | ---------------- |
| `--network, -n`     | Network range (CIDR notation)         | Required         |
| `--communities, -c` | SNMP community strings                | `public private` |
| `--timeout, -t`     | SNMP timeout (seconds)                | `3`              |
| `--retries, -r`     | SNMP retries                          | `1`              |
| `--workers, -w`     | Concurrent workers                    | `50`             |
| `--output, -o`      | Output format (`csv`, `json`, `both`) | `csv`            |
| `--filename, -f`    | Output filename prefix                | `network_scan`   |
| `--verbose, -v`     | Enable verbose logging                | `false`          |

## 📊 Information Collected

For each discovered device:

- **🌐 Network**: IP Address, MAC Addresses
- **💻 System**: Device Name, Type, Vendor, OS Details
- **📈 Performance**: CPU Usage, Memory Usage, System Uptime
- **📍 Location**: Physical location and contact information
- **🔌 Interfaces**: Network interface details
- **⚙️ SNMP**: Community used, system description, object ID

## 📁 Project Structure

```
netscan/
├── core/
│   └── snmp_scanner.py          # Core SNMP scanning engine
├── data/                        # Output files (CSV/JSON)
├── .venv/                       # Python virtual environment
├── snmp_scanner.py              # Main command-line interface
├── quick_test.py                # Quick device testing
├── requirements.txt             # Python dependencies
└── README.md                    # This documentation
```

## 🔧 SNMP Configuration

### Windows Setup

1. **Enable SNMP Service:**

   - Control Panel → Programs → Windows Features
   - Check "Simple Network Management Protocol (SNMP)"
   - Configure community strings in SNMP Service properties

2. **Firewall Configuration:**
   ```cmd
   netsh advfirewall firewall add rule name="SNMP-In" dir=in action=allow protocol=UDP localport=161
   ```

### Linux Setup

```bash
# Install SNMP daemon
sudo apt-get install snmpd

# Configure /etc/snmp/snmpd.conf
echo "rocommunity public 192.168.1.0/24" | sudo tee -a /etc/snmp/snmpd.conf

# Restart service
sudo systemctl restart snmpd
```

## 💡 Usage Examples

### Example 1: Scan Local Network

```bash
python snmp_scanner.py --network 192.168.1.0/24 --communities public private
```

### Example 2: Fast Scan with High Concurrency

```bash
python snmp_scanner.py --network 10.0.0.0/16 --workers 200 --timeout 2
```

### Example 3: Export to Both Formats

```bash
python snmp_scanner.py --network 172.16.0.0/12 --output both --filename corporate_scan
```

### Example 4: Verbose Scanning

```bash
python snmp_scanner.py --network 192.168.0.0/16 --verbose --communities public private community123
```

## 🔍 Troubleshooting

### No Devices Found?

- ✅ Verify SNMP is enabled on target devices
- ✅ Check community strings are correct
- ✅ Ensure UDP port 161 is not blocked by firewall
- ✅ Try different SNMP communities
- ✅ Test with `quick_test.py` first

### Slow Performance?

- ⚡ Increase `--workers` for faster scanning
- ⚡ Reduce `--timeout` for quicker responses
- ⚡ Use smaller network ranges for testing

### Import Errors?

- 📦 Ensure virtual environment is activated
- 📦 Install dependencies: `pip install -r requirements.txt`
- 📦 Check Python version (3.7+ required)

## 📈 Sample Output

```
🌐 SNMP Network Scanner
==================================================
Network Range: 192.168.1.0/24
Communities: public, private
Timeout: 3s, Retries: 1
Workers: 50
==================================================
🚀 Starting network scan...
🔍 Scanning... 254/254 (100.0%)
✅ Scan completed in 15.3 seconds

================================================================================
SNMP NETWORK SCAN RESULTS - 2025-08-24 14:30:45
================================================================================
Total devices found: 3
================================================================================

[1] Device: DESKTOP-ABC123 (192.168.1.10)
    Type: Windows Computer
    Vendor: Microsoft
    Status: Online
    OS: Microsoft Windows 10 Pro
    MAC: 00:1B:44:11:3A:B7
    CPU Usage: 15.2%
    Memory Usage: 65.8%

[2] Device: ubuntu-server (192.168.1.20)
    Type: Linux Server
    Vendor: Linux
    Status: Online
    OS: Linux ubuntu 5.4.0-88-generic
    MAC: 08:00:27:BB:05:F1
    CPU Usage: 8.1%
    Memory Usage: 42.3%
```

## 📝 Requirements

- **Python**: 3.7 or higher
- **Dependencies**: Listed in `requirements.txt`
- **Network**: Access to target devices on UDP port 161
- **SNMP**: Enabled on target devices with known community strings

## 🤝 Support

For issues or questions:

1. Check the troubleshooting section above
2. Verify SNMP configuration on target devices
3. Test with `quick_test.py` for known working devices
4. Review application logs with `--verbose` flag

---

**Note**: This tool is designed for network administration and security assessment on networks you own or have permission to scan.
