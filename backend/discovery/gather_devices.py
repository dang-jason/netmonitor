import socket
import subprocess
import platform
import re
import ipaddress
import concurrent.futures
import requests
import json
from collections import defaultdict
import time
from oui_database import load_local_oui_database

class NetworkDiscovery:
    def __init__(self):
        # Load OUI (Organizationally Unique Identifier) database for vendor lookup
        self.oui_db = self.load_oui_database()
        
    def load_oui_database(self):
        """Load MAC address to vendor mapping"""
        # You can download this from IEEE or use a static database
        # For demo purposes, here's a small sample
        return load_local_oui_database()
    
    def ping_sweep(self, network):
        """Perform ping sweep on network range"""
        alive_hosts = []
        network_obj = ipaddress.IPv4Network(network, strict=False)
        
        def ping_host(ip):
            try:
                if platform.system().lower() == 'windows':
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], #windows
                                          capture_output=True, text=True, timeout=3)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], #mac
                                          capture_output=True, text=True, timeout=3)
                return str(ip) if result.returncode == 0 else None
            except:
                return None
        
        # Use threading for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(ping_host, ip) for ip in network_obj.hosts()]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)
        
        return alive_hosts
    
    def get_arp_table(self):
        """Get ARP table entries"""
        arp_entries = {}
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                # Parse Windows ARP output
                for line in result.stdout.split('\n'):
                    if '---' in line or not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1]
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                            arp_entries[ip] = mac.upper().replace('-', ':')
            else:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                # Parse Unix/Linux ARP output
                for line in result.stdout.split('\n'):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line)
                    if match:
                        ip, mac = match.groups()
                        arp_entries[ip] = mac.upper()
        except Exception as e:
            print(f"Error getting ARP table: {e}")
        
        return arp_entries
    
    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def get_vendor_from_mac(self, mac_address):
        """Get vendor from MAC address using OUI database"""
        if not mac_address:
            return "Unknown"
        
        # Get first 3 octets (OUI)
        oui = ':'.join(mac_address.split(':')[:3])
        return self.oui_db.get(oui, "Unknown")
    
    def classify_device(self, hostname, vendor, ip, open_ports=None):
        """Classify device type based on available information"""
        hostname_lower = hostname.lower()
        vendor_lower = vendor.lower()
        
        # Classification based on hostname patterns
        if any(keyword in hostname_lower for keyword in ['router', 'rt-', 'gw-', 'gateway']):
            return "Router"
        elif any(keyword in hostname_lower for keyword in ['switch', 'sw-', 'access']):
            return "Switch"
        elif any(keyword in hostname_lower for keyword in ['firewall', 'fw-', 'pfsense', 'sophos']):
            return "Firewall"
        elif any(keyword in hostname_lower for keyword in ['server', 'srv-', 'web', 'mail', 'dns', 'dc-']):
            return "Server"
        elif any(keyword in hostname_lower for keyword in ['printer', 'print']):
            return "Printer"
        elif any(keyword in hostname_lower for keyword in ['ap-', 'wifi', 'wireless']):
            return "Access Point"
        
        # Classification based on vendor
        if any(vendor_name in vendor_lower for vendor_name in ['cisco', 'juniper', 'mikrotik']):
            return "Network Equipment"
        elif any(vendor_name in vendor_lower for vendor_name in ['hp', 'canon', 'xerox', 'brother']):
            return "Printer"
        elif vendor_lower in ['raspberry pi foundation']:
            return "IoT Device"
        elif any(vendor_name in vendor_lower for vendor_name in ['vmware', 'virtualbox', 'qemu']):
            return "Virtual Machine"
        
        # Classification based on common ports (if provided)
        if open_ports:
            if 80 in open_ports or 443 in open_ports:
                return "Web Server"
            elif 22 in open_ports:
                return "Linux Server"
            elif 3389 in open_ports:
                return "Windows Server"
            elif 161 in open_ports:
                return "Network Equipment"
        
        return "Unknown Device"
    
    def port_scan(self, ip, ports=[22, 23, 80, 443, 161, 3389]):
        """Quick port scan to help with device classification"""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports
    
    def discover_network(self, network_range, include_port_scan=False):
        """Main discovery function"""
        print(f"Starting network discovery for {network_range}")
        
        # Step 1: Ping sweep
        print("Performing ping sweep...")
        alive_hosts = self.ping_sweep(network_range)
        print(f"Found {len(alive_hosts)} alive hosts")
        
        # Step 2: Get ARP table
        print("Getting ARP table...")
        arp_table = self.get_arp_table()
        
        # Step 3: Gather device information
        devices = []
        for ip in alive_hosts:
            print(f"Gathering info for {ip}...")
            
            # Get hostname
            hostname = self.get_hostname(ip)
            
            # Get MAC address from ARP table
            mac_address = arp_table.get(ip, None)
            
            # Get vendor from MAC
            vendor = self.get_vendor_from_mac(mac_address) if mac_address else "Unknown"
            
            # Optional port scan
            open_ports = []
            if include_port_scan:
                open_ports = self.port_scan(ip)
            
            # Classify device
            device_type = self.classify_device(hostname, vendor, ip, open_ports)
            
            device_info = {
                'ip': ip,
                'hostname': hostname,
                'mac_address': mac_address,
                'vendor': vendor,
                'type': device_type,
                'open_ports': open_ports
            }
            
            devices.append(device_info)
        
        return devices
    
    def add_manual_device(self, ip, hostname=None, device_type=None):
        """Manually add a device"""
        if not hostname:
            hostname = self.get_hostname(ip)
        
        # Try to get MAC from ARP table
        arp_table = self.get_arp_table()
        mac_address = arp_table.get(ip, None)
        vendor = self.get_vendor_from_mac(mac_address) if mac_address else "Unknown"
        
        if not device_type:
            device_type = self.classify_device(hostname, vendor, ip)
        
        return {
            'ip': ip,
            'hostname': hostname,
            'mac_address': mac_address,
            'vendor': vendor,
            'type': device_type,
            'open_ports': []
        }

def main():
    # Example usage
    discovery = NetworkDiscovery()
    
    # Discover devices on local network
    # Change this to your network range
    network_range = "192.168.1.0/24"
    
    # Discover devices (set include_port_scan=True for more detailed classification)
    devices = discovery.discover_network(network_range, include_port_scan=True)
    
    # Display results
    print("\n" + "="*80)
    print("NETWORK DISCOVERY RESULTS")
    print("="*80)
    
    device_counts = defaultdict(int)
    
    for device in devices:
        print(f"\nIP Address: {device['ip']}")
        print(f"Hostname: {device['hostname']}")
        print(f"MAC Address: {device['mac_address'] or 'Unknown'}")
        print(f"Vendor: {device['vendor']}")
        print(f"Device Type: {device['type']}")
        if device['open_ports']:
            print(f"Open Ports: {', '.join(map(str, device['open_ports']))}")
        print("-" * 40)
        
        device_counts[device['type']] += 1
    
    # Summary
    print(f"\nSUMMARY:")
    print(f"Total devices found: {len(devices)}")
    for device_type, count in device_counts.items():
        print(f"{device_type}: {count}")
    
    # Example of manual device addition
    print("\nAdding manual device...")
    manual_device = discovery.add_manual_device("192.168.1.1", "Router", "Router")
    print(f"Manual device: {manual_device}")

main()