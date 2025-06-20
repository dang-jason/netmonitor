import requests
import re
import json

def download_oui_database():
    """Download and parse IEEE OUI database"""
    url = "https://standards-oui.ieee.org/oui/oui.txt"
    
    try:
        print("Downloading OUI database...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        oui_dict = {}
        
        for line in response.text.split('\n'):
            if '(hex)' in line:
                parts = line.split('\t')
                if len(parts) >= 3:
                    # Extract MAC prefix (first 3 octets)
                    mac_prefix = parts[0].replace('(hex)', '').strip()
                    mac_prefix = mac_prefix.replace('-', ':')
                    
                    # Extract vendor name
                    vendor = parts[2].strip()
                    
                    oui_dict[mac_prefix] = vendor
        
        print(f"Loaded {len(oui_dict)} vendor entries")
        
        # Save to file for future use
        with open('oui_database.json', 'w') as f:
            json.dump(oui_dict, f, indent=2)
        
        return oui_dict
        
    except Exception as e:
        print(f"Error downloading OUI database: {e}")
        return {}

def load_local_oui_database():
    """Load OUI database from local file"""
    try:
        with open('oui_database.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Local OUI database not found, downloading...")
        return download_oui_database()

# Alternative: Using netaddr library (install with: pip install netaddr)
def get_vendor_with_netaddr(mac_address):
    """Get vendor using netaddr library"""
    try:
        from netaddr import EUI
        mac = EUI(mac_address)
        return mac.oui.registration().org
    except:
        return "Unknown"
    