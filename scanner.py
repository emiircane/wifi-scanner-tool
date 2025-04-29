from scapy.all import ARP, Ether, srp
from scapy.layers.l2 import getmacbyip
import nmap
import ipaddress
from typing import List, Dict
import logging
from datetime import datetime
import time
from utils import get_mac_vendor

class NetworkScanner:
    def __init__(self, interface: str = None):
        self.interface = interface
        self.nm = nmap.PortScanner()
        self.devices = []

    def get_network_range(self, ip: str, netmask: str) -> str:
        """Convert IP and netmask to CIDR notation."""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception as e:
            logging.error(f"Error calculating network range: {e}")
            return None

    def arp_scan(self, network: str) -> List[Dict]:
        """Perform ARP scan on the network."""
        try:
            # Create ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send packet and capture responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                vendor = get_mac_vendor(mac)
                
                device = {
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'status': 'Active',
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'open_ports': [],
                    'os': 'Unknown',
                    'hostname': 'Unknown'
                }
                devices.append(device)
                logging.info(f"Found device: {ip} ({mac}) - {vendor}")
            
            return devices
        except Exception as e:
            logging.error(f"Error during ARP scan: {e}")
            return []

    def port_scan(self, ip: str) -> Dict:
        """Perform port scan on a specific IP."""
        try:
            # Perform a basic TCP scan of common ports with timeout
            self.nm.scan(ip, arguments='-sT -F --max-retries 1 --host-timeout 10s')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                return {
                    'open_ports': list(host_info.get('tcp', {}).keys()),
                    'os': host_info.get('osmatch', [{}])[0].get('name', 'Unknown'),
                    'hostname': host_info.get('hostname', 'Unknown')
                }
            return {}
        except Exception as e:
            logging.error(f"Error during port scan: {e}")
            return {}

    def scan_network(self, ip: str, netmask: str) -> List[Dict]:
        """Perform complete network scan."""
        try:
            # Get network range
            network = self.get_network_range(ip, netmask)
            if not network:
                raise Exception("Ağ aralığı hesaplanamadı")

            logging.info(f"Starting network scan on {network}")
            
            # Perform ARP scan first
            devices = self.arp_scan(network)
            if not devices:
                logging.warning("No devices found during ARP scan")
                return []
            
            # Return devices immediately after ARP scan
            # Port scanning will be done separately if needed
            self.devices = devices
            return devices
            
        except Exception as e:
            logging.error(f"Error during network scan: {e}")
            raise

    def get_scan_results(self) -> List[Dict]:
        """Return the results of the last scan."""
        return self.devices 