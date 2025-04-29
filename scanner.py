from scapy.all import ARP, Ether, srp
from scapy.layers.l2 import getmacbyip
import nmap
import ipaddress
from typing import List, Dict
import logging
from datetime import datetime
import time
from utils import get_interface_info, get_mac_vendor
import socket
import requests

class NetworkScanner:
    def __init__(self):
        self.port_profiles = {
            'quick': [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080],
            'common': [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443, 27017],
            'full': list(range(1, 65536))
        }
        self.current_profile = 'quick'
        self.mac_cache = {}  # MAC adresi üretici bilgilerini önbellekle
        self.hostname_cache = {}  # Hostname bilgilerini önbellekle
        self.logger = logging.getLogger('NetworkScanner')
        
    def scan_network(self, interface, ip_range=None):
        try:
            # Arayüz bilgilerini al
            if isinstance(interface, str):
                # Eğer interface bir string ise, get_interface_info fonksiyonunu kullan
                interface_info = get_interface_info(interface)
                if not interface_info:
                    raise Exception("Arayüz bilgileri alınamadı")
            else:
                # Eğer interface zaten bir dict ise, doğrudan kullan
                interface_info = interface
                
            # IP aralığını belirle
            if not ip_range:
                ip = interface_info.get('ip')
                netmask = interface_info.get('netmask')
                if not ip or not netmask:
                    raise Exception("Arayüz IP ve netmask bilgileri alınamadı")
                    
                # Ağ aralığını hesapla
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                ip_range = str(network)
                
            self.logger.info(f"Ağ taraması başlatılıyor: {ip_range}")
            
            # ARP taraması yap
            devices = []
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            self.logger.debug("ARP taraması yapılıyor...")
            result = srp(packet, timeout=2, verbose=0)[0]
            
            # Bulunan cihazları listele
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self.get_mac_vendor(received.hwsrc),
                    'hostname': self.get_hostname(received.psrc),
                    'ports': [],
                    'os': 'Unknown',
                    'services': []
                })
                
            if not devices:
                self.logger.warning("Hiç cihaz bulunamadı")
                return []
                
            self.logger.info(f"{len(devices)} cihaz bulundu")
            
            # Tüm cihazlar için tek bir Nmap taraması yap
            ip_list = [device['ip'] for device in devices]
            ip_string = ' '.join(ip_list)
            
            self.logger.debug(f"Nmap taraması başlatılıyor: {ip_string}")
            nm = nmap.PortScanner()
            nm.scan(ip_string, arguments='-sS -sV -O --version-intensity 5 -T4')
            
            # Her cihaz için detaylı bilgileri topla
            for device in devices:
                ip = device['ip']
                if ip in nm.all_hosts():
                    # Port taraması sonuçları
                    if 'tcp' in nm[ip]:
                        device['ports'] = list(nm[ip]['tcp'].keys())
                        
                    # İşletim sistemi bilgisi
                    if 'osmatch' in nm[ip]:
                        os_matches = nm[ip]['osmatch']
                        if os_matches:
                            device['os'] = os_matches[0]['name']
                            
                    # Servis bilgileri
                    if 'tcp' in nm[ip]:
                        services = []
                        for port, data in nm[ip]['tcp'].items():
                            if data['state'] == 'open':
                                service = f"{port}/{data['name']}"
                                if data['product']:
                                    service += f" ({data['product']})"
                                services.append(service)
                        device['services'] = services
                        
            return devices
            
        except Exception as e:
            self.logger.error(f"Tarama sırasında hata: {str(e)}", exc_info=True)
            raise
            
    def get_mac_vendor(self, mac):
        """MAC adresi üretici bilgisini al (önbellekli)"""
        if mac in self.mac_cache:
            return self.mac_cache[mac]
            
        try:
            # MAC adresinin ilk 6 karakterini al
            mac_prefix = mac.replace(':', '').upper()[:6]
            
            # API'ye istek at
            response = requests.get(f'http://api.macvendors.com/{mac_prefix}', timeout=1)
            if response.status_code == 200:
                vendor = response.text
                self.mac_cache[mac] = vendor
                return vendor
                
        except Exception as e:
            self.logger.debug(f"MAC vendor bilgisi alınamadı: {str(e)}")
            
        return "Unknown"
        
    def get_hostname(self, ip):
        """Hostname bilgisini al (önbellekli)"""
        if ip in self.hostname_cache:
            return self.hostname_cache[ip]
            
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.hostname_cache[ip] = hostname
            return hostname
        except:
            return "Unknown"

    def get_network_range(self, ip: str, netmask: str) -> str:
        """Convert IP and netmask to CIDR notation."""
        try:
            # IP ve netmask'i IPv4Address nesnelerine dönüştür
            ip_addr = ipaddress.IPv4Address(ip)
            netmask_addr = ipaddress.IPv4Address(netmask)
            
            # Netmask'i CIDR prefix'e dönüştür
            prefix = bin(int(netmask_addr)).count('1')
            
            # Ağ adresini hesapla
            network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            return str(network)
        except Exception as e:
            self.logger.error(f"Ağ aralığı hesaplanırken hata: {e}")
            return None

    def arp_scan(self, ip):
        """
        Tek bir IP adresi için ARP taraması yapar
        """
        try:
            # ARP request oluştur
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Paketi gönder ve yanıt bekle
            result = srp(packet, timeout=1, verbose=0)[0]
            
            # Yanıt varsa cihaz çevrimiçi
            return len(result) > 0
            
        except Exception as e:
            logging.error(f"ARP tarama hatası ({ip}): {str(e)}")
            return False

    def port_scan(self, ip):
        """Belirtilen IP adresinde port taraması yapar"""
        try:
            self.logger.debug(f"Port taraması başlatılıyor: {ip}")
            
            # Nmap taraması yap
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-sS -sV -O --version-intensity 5')
            
            if ip in nm.all_hosts():
                host = nm[ip]
                
                # Açık portları topla
                open_ports = []
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        state = host[proto][port]['state']
                        if state == 'open':
                            service = host[proto][port].get('name', 'unknown')
                            version = host[proto][port].get('version', '')
                            open_ports.append(f"{port}/{service}{' (' + version + ')' if version else ''}")
                
                # İşletim sistemi bilgisini al
                os_info = 'Unknown'
                if 'osmatch' in host and host['osmatch']:
                    os_info = host['osmatch'][0]['name']
                
                # Hostname bilgisini al
                hostname = host.get('hostname', [''])[0] or 'Unknown'
                
                self.logger.debug(f"Port taraması tamamlandı: {ip} - {len(open_ports)} açık port bulundu")
                return {
                    'open_ports': open_ports,
                    'os': os_info,
                    'hostname': hostname
                }
            else:
                self.logger.warning(f"IP bulunamadı Nmap sonuçlarında: {ip}")
                return {
                    'open_ports': [],
                    'os': 'Unknown',
                    'hostname': 'Unknown'
                }
                
        except Exception as e:
            self.logger.error(f"Port taraması sırasında hata: {ip} - {str(e)}", exc_info=True)
            return {
                'open_ports': [],
                'os': 'Unknown',
                'hostname': 'Unknown'
            }

    def detect_os(self, ip):
        """IP adresinin işletim sistemini tespit eder"""
        try:
            # Nmap ile OS tespiti
            self.nm.scan(ip, arguments='-O --osscan-guess')
            if ip in self.nm.all_hosts():
                os_info = self.nm[ip].get('osmatch', [{}])[0].get('name', 'Unknown')
                return os_info
            return "Unknown"
        except:
            return "Unknown"

    def detect_services(self, ip):
        """IP adresinde çalışan servisleri tespit eder"""
        try:
            # Nmap ile servis taraması
            self.nm.scan(ip, arguments='-sV --version-intensity 5')
            if ip in self.nm.all_hosts():
                services = []
                for port in self.nm[ip].get('tcp', {}):
                    service = self.nm[ip]['tcp'][port]
                    if service.get('state') == 'open':
                        service_info = f"{service.get('name', 'unknown')} ({port})"
                        if service.get('product'):
                            service_info += f" - {service['product']}"
                        if service.get('version'):
                            service_info += f" {service['version']}"
                        services.append(service_info)
                return ', '.join(services) if services else 'No open services'
            return 'No open services'
        except:
            return 'No open services'

    def scan_ip_range(self, start_ip, end_ip):
        """Belirtilen IP aralığını tarar"""
        try:
            devices = []
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            # IP aralığını CIDR notasyonuna çevir
            network = ipaddress.IPv4Network(f"{start_ip}/24", strict=False)
            network_str = str(network)
            logging.info(f"Taranacak ağ: {network_str}")
            
            # ARP taraması yap
            arp_devices = self.arp_scan(network_str)
            
            # ARP sonuçlarını filtrele
            for device in arp_devices:
                ip = ipaddress.IPv4Address(device['ip'])
                if start <= ip <= end:
                    devices.append(device)
            
            # Her cihaz için detaylı tarama yap
            for device in devices:
                try:
                    ip = device['ip']
                    # Port taraması
                    port_info = self.port_scan(ip)
                    device.update(port_info)
                    
                    # Hostname bilgisi
                    device['hostname'] = self.get_hostname(ip)
                    
                    # İşletim sistemi tespiti
                    device['os'] = self.detect_os(ip)
                    
                    # Servis tespiti
                    device['services'] = self.detect_services(ip)
                    
                except Exception as e:
                    logging.error(f"Cihaz detay tarama hatası ({ip}): {str(e)}")
                    continue
            
            return devices
        except Exception as e:
            logging.error(f"IP aralığı tarama hatası: {str(e)}")
            raise

    def get_scan_results(self) -> List[Dict]:
        """Return the results of the last scan."""
        return self.devices 

    def monitor_devices(self, devices, callback=None):
        """
        Cihazların çevrimiçi durumunu sürekli izler
        """
        try:
            while True:
                for device in devices:
                    ip = device.get('ip')
                    if not ip:
                        continue
                        
                    # ARP ping ile cihazın çevrimiçi olup olmadığını kontrol et
                    is_online = self.arp_scan(ip)
                    
                    # Cihazın durumunu güncelle
                    device['is_online'] = is_online
                    device['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Callback fonksiyonu varsa çağır
                    if callback:
                        callback(device)
                        
                    # Her cihaz için 1 saniye bekle
                    time.sleep(1)
                    
                # Tüm cihazlar kontrol edildikten sonra 30 saniye bekle
                time.sleep(30)
                
        except Exception as e:
            logging.error(f"Cihaz izleme hatası: {str(e)}")
            if callback:
                callback({'error': str(e)}) 