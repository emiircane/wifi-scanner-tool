import psutil
import requests
import socket
from typing import Dict, List, Tuple
import logging
from datetime import datetime
import os

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_scan.log'),
        logging.StreamHandler()
    ]
)

# Raporlama için özel logger
report_logger = logging.getLogger('report_generator')
report_logger.setLevel(logging.DEBUG)

def get_network_interfaces() -> List[Dict[str, str]]:
    """Get all available network interfaces and their IP addresses."""
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                ip = addr.address
                if not ip.startswith('127.'):  # Skip localhost
                    interfaces.append({
                        'name': iface,
                        'ip': ip,
                        'netmask': addr.netmask
                    })
    return interfaces

def get_interface_info(interface_name: str) -> Dict[str, str]:
    """Get detailed information about a specific network interface."""
    logger = logging.getLogger('utils')
    try:
        # Eğer interface_name bir string ise ve parantez içinde IP adresi varsa
        if '(' in interface_name and ')' in interface_name:
            # Parantez içindeki IP adresini çıkar
            ip = interface_name.split('(')[1].split(')')[0]
            name = interface_name.split('(')[0].strip()
            
            # Ağ arayüzlerini al
            interfaces = get_network_interfaces()
            
            # IP adresine göre arayüzü bul
            for iface in interfaces:
                if iface['ip'] == ip:
                    logger.debug(f"Arayüz bilgileri bulundu: {iface}")
                    return iface
                    
            # Eğer bulunamazsa, varsayılan netmask ile döndür
            logger.warning(f"Arayüz bulunamadı, varsayılan netmask kullanılıyor: {ip}")
            return {
                'name': name,
                'ip': ip,
                'netmask': '255.255.255.0'  # Varsayılan netmask
            }
        else:
            # Arayüz adına göre arayüzü bul
            interfaces = get_network_interfaces()
            for iface in interfaces:
                if iface['name'] == interface_name:
                    logger.debug(f"Arayüz bilgileri bulundu: {iface}")
                    return iface
                    
            logger.error(f"Arayüz bulunamadı: {interface_name}")
            return None
            
    except Exception as e:
        logger.error(f"Arayüz bilgileri alınamadı: {str(e)}", exc_info=True)
        return None

def get_mac_vendor(mac_address: str) -> str:
    """Look up the vendor of a MAC address using the macvendors.com API."""
    try:
        # Remove any separators and convert to uppercase
        mac = mac_address.replace(':', '').replace('-', '').upper()
        # Use first 6 characters (OUI)
        oui = mac[:6]
        
        response = requests.get(f'https://api.macvendors.com/{oui}')
        if response.status_code == 200:
            return response.text
        return "Unknown"
    except Exception as e:
        logging.error(f"Error looking up MAC vendor: {e}")
        return "Unknown"

def generate_html_report(devices, filename='report.html'):
    """HTML raporu oluşturur"""
    try:
        # Raporlar için dizin oluştur
        reports_dir = 'reports'
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            
        report_path = os.path.join(reports_dir, filename)
        
        # HTML şablonu
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Ağ Tarama Raporu</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                    text-align: center;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                    background-color: white;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
                }
                th, td {
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #4CAF50;
                    color: white;
                }
                tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
                tr:hover {
                    background-color: #ddd;
                }
                .timestamp {
                    text-align: right;
                    color: #666;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <h1>Ağ Tarama Raporu</h1>
            <div class="timestamp">Oluşturulma Zamanı: {timestamp}</div>
            <table>
                <tr>
                    <th>IP Adresi</th>
                    <th>MAC Adresi</th>
                    <th>Hostname</th>
                    <th>Üretici</th>
                    <th>Açık Portlar</th>
                    <th>İşletim Sistemi</th>
                    <th>Servisler</th>
                    <th>Son Görülme</th>
                    <th>Durum</th>
                </tr>
        """
        
        # Cihaz bilgilerini ekle
        for device in devices:
            html_template += """
                <tr>
                    <td>{ip}</td>
                    <td>{mac}</td>
                    <td>{hostname}</td>
                    <td>{vendor}</td>
                    <td>{open_ports}</td>
                    <td>{os}</td>
                    <td>{services}</td>
                    <td>{last_seen}</td>
                    <td>{status}</td>
                </tr>
            """.format(
                ip=device.get('ip', 'Unknown'),
                mac=device.get('mac', 'Unknown'),
                hostname=device.get('hostname', 'Unknown'),
                vendor=device.get('vendor', 'Unknown'),
                open_ports=', '.join(map(str, device.get('open_ports', []))),
                os=device.get('os', 'Unknown'),
                services=device.get('services', 'Unknown'),
                last_seen=device.get('last_seen', 'Unknown'),
                status=device.get('status', 'Unknown')
            )
            
        # HTML'i kapat
        html_template += """
            </table>
        </body>
        </html>
        """
        
        # Raporu kaydet
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_template.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            
        logging.info(f"HTML raporu oluşturuldu: {report_path}")
        return True
        
    except Exception as e:
        logging.error(f"HTML rapor oluşturma hatası: {str(e)}", exc_info=True)
        return False

def log_scan_results(devices: List[Dict], filename: str = 'log.csv') -> None:
    """Log scan results to a CSV file."""
    try:
        report_logger.debug(f"CSV log oluşturuluyor: {filename}")
        report_logger.debug(f"Cihaz sayısı: {len(devices)}")
        
        import pandas as pd
        from datetime import datetime
        
        # Cihaz verilerini kontrol et ve logla
        for i, device in enumerate(devices):
            report_logger.debug(f"Cihaz {i+1} detayları:")
            report_logger.debug(f"  IP: {device.get('ip', 'N/A')}")
            report_logger.debug(f"  MAC: {device.get('mac', 'N/A')}")
            report_logger.debug(f"  Hostname: {device.get('hostname', 'N/A')}")
            report_logger.debug(f"  Vendor: {device.get('vendor', 'Unknown')}")
            report_logger.debug(f"  Status: {device.get('status', 'Unknown')}")
            report_logger.debug(f"  Open Ports: {device.get('open_ports', [])}")
            report_logger.debug(f"  OS: {device.get('os', 'Unknown')}")
            report_logger.debug(f"  Services: {device.get('services', 'N/A')}")
            report_logger.debug(f"  Last Seen: {device.get('last_seen', 'N/A')}")
        
        # Convert devices to DataFrame
        df = pd.DataFrame(devices)
        
        # Add timestamp
        df['scan_timestamp'] = datetime.now()
        
        # Ensure all columns exist
        required_columns = ['ip', 'mac', 'hostname', 'vendor', 'status', 'open_ports', 'os', 'services', 'last_seen']
        for col in required_columns:
            if col not in df.columns:
                df[col] = 'N/A'
        
        # Convert open_ports list to string
        def safe_convert_ports(ports):
            try:
                if isinstance(ports, list):
                    return ', '.join(map(str, ports))
                return str(ports) or 'None'
            except:
                return 'None'
        
        df['open_ports'] = df['open_ports'].apply(safe_convert_ports)
        
        # Dosyayı yazmadan önce dizini kontrol et
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            report_logger.debug(f"Dizin oluşturuldu: {directory}")
        
        # Write to CSV
        df.to_csv(filename, mode='a', header=not os.path.exists(filename), index=False, encoding='utf-8')
        report_logger.info(f"CSV log başarıyla oluşturuldu: {filename}")
        
    except Exception as e:
        report_logger.error(f"CSV log oluşturma hatası: {str(e)}", exc_info=True)
        raise  # Hatayı yukarı fırlat 