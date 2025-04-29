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

def generate_html_report(devices: List[Dict], filename: str = 'report.html') -> None:
    """Generate an HTML report of scanned devices."""
    try:
        report_logger.debug(f"HTML rapor oluşturuluyor: {filename}")
        report_logger.debug(f"Cihaz sayısı: {len(devices)}")
        
        # Cihaz verilerini kontrol et
        for i, device in enumerate(devices):
            report_logger.debug(f"Cihaz {i+1}: {device}")
        
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left; 
        }
        th { 
            background-color: #f2f2f2; 
        }
        tr:nth-child(even) { 
            background-color: #f9f9f9; 
        }
        .timestamp { 
            color: #666; 
            margin-bottom: 20px; 
        }
    </style>
</head>
<body>
    <h1>Network Scan Report</h1>
    <div class="timestamp">Generated on: {timestamp}</div>
    <table>
        <tr>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Vendor</th>
            <th>Status</th>
            <th>Open Ports</th>
            <th>OS</th>
            <th>Last Seen</th>
        </tr>""".format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        for device in devices:
            try:
                # Open ports'u güvenli bir şekilde işle
                open_ports = device.get('open_ports', [])
                if isinstance(open_ports, list):
                    open_ports_str = ', '.join(map(str, open_ports)) or 'None'
                else:
                    open_ports_str = str(open_ports) or 'None'
                
                html_content += f"""
        <tr>
            <td>{device.get('ip', 'N/A')}</td>
            <td>{device.get('mac', 'N/A')}</td>
            <td>{device.get('vendor', 'Unknown')}</td>
            <td>{device.get('status', 'Unknown')}</td>
            <td>{open_ports_str}</td>
            <td>{device.get('os', 'Unknown')}</td>
            <td>{device.get('last_seen', 'N/A')}</td>
        </tr>"""
            except Exception as e:
                report_logger.error(f"Cihaz verisi işlenirken hata: {str(e)}")
                continue

        html_content += """
    </table>
</body>
</html>"""

        # Dosyayı yazmadan önce dizini kontrol et
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            report_logger.debug(f"Dizin oluşturuldu: {directory}")

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        report_logger.info(f"HTML rapor başarıyla oluşturuldu: {filename}")
        
    except Exception as e:
        report_logger.error(f"HTML rapor oluşturma hatası: {str(e)}", exc_info=True)
        # Hatayı yut ve devam et
        pass

def log_scan_results(devices: List[Dict], filename: str = 'log.csv') -> None:
    """Log scan results to a CSV file."""
    try:
        report_logger.debug(f"CSV log oluşturuluyor: {filename}")
        report_logger.debug(f"Cihaz sayısı: {len(devices)}")
        
        import pandas as pd
        from datetime import datetime
        
        # Cihaz verilerini kontrol et
        for i, device in enumerate(devices):
            report_logger.debug(f"Cihaz {i+1}: {device}")
        
        # Convert devices to DataFrame
        df = pd.DataFrame(devices)
        
        # Add timestamp
        df['scan_timestamp'] = datetime.now()
        
        # Ensure all columns exist
        required_columns = ['ip', 'mac', 'vendor', 'status', 'open_ports', 'os', 'last_seen']
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
        # Hatayı yut ve devam et
        pass 