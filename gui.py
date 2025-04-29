import sys
import os
import subprocess
import requests
import winreg
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QComboBox, QTableWidget, 
                            QTableWidgetItem, QLabel, QProgressBar, QMessageBox,
                            QTabWidget, QSplitter, QLineEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QDateTime
from PyQt6.QtGui import QFont, QIcon, QPainter
from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QDateTimeAxis, QValueAxis
import logging
from datetime import datetime
import tempfile
import time
import win32com.client
import psutil
import socket
import ctypes
import random

from utils import generate_html_report, log_scan_results
from scanner import NetworkScanner

def is_admin():
    """Uygulamanın yönetici haklarıyla çalışıp çalışmadığını kontrol eder"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Uygulamayı yönetici haklarıyla yeniden başlatır"""
    try:
        if sys.argv[-1] != 'asadmin':
            script = os.path.abspath(sys.argv[0])
            params = ' '.join(sys.argv[1:] + ['asadmin'])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, script, None, 1)
            sys.exit()
    except Exception as e:
        logging.error(f"Yönetici hakları alınamadı: {e}")
        return False
    return True

def get_network_interfaces():
    """Sistemdeki ağ arayüzlerini listeler"""
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # Sadece IPv4 adreslerini al
                interfaces.append({
                    'name': iface,
                    'ip': addr.address,
                    'netmask': addr.netmask
                })
    return interfaces

def add_to_path(path):
    """PATH değişkenine kalıcı olarak yeni bir yol ekler"""
    try:
        # Windows Registry'den mevcut PATH'i al
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", 0, winreg.KEY_ALL_ACCESS)
        current_path = winreg.QueryValueEx(key, "Path")[0]
        
        # Eğer yol zaten PATH'te değilse ekle
        if path not in current_path:
            new_path = current_path + ";" + path
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
            winreg.CloseKey(key)
            
            # Değişiklikleri sistem genelinde yayınla
            subprocess.run(['setx', 'PATH', new_path], check=True)
            
            # Windows'a PATH değişikliğini bildir
            shell = win32com.client.Dispatch("WScript.Shell")
            shell.Environment("PROCESS")["PATH"] = new_path
            
            return True
        return True
    except Exception as e:
        logging.error(f"PATH güncelleme hatası: {e}")
        return False

def check_nmap_installation():
    """Nmap'in yüklü olup olmadığını kontrol eder"""
    try:
        # Önce Registry'de kontrol et
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Nmap")
        nmap_path = winreg.QueryValueEx(key, "InstallDir")[0]
        winreg.CloseKey(key)
        
        # Nmap'in çalıştırılabilir dosyasını kontrol et
        nmap_exe = os.path.join(nmap_path, "nmap.exe")
        if os.path.exists(nmap_exe):
            # PATH'e Nmap dizinini ekle
            if nmap_path not in os.environ["PATH"]:
                add_to_path(nmap_path)
            return True
            
        # Eğer nmap.exe bulunamazsa, PATH'te ara
        for path in os.environ["PATH"].split(os.pathsep):
            nmap_exe = os.path.join(path, "nmap.exe")
            if os.path.exists(nmap_exe):
                return True
                
        return False
    except WindowsError:
        # Registry'de bulunamazsa, PATH'te ara
        for path in os.environ["PATH"].split(os.pathsep):
            nmap_exe = os.path.join(path, "nmap.exe")
            if os.path.exists(nmap_exe):
                return True
        return False

def download_and_install_nmap():
    """Nmap'i indirir ve kurar"""
    try:
        # Nmap'in en son sürümünü indir
        nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
        temp_dir = tempfile.gettempdir()
        installer_path = os.path.join(temp_dir, "nmap-setup.exe")
        
        # İndirme işlemi
        response = requests.get(nmap_url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        
        with open(installer_path, 'wb') as f:
            downloaded = 0
            for data in response.iter_content(chunk_size=4096):
                downloaded += len(data)
                f.write(data)
                # İlerleme yüzdesini hesapla
                progress = int((downloaded / total_size) * 100)
                yield progress
        
        # Kurulum işlemi
        try:
            # Önce normal kurulum dene
            result = subprocess.run([installer_path, '/S'], 
                                 capture_output=True, 
                                 text=True, 
                                 check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Normal kurulum başarısız: {e.stderr}")
            # Hata durumunda sessiz kurulum dene
            try:
                result = subprocess.run([installer_path, '/SILENT'], 
                                     capture_output=True, 
                                     text=True, 
                                     check=True)
            except subprocess.CalledProcessError as e:
                logging.error(f"Sessiz kurulum başarısız: {e.stderr}")
                # Son çare olarak manuel kurulum öner
                raise Exception("Nmap kurulumu başarısız oldu. Lütfen manuel olarak kurun: https://nmap.org/download.html")
        
        # Kurulum dosyasını temizle
        try:
            os.remove(installer_path)
        except:
            pass
        
        # Kurulumun tamamlanması için bekle
        time.sleep(5)
        
        # PATH'i güncelle
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Nmap")
            nmap_path = winreg.QueryValueEx(key, "InstallDir")[0]
            winreg.CloseKey(key)
            
            if nmap_path not in os.environ["PATH"]:
                add_to_path(nmap_path)
        except:
            pass
        
        return True
    except Exception as e:
        logging.error(f"Nmap kurulum hatası: {e}")
        return False

class NmapInstallerThread(QThread):
    """Nmap kurulum işlemini arka planda gerçekleştiren thread"""
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool)
    error = pyqtSignal(str)

    def run(self):
        try:
            for progress in download_and_install_nmap():
                self.progress.emit(progress)
            self.finished.emit(True)
        except Exception as e:
            self.error.emit(str(e))

def get_interface_info(interface_name):
    """Seçilen ağ arayüzünün IP ve netmask bilgilerini döndürür"""
    try:
        # Arayüz adından parantez içindeki IP'yi çıkar
        ip = interface_name.split('(')[1].split(')')[0]
        
        # IP adresinden ağ bilgilerini al
        interfaces = get_network_interfaces()
        for iface in interfaces:
            if iface['ip'] == ip:
                return {
                    'ip': iface['ip'],
                    'netmask': iface['netmask']
                }
        
        # Eğer bulunamazsa, varsayılan olarak /24 subnet mask kullan
        return {
            'ip': ip,
            'netmask': '255.255.255.0'
        }
    except Exception as e:
        logging.error(f"Arayüz bilgisi alınamadı: {str(e)}")
        return None

class ScanWorker(QThread):
    """Arka planda tarama işlemini gerçekleştiren worker thread"""
    progress = pyqtSignal(int)
    status = pyqtSignal(str)  # Yeni sinyal: durum mesajları için
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, scanner, interface, ip_range=None):
        super().__init__()
        self.scanner = scanner
        self.interface = interface
        self.ip_range = ip_range
        self.is_running = True
        
    def run(self):
        try:
            # Başlangıç ilerlemesi
            self.progress.emit(0)
            self.status.emit("Tarama başlatılıyor...")
            
            # ARP taraması başlat
            self.progress.emit(10)
            self.status.emit("ARP taraması yapılıyor...")
            devices = self.scanner.scan_network(self.interface, self.ip_range)
            
            if not devices:
                self.error.emit("Hiç cihaz bulunamadı")
                return
                
            # İlerleme güncellemesi
            total_devices = len(devices)
            self.status.emit(f"{total_devices} cihaz bulundu. Detaylı tarama başlatılıyor...")
            
            # Her cihaz için ilerleme güncelle
            for i, device in enumerate(devices):
                if not self.is_running:
                    return
                    
                # Her cihaz için ilerleme güncelle (10% - 90% arası)
                progress = 10 + int((i + 1) / total_devices * 80)
                self.progress.emit(progress)
                self.status.emit(f"Cihaz {i+1}/{total_devices} taranıyor: {device['ip']}")
                
            # Rapor oluşturma
            self.progress.emit(90)
            self.status.emit("Raporlar oluşturuluyor...")
            
            # Tarama tamamlandı
            self.progress.emit(100)
            self.status.emit("Tarama tamamlandı!")
            self.finished.emit(devices)
            
        except Exception as e:
            self.error.emit(f"Tarama sırasında hata: {str(e)}")
            
    def stop(self):
        self.is_running = False

class DeviceActivityChart(QChart):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Cihaz Aktivite Grafiği")
        self.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        self.legend().setVisible(True)
        self.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        
        # Zaman ekseni
        self.timeAxis = QDateTimeAxis()
        self.timeAxis.setFormat("HH:mm:ss")
        self.timeAxis.setTitleText("Zaman")
        self.addAxis(self.timeAxis, Qt.AlignmentFlag.AlignBottom)
        
        # Değer ekseni
        self.valueAxis = QValueAxis()
        self.valueAxis.setTitleText("Aktivite Seviyesi")
        self.valueAxis.setRange(0, 100)
        self.addAxis(self.valueAxis, Qt.AlignmentFlag.AlignLeft)
        
        self.series = {}
        self.maxPoints = 100  # Maksimum veri noktası sayısı
        
    def addDevice(self, device_ip):
        if device_ip not in self.series:
            series = QLineSeries()
            series.setName(device_ip)
            self.addSeries(series)
            series.attachAxis(self.timeAxis)
            series.attachAxis(self.valueAxis)
            self.series[device_ip] = series
            
    def updateDeviceActivity(self, device_ip, activity_level):
        if device_ip not in self.series:
            self.addDevice(device_ip)
            
        series = self.series[device_ip]
        current_time = QDateTime.currentDateTime()
        
        # Yeni veri noktası ekle
        series.append(current_time.toMSecsSinceEpoch(), activity_level)
        
        # Eski veri noktalarını temizle
        while series.count() > self.maxPoints:
            series.remove(0)
            
        # Eksenleri güncelle
        if series.count() > 0:
            self.timeAxis.setRange(
                QDateTime.fromMSecsSinceEpoch(series.at(0).x()),
                QDateTime.fromMSecsSinceEpoch(series.at(series.count()-1).x())
            )

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Loglama ayarlarını güncelle
        self.logger = logging.getLogger('MainWindow')
        self.logger.setLevel(logging.DEBUG)
        
        # Dosyaya loglama
        fh = logging.FileHandler('gui_debug.log')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        # GUI kurulumu
        self.setWindowTitle("WiFi Scanner Tool")
        self.setGeometry(100, 100, 800, 600)
        
        # Ana widget ve layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Tab widget oluştur
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Tarama sekmesi
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        
        # Başlık
        title = QLabel("WiFi Scanner Tool")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scan_layout.addWidget(title)
        
        # Ağ arayüzü seçimi
        interface_layout = QHBoxLayout()
        interface_label = QLabel("Ağ Arayüzü:")
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        scan_layout.addLayout(interface_layout)
        
        # IP aralığı girişi
        ip_range_layout = QHBoxLayout()
        ip_range_label = QLabel("IP Aralığı:")
        self.start_ip_input = QLineEdit()
        self.start_ip_input.setPlaceholderText("Başlangıç IP (örn: 192.168.1.1)")
        self.end_ip_input = QLineEdit()
        self.end_ip_input.setPlaceholderText("Bitiş IP (örn: 192.168.1.254)")
        ip_range_layout.addWidget(ip_range_label)
        ip_range_layout.addWidget(self.start_ip_input)
        ip_range_layout.addWidget(QLabel("-"))
        ip_range_layout.addWidget(self.end_ip_input)
        scan_layout.addLayout(ip_range_layout)
        
        # Tarama butonu
        self.scan_button = QPushButton("Taramayı Başlat")
        self.scan_button.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_button)
        
        # İlerleme çubuğu ve durum etiketi
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_label = QLabel("")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        scan_layout.addLayout(progress_layout)
        
        # Sonuç tablosu
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(7)
        self.result_table.setHorizontalHeaderLabels(["IP", "MAC", "Hostname", "Üretici", "Açık Portlar", "İşletim Sistemi", "Servisler"])
        scan_layout.addWidget(self.result_table)
        
        # Yenile butonu
        refresh_button = QPushButton("Arayüzleri Yenile")
        refresh_button.clicked.connect(self.refresh_interfaces)
        scan_layout.addWidget(refresh_button)
        
        self.scanner = NetworkScanner()
        self.worker = None
        
        # Grafik sekmesi
        chart_tab = QWidget()
        chart_layout = QVBoxLayout(chart_tab)
        
        # Aktivite grafiği
        self.activity_chart = DeviceActivityChart()
        chart_view = QChartView(self.activity_chart)
        chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        chart_layout.addWidget(chart_view)
        
        # Sekmeleri ekle
        self.tab_widget.addTab(scan_tab, "Ağ Tarama")
        self.tab_widget.addTab(chart_tab, "Aktivite Grafiği")
        
        # Aktivite güncelleme zamanlayıcısı
        self.activity_timer = QTimer()
        self.activity_timer.timeout.connect(self.updateDeviceActivity)
        self.activity_timer.start(1000)  # Her saniye güncelle

    def refresh_interfaces(self):
        """Ağ arayüzlerini yeniler"""
        self.interface_combo.clear()
        interfaces = get_network_interfaces()
        for iface in interfaces:
            self.interface_combo.addItem(f"{iface['name']} ({iface['ip']})", iface)

    def check_and_install_nmap(self):
        """Nmap'in yüklü olup olmadığını kontrol eder ve gerekirse kurar"""
        if not check_nmap_installation():
            reply = QMessageBox.question(
                self, 
                "Nmap Kurulumu Gerekli",
                "Nmap programı bulunamadı. Otomatik kurulum denensin mi?\n\n"
                "Not: Otomatik kurulum başarısız olursa, manuel kurulum için:\n"
                "1. https://nmap.org/download.html adresine gidin\n"
                "2. 'Latest stable release self-installer' bağlantısına tıklayın\n"
                "3. İndirilen dosyayı yönetici olarak çalıştırın\n"
                "4. Kurulum tamamlandıktan sonra uygulamayı yeniden başlatın",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.progress_bar.setVisible(True)
                self.progress_bar.setValue(0)
                self.scan_button.setEnabled(False)
                
                # Kurulum thread'ini başlat
                self.installer = NmapInstallerThread()
                self.installer.progress.connect(self.update_progress)
                self.installer.finished.connect(self.nmap_installation_finished)
                self.installer.error.connect(self.nmap_installation_error)
                self.installer.start()
                return False
            
            return False
        return True

    def nmap_installation_finished(self, success):
        """Nmap kurulumu tamamlandığında çağrılır"""
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        
        if success:
            QMessageBox.information(self, "Başarılı", "Nmap başarıyla kuruldu!")
            # Kurulumdan sonra biraz bekle ve tekrar kontrol et
            time.sleep(2)
            if check_nmap_installation():
                self.start_scan()
            else:
                QMessageBox.warning(self, "Uyarı", 
                    "Nmap kuruldu ancak sistem henüz tanımıyor. Lütfen uygulamayı yeniden başlatın.")
        else:
            QMessageBox.critical(self, "Hata", "Nmap kurulumu başarısız oldu!")

    def nmap_installation_error(self, error_message):
        """Nmap kurulumu sırasında hata oluştuğunda çağrılır"""
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("Kurulum Hatası")
        msg.setText("Nmap kurulumu başarısız oldu!")
        msg.setInformativeText(
            "Lütfen manuel olarak kurun:\n\n"
            "1. https://nmap.org/download.html adresine gidin\n"
            "2. 'Latest stable release self-installer' bağlantısına tıklayın\n"
            "3. İndirilen dosyayı yönetici olarak çalıştırın\n"
            "4. Kurulum tamamlandıktan sonra uygulamayı yeniden başlatın\n\n"
            "Hata detayı:\n" + error_message
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def start_scan(self):
        """Taramayı başlat"""
        try:
            # Nmap kurulumunu kontrol et
            if not check_nmap_installation():
                reply = QMessageBox.question(self, "Nmap Kurulumu",
                                          "Nmap yüklü değil. Şimdi indirip kurmak ister misiniz?",
                                          QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.Yes:
                    self.install_nmap()
                else:
                    return
            
            # IP aralığını kontrol et
            start_ip = self.start_ip_input.text().strip()
            end_ip = self.end_ip_input.text().strip()
            
            if start_ip and end_ip:
                try:
                    # IP adreslerinin geçerli olduğunu kontrol et
                    socket.inet_aton(start_ip)
                    socket.inet_aton(end_ip)
                    ip_range = f"{start_ip}-{end_ip}"
                except socket.error:
                    QMessageBox.warning(self, "Hata", "Geçersiz IP adresi formatı!")
                    return
            else:
                ip_range = None
            
            # Arayüz bilgilerini al
            interface = self.interface_combo.currentText()
            if not interface:
                QMessageBox.warning(self, "Hata", "Lütfen bir ağ arayüzü seçin!")
                return
            
            # UI güncelle
            self.scan_button.setEnabled(False)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            self.result_table.setRowCount(0)
            
            # Tarama işlemini başlat
            self.worker = ScanWorker(self.scanner, interface, ip_range)
            self.worker.progress.connect(self.update_progress)
            self.worker.status.connect(self.update_status)
            self.worker.finished.connect(self.scan_finished)
            self.worker.error.connect(self.scan_error)
            self.worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Tarama başlatılırken hata: {str(e)}")
            self.scan_button.setEnabled(True)

    def stop_scan(self):
        """Aktif taramayı durdur"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.reset_scan_ui()
            
    def reset_scan_ui(self):
        """UI'ı başlangıç durumuna getir"""
        try:
            self.scan_button.setText("Taramayı Başlat")
            self.scan_button.clicked.disconnect()
            self.scan_button.clicked.connect(self.start_scan)
            self.progress_bar.setValue(0)
            self.logger.debug("UI başarıyla sıfırlandı")
        except Exception as e:
            self.logger.error(f"UI sıfırlama hatası: {str(e)}")

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def update_status(self, message):
        self.status_label.setText(message)
        
    def scan_finished(self, devices):
        try:
            # Sonuçları sakla
            self.last_scan_results = devices
            
            # UI güncelle
            self.scan_button.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.status_label.setText(f"Tarama tamamlandı - {len(devices)} cihaz bulundu")
            
            # Tabloyu güncelle
            self.logger.debug("Tablo güncelleniyor")
            self.result_table.setRowCount(len(devices))
            
            for row, device in enumerate(devices):
                try:
                    # IP
                    self.result_table.setItem(row, 0, QTableWidgetItem(device.get('ip', 'N/A')))
                    # MAC
                    self.result_table.setItem(row, 1, QTableWidgetItem(device.get('mac', 'N/A')))
                    # Hostname
                    self.result_table.setItem(row, 2, QTableWidgetItem(device.get('hostname', 'N/A')))
                    # Vendor
                    self.result_table.setItem(row, 3, QTableWidgetItem(device.get('vendor', 'Unknown')))
                    # Open Ports
                    ports = device.get('ports', [])
                    ports_str = ', '.join(map(str, ports)) if ports else 'None'
                    self.result_table.setItem(row, 4, QTableWidgetItem(ports_str))
                    # OS
                    self.result_table.setItem(row, 5, QTableWidgetItem(device.get('os', 'Unknown')))
                    # Services
                    self.result_table.setItem(row, 6, QTableWidgetItem(device.get('services', 'N/A')))
                    
                except Exception as e:
                    self.logger.error(f"Satır güncelleme hatası (satır {row}): {str(e)}")
                    continue
            
            self.logger.debug("Tablo başarıyla güncellendi")
            
            # Raporları oluşturmayı dene
            report_errors = []
            
            try:
                # HTML raporu oluştur
                self.logger.debug("HTML rapor oluşturuluyor")
                generate_html_report(devices)
                self.logger.info("HTML rapor başarıyla oluşturuldu")
            except Exception as e:
                error_msg = f"HTML rapor oluşturma hatası: {str(e)}"
                self.logger.error(error_msg)
                report_errors.append(error_msg)
            
            try:
                # CSV logunu oluştur
                self.logger.debug("CSV log oluşturuluyor")
                log_scan_results(devices)
                self.logger.info("CSV log başarıyla oluşturuldu")
            except Exception as e:
                error_msg = f"CSV log oluşturma hatası: {str(e)}"
                self.logger.error(error_msg)
                report_errors.append(error_msg)
            
            # Rapor oluşturma hatalarını göster
            if report_errors:
                error_details = "\n\n".join(report_errors)
                QMessageBox.warning(self, "Rapor Oluşturma Hatası", 
                    "Bazı raporlar oluşturulurken hata oluştu, ancak tarama sonuçları başarıyla görüntülendi.\n\n"
                    f"Hata detayları:\n{error_details}")
            else:
                # Başarı mesajını göster
                QMessageBox.information(self, "Başarılı", 
                    f"Tarama tamamlandı!\n{len(devices)} cihaz bulundu.\nRaporlar oluşturuldu.")
            
            # Grafik sekmesine geç
            self.tab_widget.setCurrentIndex(1)
            
            # Her cihaz için grafik serisi oluştur
            for device in devices:
                self.activity_chart.addDevice(device['ip'])
            
        except Exception as e:
            error_msg = f"Sonuçları işlerken hata oluştu: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            QMessageBox.critical(self, "Hata", error_msg)
        finally:
            self.progress_bar.setVisible(False)

    def scan_error(self, error_msg):
        QMessageBox.warning(self, "Hata", error_msg)
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Tarama sırasında hata oluştu!")

    def updateDeviceActivity(self):
        """Cihaz aktivitelerini güncelle"""
        try:
            # Eğer tarama çalışıyorsa ve sonuçlar varsa
            if hasattr(self, 'worker') and self.worker and self.worker.isRunning():
                # Sonuçları al
                if hasattr(self, 'last_scan_results') and self.last_scan_results:
                    for device in self.last_scan_results:
                        # Aktivite seviyesini hesapla (örnek olarak rastgele bir değer)
                        activity_level = random.randint(0, 100)
                        self.activity_chart.updateDeviceActivity(device['ip'], activity_level)
        except Exception as e:
            self.logger.error(f"Aktivite güncelleme hatası: {str(e)}")

def main():
    # Yönetici haklarını kontrol et
    if not is_admin():
        try:
            # Yönetici haklarıyla yeniden başlat
            script = os.path.abspath(sys.argv[0])
            params = ' '.join(sys.argv[1:])
            
            # PowerShell komutu oluştur
            ps_command = f'Start-Process python -ArgumentList "{script} {params}" -Verb RunAs'
            
            # PowerShell'i yönetici olarak başlat
            subprocess.run(['powershell', '-Command', ps_command], check=True)
            sys.exit()
        except Exception as e:
            logging.error(f"Yönetici hakları alınamadı: {e}")
            QMessageBox.critical(None, "Hata", 
                "Bu uygulama yönetici hakları gerektirir. Lütfen uygulamayı yönetici olarak çalıştırın.")
            sys.exit(1)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 