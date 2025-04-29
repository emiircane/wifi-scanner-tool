import sys
import os
import subprocess
import requests
import winreg
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QComboBox, QTableWidget, 
                            QTableWidgetItem, QLabel, QProgressBar, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
import logging
from datetime import datetime
import tempfile
import time
import win32com.client
import psutil
import socket
import ctypes

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

class ScanWorker(QThread):
    """Arka planda tarama işlemini gerçekleştiren worker thread"""
    finished = pyqtSignal(list)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)
    
    def __init__(self, interface_ip, interface_netmask):
        super().__init__()
        self.interface_ip = interface_ip
        self.interface_netmask = interface_netmask
        self.scanner = None
        self.is_running = False
        
        # Loglama ayarlarını güncelle
        self.logger = logging.getLogger('ScanWorker')
        self.logger.setLevel(logging.DEBUG)
        
        # Dosyaya loglama
        fh = logging.FileHandler('scan_debug.log')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
    def run(self):
        try:
            self.is_running = True
            self.logger.info(f"Tarama başlatılıyor - IP: {self.interface_ip}, Netmask: {self.interface_netmask}")
            
            # Scanner'ı başlat
            try:
                self.scanner = NetworkScanner()
                self.logger.debug("NetworkScanner başarıyla oluşturuldu")
            except Exception as e:
                self.logger.error(f"NetworkScanner oluşturma hatası: {str(e)}")
                raise
            
            # Başlangıç ilerlemesi
            self.progress.emit(10)
            self.logger.debug("İlerleme: 10%")
            
            # Ağ taramasını başlat
            try:
                self.logger.debug("Ağ taraması başlatılıyor...")
                devices = self.scanner.scan_network(self.interface_ip, self.interface_netmask)
                self.logger.info(f"Ağ taraması tamamlandı. Bulunan cihaz sayısı: {len(devices) if devices else 0}")
            except Exception as e:
                self.logger.error(f"Ağ tarama hatası: {str(e)}")
                raise
            
            if not devices:
                self.logger.warning("Ağda hiç cihaz bulunamadı")
                self.error.emit("Ağda hiç cihaz bulunamadı.")
                return
            
            self.progress.emit(50)
            self.logger.debug("İlerleme: 50%")
            
            # Her cihaz için port taraması yap
            total_devices = len(devices)
            self.logger.info(f"Port taraması başlatılıyor. Toplam cihaz sayısı: {total_devices}")
            
            for i, device in enumerate(devices):
                if not self.is_running:
                    self.logger.info("Tarama kullanıcı tarafından durduruldu")
                    break
                
                try:
                    self.logger.debug(f"Port taraması başlatılıyor - Cihaz {i+1}/{total_devices}: {device['ip']}")
                    port_info = self.scanner.port_scan(device['ip'])
                    devices[i].update(port_info)
                    self.logger.debug(f"Port taraması tamamlandı - Cihaz: {device['ip']}")
                    
                    progress = 50 + int((i + 1) / total_devices * 50)
                    self.progress.emit(progress)
                    self.logger.debug(f"İlerleme: {progress}%")
                    
                except Exception as e:
                    self.logger.error(f"Port tarama hatası ({device['ip']}): {str(e)}")
                    continue
            
            if self.is_running:
                self.logger.info("Tarama başarıyla tamamlandı")
                self.finished.emit(devices)
            
        except Exception as e:
            error_msg = f"Tarama sırasında hata oluştu: {str(e)}"
            self.logger.error(error_msg, exc_info=True)  # Tam hata stack'ini logla
            self.error.emit(error_msg)
        finally:
            self.is_running = False
            self.logger.info("Tarama thread'i sonlandırıldı")
            
    def stop(self):
        """Taramayı güvenli bir şekilde durdur"""
        self.logger.info("Tarama durdurma isteği alındı")
        self.is_running = False
        self.wait()
        self.logger.info("Tarama durduruldu")

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
        self.setWindowTitle("WiFi Tarayıcı Aracı")
        self.setMinimumSize(800, 600)
        
        # Ana widget ve layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Başlık
        title = QLabel("WiFi Tarayıcı Aracı")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Arayüz seçimi
        interface_layout = QHBoxLayout()
        interface_label = QLabel("Ağ Arayüzü:")
        self.interface_combo = QComboBox()
        self.refresh_interfaces()
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        layout.addLayout(interface_layout)
        
        # Tarama butonu
        self.scan_button = QPushButton("Taramayı Başlat")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        # İlerleme çubuğu
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Sonuç tablosu
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(7)
        self.result_table.setHorizontalHeaderLabels([
            "IP Adresi", "MAC Adresi", "Üretici", "Durum", 
            "Açık Portlar", "İşletim Sistemi", "Son Görülme"
        ])
        layout.addWidget(self.result_table)
        
        # Yenile butonu
        refresh_button = QPushButton("Arayüzleri Yenile")
        refresh_button.clicked.connect(self.refresh_interfaces)
        layout.addWidget(refresh_button)
        
        # Durum çubuğu
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        self.scan_worker = None

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
        try:
            self.logger.info("Tarama başlatma isteği alındı")
            
            if not self.interface_combo.currentText():
                self.logger.warning("Ağ arayüzü seçilmedi")
                QMessageBox.warning(self, "Uyarı", "Lütfen bir ağ arayüzü seçin.")
                return
            
            # Nmap kontrolü
            if not check_nmap_installation():
                self.logger.info("Nmap kurulu değil, kurulum başlatılıyor")
                self.check_and_install_nmap()
                return
            
            # Arayüz bilgilerini al
            interface_data = self.interface_combo.currentData()
            if not interface_data:
                self.logger.warning("Geçerli ağ arayüzü seçilmedi")
                QMessageBox.warning(self, "Uyarı", "Geçerli bir ağ arayüzü seçilmedi.")
                return
            
            self.logger.info(f"Seçilen arayüz: {interface_data}")
            
            # Önceki tarama varsa durdur
            if self.scan_worker and self.scan_worker.isRunning():
                self.logger.info("Önceki tarama durduruluyor")
                self.scan_worker.stop()
            
            # Yeni tarama başlat
            self.scan_worker = ScanWorker(interface_data['ip'], interface_data['netmask'])
            self.scan_worker.progress.connect(self.update_progress)
            self.scan_worker.finished.connect(self.scan_finished)
            self.scan_worker.error.connect(self.scan_error)
            
            # UI'ı güncelle
            self.scan_button.setText("Taramayı Durdur")
            self.scan_button.clicked.disconnect()
            self.scan_button.clicked.connect(self.stop_scan)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.result_table.setRowCount(0)
            
            self.logger.info("Tarama başlatılıyor")
            self.scan_worker.start()
            
        except Exception as e:
            error_msg = f"Tarama başlatılırken hata oluştu: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            QMessageBox.critical(self, "Hata", error_msg)
            self.reset_scan_ui()
            
    def stop_scan(self):
        """Aktif taramayı durdur"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
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
        """İlerleme çubuğunu günceller"""
        self.progress_bar.setValue(value)
        if value == 10:
            self.status_label.setText("Scanner başlatılıyor...")
        elif value == 20:
            self.status_label.setText("Ağ taraması yapılıyor...")
        elif value == 100:
            self.status_label.setText("Tarama tamamlandı!")

    def scan_finished(self, devices):
        """Tarama tamamlandığında çağrılır"""
        try:
            self.logger.info("Tarama sonuçları alındı, UI güncelleniyor")
            
            # UI kontrollerini güncelle
            self.reset_scan_ui()
            self.status_label.setText(f"Tarama tamamlandı! {len(devices)} cihaz bulundu.")
            self.logger.debug("UI kontrolleri güncellendi")
            
            try:
                # Tabloyu güncelle
                self.logger.debug("Tablo güncelleniyor")
                self.result_table.setRowCount(len(devices))
                
                for row, device in enumerate(devices):
                    try:
                        # Her bir hücreyi güvenli bir şekilde güncelle
                        items = [
                            (0, device.get('ip', 'N/A')),
                            (1, device.get('mac', 'N/A')),
                            (2, device.get('vendor', 'Unknown')),
                            (3, device.get('status', 'Unknown')),
                            (4, ', '.join(map(str, device.get('open_ports', []))) or 'None'),
                            (5, device.get('os', 'Unknown')),
                            (6, device.get('last_seen', 'N/A'))
                        ]
                        
                        for col, value in items:
                            try:
                                item = QTableWidgetItem(str(value))
                                self.result_table.setItem(row, col, item)
                            except Exception as e:
                                self.logger.error(f"Hücre güncelleme hatası (satır {row}, sütun {col}): {str(e)}")
                                
                    except Exception as e:
                        self.logger.error(f"Satır güncelleme hatası (satır {row}): {str(e)}")
                        continue
                
                self.logger.debug("Tablo başarıyla güncellendi")
                
            except Exception as e:
                self.logger.error(f"Tablo güncelleme hatası: {str(e)}")
                QMessageBox.warning(self, "Uyarı", "Sonuçlar tabloya yüklenirken hata oluştu!")
            
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
            
        except Exception as e:
            error_msg = f"Sonuçları işlerken hata oluştu: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            QMessageBox.critical(self, "Hata", error_msg)
        finally:
            self.progress_bar.setVisible(False)

    def scan_error(self, error_message):
        """Tarama sırasında hata oluştuğunda çağrılır"""
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Tarama sırasında hata oluştu!")
        QMessageBox.critical(self, "Hata", f"Tarama sırasında bir hata oluştu:\n{error_message}")

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