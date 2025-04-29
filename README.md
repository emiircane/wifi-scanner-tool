# WiFi Tarayıcı Aracı

Yerel ağınızdaki cihazlar hakkında detaylı bilgi sağlayan kapsamlı bir ağ tarama aracı. PyQt6 tabanlı modern bir kullanıcı arayüzü ile kullanımı kolay ve güçlü bir ağ analiz aracıdır.

## Özellikler

- **Modern Kullanıcı Arayüzü**
  - PyQt6 tabanlı sezgisel arayüz
  - Gerçek zamanlı ilerleme göstergesi
  - Detaylı sonuç tablosu
  - Ağ arayüzü seçimi ve yenileme

- **Gelişmiş Ağ Tarama**
  - ARP ve ICMP taraması
  - Port taraması ve işletim sistemi tespiti
  - MAC adresi üretici bilgisi sorgulama
  - Cihaz aktivite izleme

- **Otomatik Kurulum ve Yapılandırma**
  - Nmap otomatik kurulum ve yapılandırma
  - Yönetici hakları otomatik kontrolü
  - Gerekli bağımlılıkların otomatik yönetimi

- **Kapsamlı Raporlama**
  - HTML formatında detaylı raporlar
  - CSV formatında log kayıtları
  - Cihaz detayları ve istatistikler
  - Hata durumunda bile çalışmaya devam etme

- **Güvenlik ve Hata Yönetimi**
  - Kapsamlı hata yakalama ve loglama
  - Güvenli thread yönetimi
  - Kullanıcı dostu hata mesajları
  - Tarama işlemini güvenli şekilde durdurma

## Gereksinimler

- Python 3.8+
- Windows 10/11
- Yönetici/administrator yetkileri (ağ taraması için)
- Gerekli Python paketleri (requirements.txt dosyasına bakın)

## Kurulum

1. Depoyu klonlayın:
```bash
git clone https://github.com/emiircane/wifi-scanner-tool.git
cd wifi-scanner-tool
```

2. Bağımlılıkları yükleyin:
```bash
pip install -r requirements.txt
```

## Kullanım

Programı çalıştırmak için üç yöntem var:

1. **Batch Dosyası ile Çalıştırma**:
   - `run_as_admin.bat` dosyasına çift tıklayın
   - Windows güvenlik uyarısında "Evet" veya "Allow" düğmesine tıklayın

2. **PowerShell ile Çalıştırma**:
   - PowerShell'i yönetici olarak açın
   - Şu komutu çalıştırın:
   ```powershell
   Start-Process python -ArgumentList "main.py" -Verb RunAs
   ```

3. **Normal Çalıştırma**:
   - Komut satırında şu komutu çalıştırın:
   ```bash
   python main.py
   ```
   - Program otomatik olarak yönetici hakları isteyecektir

## Program Kullanımı

1. Program başladığında, ağ arayüzlerini gösteren bir açılır liste göreceksiniz
2. Taramak istediğiniz ağ arayüzünü seçin
3. "Taramayı Başlat" düğmesine tıklayın
4. Tarama ilerlemesini ilerleme çubuğundan takip edin
5. Tarama tamamlandığında sonuçlar tabloda görüntülenecek
6. HTML rapor ve CSV log dosyaları otomatik olarak oluşturulacak

## Proje Yapısı

- `main.py` - Ana uygulama giriş noktası
- `gui.py` - PyQt6 tabanlı kullanıcı arayüzü
- `scanner.py` - Ağ tarama işlevselliği
- `utils.py` - Yardımcı fonksiyonlar ve raporlama
- `requirements.txt` - Gerekli Python paketleri
- `run_as_admin.bat` - Yönetici haklarıyla çalıştırma betiği
- `report.html` - Oluşturulan HTML raporları
- `log.csv` - Aktivite günlükleri

## Güvenlik Uyarısı

Bu araç yalnızca eğitim ve ağ yönetimi amaçlıdır. Sahibi olmadığınız veya yönetmediğiniz ağları taramadan önce mutlaka gerekli izinleri alın.

## Hata Ayıklama

Program çalışırken sorun yaşarsanız:

1. Log dosyalarını kontrol edin:
   - `network_scan.log` - Genel log kayıtları
   - `gui_debug.log` - Kullanıcı arayüzü logları
   - `scan_debug.log` - Tarama işlemi logları

2. Nmap'in doğru kurulu olduğundan emin olun
3. Programı yönetici haklarıyla çalıştırdığınızdan emin olun
4. Güvenlik duvarı ayarlarınızı kontrol edin

## Lisans

MIT Lisansı 