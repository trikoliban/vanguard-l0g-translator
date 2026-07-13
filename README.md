# Vanguard Log Translator & Decryptor

Riot Vanguard anti-cheat çekirdek (`vgk.sys`) ve istemci (`vgc.exe`) log dosyalarını otomatik olarak çözen (decrypt) ve anlaşılır, temiz açıklamalara çeviren evrensel bir Windows aracıdır.

Vanguard logları normalde ham olay kodları (Event ID), bellek adresleri, işlem numaraları (PID) ve hex kodlarından ibarettir. Bu araç, gizlilik amacıyla tüm sistem belirteçlerini (PIDs, hex pointer'lar, handle nesneleri) temizler ve karmaşık olay numaralarını okunabilir açıklamalara dönüştürür.

## 🚀 Öne Çıkan Özellikler

* **🔑 Hibrit Şifre Çözücü ve Çevirici**: Şifreli log dosyalarını (`pvpv` sihirli başlığı ile başlayanları) otomatik olarak algılar ve çeviriye başlamadan önce yerleşik RC4 şifre çözme mekanizmasıyla çözer.
* **🔒 Güvenlik & Anonimleştirme**: Kişisel gizlilik ve güvenlik için ham işlem tanıtıcılarını (handles), iş parçacığı kimliklerini (TID), işlem kimliklerini (PID) ve çekirdek bellek adreslerini loglardan tamamen temizler.
* **🌐 VGC & VGK Çevirisi**: Sürücü olaylarını (Örn: `B000003C`, `B000003B`) ve istemci olaylarını (Örn: `139`, `163`, `164`, `199`) doğrudan anlaşılır teknik açıklamalara dönüştürür.
* **📁 Toplu Klasör İşleme**: Tek bir log dosyasını veya çok sayıda log dosyası içeren komple bir klasörü tek seferde işleyebilir.
* **📂 Akıllı Masaüstü Yolu Çözücü**: Türkçe karakterli masaüstü yollarında (`Masaüstü` gibi) veya OneDrive yönlendirmelerinde yaşanan karakter kodlaması (Unicode) hatalarını önlemek için Windows kayıt defterinden gerçek masaüstü yolunu dinamik olarak tespit eder.
* **🛡️ Yetki Sınırı Koruması**: Windows'un korumalı sistem klasörlerine (Örn: `C:\Program Files\Riot Vanguard\Logs`) doğrudan yazma izni verilmediğinde, çıktıları otomatik olarak masaüstünüzdeki `Translated_Vanguard_Logs` klasörüne yönlendirir.

## 📋 Çeviri Örnekleri

### Vanguard Sürücü Derleme Bilgisi
* **Öncesi**: `[2025-08-17_09-46-13] [!] [1000004A]: 1.17.12.4 ; Wed Aug  6 17:39:45 2025`
* **Sonrası**: `[2025-08-17_09-46-13] Vanguard driver build version 1.17.12.4 compiled on Wednesday August 6, 17:39:45 2025.`

### Süreç Takibi (Surveillance)
* **Öncesi**: `[2025-08-17_09-46-23] [!] [B000003C]: 912 ; FFFF950F830B6080 ; 0 ; 1 ; csrss.exe`
* **Sonrası**: `[2025-08-17_09-46-23] Process placed under surveillance: Process csrss is now closely monitored.`

### İstemci Gecikme Testi
* **Öncesi**: `[2025-11-28_17-18-20] [19736][11/28/25 17:18:20][i]: 163: 110`
* **Sonrası**: `[2025-11-28_17-18-20] Latency check: Network round-trip latency of 110 milliseconds verified.`

---

## 🛠️ Kullanım

### Hızlı Başlangıç (Windows)
1. [vanguard_log_translator.bat](vanguard_log_translator.bat) dosyasına çift tıklayın.
2. Açılan menüde `3` yazıp onaylayarak Vanguard loglarının varsayılan konumunu taratın. Çözülen ve çevrilen loglar masaüstünüzdeki `Translated_Vanguard_Logs` klasörüne otomatik olarak çıkartılacaktır.
3. Dilerseniz herhangi bir log dosyasını veya klasörünü doğrudan `.bat` dosyasının üzerine sürükleyip bırakarak da çevirebilirsiniz.

### Komut Satırı (CLI)
Log dosyasını veya klasörünü komut satırından manuel çevirmek için:
```bash
python vanguard_log_translator.py <girdi_yolu> <cikti_yolu>
```

---

## ⚙️ Gereksinimler
* **İşletim Sistemi**: Windows 10 / 11
* **Python**: Python 3.x yüklü olmalıdır.
