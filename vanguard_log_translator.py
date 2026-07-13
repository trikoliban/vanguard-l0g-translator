import os
import re
import sys
import glob
import struct

# Türkçe Gün ve Ay Eşleştirmeleri
DAYS = {"Mon": "Pazartesi", "Tue": "Salı", "Wed": "Çarşamba", "Thu": "Perşembe", "Fri": "Cuma", "Sat": "Cumartesi", "Sun": "Pazar"}
MONTHS = {
    "Jan": "Ocak", "Feb": "Şubat", "Mar": "Mart", "Apr": "Nisan", 
    "May": "Mayıs", "Jun": "Haziran", "Jul": "Temmuz", "Aug": "Ağustos", 
    "Sep": "Eylül", "Oct": "Ekim", "Nov": "Kasım", "Dec": "Aralık"
}

NTSTATUS_MAP = {
    "C0000001": "STATUS_UNSUCCESSFUL",
    "C0000002": "STATUS_NOT_IMPLEMENTED",
    "C0000003": "STATUS_INVALID_INFO_CLASS",
    "C0000022": "STATUS_ACCESS_DENIED",
    "C0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
    "C00000BB": "STATUS_NOT_SUPPORTED",
    "C0000225": "STATUS_NOT_FOUND",
    "C0000365": "STATUS_FAIL_FAST_EXCEPTION",
    "C0000005": "STATUS_ACCESS_VIOLATION",
    "00000000": "STATUS_SUCCESS"
}

# Vanguard Şifre Çözme Sabitleri (decryptor (1).py dosyasından)
CONST_A = bytes.fromhex('c379b147423ef709fdb94dce8fafb8f8')
CONST_B = bytes.fromhex('84d314fc0adc36674a72e10ef02e5ccb')
MASK = CONST_A + CONST_B

def rc4_decrypt_record(rec, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    dec = []
    for char in rec:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        dec.append(char ^ S[(S[i] + S[j]) % 256])
    return bytes(dec)

def decrypt_log_data(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'pvpv':
                return None  # Şifresiz düz metin veya farklı format
            
            f.read(4) # versiyon/dolgu
            key_bytes = f.read(32)
            
            records = []
            while True:
                len_bytes = f.read(8)
                if not len_bytes or len(len_bytes) < 8:
                    break
                rec_len = struct.unpack('<Q', len_bytes)[0]
                payload = f.read(rec_len)
                records.append(payload)
                
        real_key = bytes([b ^ m for b, m in zip(key_bytes, MASK)])
        decrypted_lines = []
        for payload in records:
            dec = rc4_decrypt_record(payload, real_key)
            text = dec.decode('utf-16-le', errors='ignore').strip()
            if text:
                decrypted_lines.append(text)
        return decrypted_lines
    except Exception as e:
        print(f"[-] Hata - Şifre çözülemedi {os.path.basename(file_path)}: {e}")
        return None

def get_desktop_path():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        val, _ = winreg.QueryValueEx(key, "Desktop")
        val = os.path.expandvars(val)
        return val
    except Exception:
        home = os.path.expanduser("~")
        for folder in ["OneDrive/Masaüstü", "Masaüstü", "OneDrive/Desktop", "Desktop"]:
            p = os.path.join(home, folder)
            if os.path.exists(p):
                return p
        return os.path.join(home, "Desktop")

def clean_process_name(name):
    return name.replace(".exe", "").replace(".sys", "")

def translate_ntstatus(code):
    code_upper = code.upper().strip()
    if code_upper in NTSTATUS_MAP:
        return NTSTATUS_MAP[code_upper]
    if all(c in '0123456789ABCDEFabcdef' for c in code_upper):
        return "STATUS_" + code_upper
    return code

def translate_date_time(date_time_str):
    m = re.search(r'([A-Za-z]{3})\s+([A-Za-z]{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})', date_time_str)
    if m:
        day_name = DAYS.get(m.group(1), m.group(1))
        month_name = MONTHS.get(m.group(2), m.group(2))
        day_num = m.group(3)
        return f"{day_name} {month_name} {day_num}, {m.group(4)}:{m.group(5)}:{m.group(6)} {m.group(7)}"
    return date_time_str

def sanitize_arguments(parts):
    cleaned = []
    for p in parts:
        p_strip = p.strip()
        if not p_strip:
            continue
        if len(p_strip) >= 8 and all(c in '0123456789ABCDEFabcdef' for c in p_strip):
            continue
        if p_strip.isdigit() and len(p_strip) >= 3 and int(p_strip) > 500 and int(p_strip) != 26100:
            continue
        
        if p_strip.endswith('.exe') or p_strip.endswith('.sys'):
            cleaned.append(clean_process_name(p_strip))
        else:
            cleaned.append(p_strip)
    return cleaned

# Çekirdek (VGK) Olay Çevirici (Türkçe)
def translate_vgk_line(code, args):
    args = args.split('<<<')[0].strip()
    parts = [p.strip() for p in args.split(';') if p.strip()]
    
    if code == "1000002A":
        return "Sürücü iletişim kanalı başarıyla aktif edildi."
    elif code == "1000004A":
        if len(parts) >= 2:
            ver = parts[0]
            date_time = translate_date_time(parts[1])
            return f"Vanguard sürücü derleme sürümü {ver}, {date_time} tarihinde derlendi."
        return "Vanguard sürücü sürümü ve derleme tarihi doğrulandı."
    elif code == "1000004E":
        if len(parts) >= 3:
            return f"İşletim sistemi detayları: Windows sürümü {parts[0]}.{parts[1]} derleme {parts[2]}."
        return "İşletim sistemi sürüm bilgisi günlüğe kaydedildi."
    elif code == "10000051":
        return "Sürücü durum kontrolü: Dahili sürücü rutini tamamlandı."
    elif code == "1000006D":
        return "Vanguard çekirdek modülü vgk.sys başarıyla yüklendi."
    elif code == "100000FA":
        return "Oyun istemcisi süreç takibi sonlandırıldı."
    elif code == "100000FB":
        return "Oyun istemcisi süreç takibi başlatıldı."
    elif code in ("1000165", "10000165"):
        return "Sürücü durumu: Çekirdek telemetri kontrolü 165 tamamlandı."
    elif code in ("1000166", "10000166"):
        return "Sürücü durumu: Çekirdek telemetri kontrolü 166 tamamlandı."
    elif code == "B0000001":
        return "Sürücü başlatma aşama 1 tamamlandı."
    elif code == "B0000002":
        return "Sürücü başlatma aşama 2 tamamlandı."
    elif code == "B0000017":
        return "Güvenlik uyarısı: Güvensiz veya imzasız bir sürücünün yüklenmesi engellendi."
    elif code in ("B0000028", "B0000041", "B0000043"):
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        if len(proc_names) >= 2:
            src = clean_process_name(proc_names[0])
            dst = clean_process_name(proc_names[1])
            return f"Erişim isteği: {src} süreci, {dst} sürecine erişim talep etti."
        return "Aktif süreçler arasındaki erişim isteği denetlendi."
    elif code in ("B0000029", "B0000042", "B0000044"):
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        if len(proc_names) >= 2:
            src = clean_process_name(proc_names[0])
            dst = clean_process_name(proc_names[1])
            return f"Tutamaç oluşturma: {src} süreci, {dst} süreci için bir tutamaç (handle) açtı."
        return "Tutamaç kopyalama veya oluşturma olayı denetlendi."
    elif code == "B000003B":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        name = clean_process_name(proc_names[0]) if proc_names else "izlenen süreç"
        status_part = parts[-1] if parts else "00000000"
        status_text = translate_ntstatus(status_part)
        return f"Süreç sonlandırıldı: İzlenen {name} süreci {status_text} durumuyla kapandı."
    elif code == "B000003C":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        name = clean_process_name(proc_names[0]) if proc_names else "hedef süreç"
        return f"Süreç takibe alındı: {name} süreci artık yakından izleniyor."
    elif code == "B00000B7":
        return "İşlem başarıyla tamamlandı."
    elif code == "B00000D3":
        return "Sürücü durum kontrolü: İmza veri tabanı kontrolü tamamlandı."
    elif code == "B00000D8":
        return "Donanım ve sürücü imza doğrulaması başlatıldı."
    elif code == "B00000DE":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p.isalpha()]
        name = clean_process_name(proc_names[0]) if proc_names else "güvenilir servis"
        return f"Güvenilir servis süreci kaydedildi: {name}."
    elif code == "B00000DF":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        if len(proc_names) >= 2:
            src = clean_process_name(proc_names[0])
            dst = clean_process_name(proc_names[1])
            return f"Süreç etkileşimi: {src} süreci, {dst} süreciyle etkileşime girdi."
        return "Süreçler arası çekirdek etkileşim olayı günlüğe kaydedildi."
    elif code == "B00000E7":
        if len(parts) >= 2:
            return f"Sürücü parametre kalibrasyonu: İşlem durumu doğrulandı (durumlar: {parts[0]}, {parts[1]})."
        return "Sürücü parametre kalibrasyonu: İşlem durumu doğrulandı."
    elif code == "B00000F1":
        if parts:
            return f"Sürücü metrik kontrolü: {parts[0]} değeri bildirildi."
        return "Sürücü metrik kontrolü: Değer bildirildi."
    elif code == "B0000106":
        return "Çekirdek güvenlik kontrolü: Aktif kritik sistem süreçleri doğrulandı."
    elif code == "B0000124":
        if parts:
            return f"Sistem derleme kontrolü: {parts[0]} değeri doğrulandı."
        return "Sistem derleme kontrolü: Değer doğrulandı."
    elif code == "B0000133":
        return "Sürücü durum sorgusu: Fonksiyon STATUS_NOT_SUPPORTED durumu döndürdü."
    elif code == "E0000045":
        return "Çekirdek tahsisi: Sistem bellek bloğu tahsis edildi."
    elif code == "E0000050":
        if parts:
            status = translate_ntstatus(parts[0])
            return f"Hata: {status} durumu ile hızlı hata (fail fast) istisnası oluştu."
        return "Hata: Hızlı hata (fail fast) istisnası oluştu."
    elif code == "E0000054":
        return "Uyumluluk uyarısı: Donanım sanallaştırma veya Güvenilir Platform Modülü (TPM) durumu uyumsuz."
    elif code == "E0000055":
        return "Güvenlik uyarısı: Hipervizör korumalı Kod Bütünlüğü (HVCI) veya Güvenli Önyükleme (Secure Boot) kapalı."
    elif code == "E0000057":
        return "Sistem bütünlüğü uyarısı: Windows çekirdek hata ayıklama modu veya test imzalama açık."
    elif code == "E000005A":
        return "Donanım kısıtlaması veya BIOS doğrulaması başarısız oldu."
    elif code in ("E0000067", "E000006C"):
        return "Sürücü durum kontrolü: Dahili kod kontrolü tamamlandı."
    elif code == "E0000089":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys')]
        name = clean_process_name(proc_names[0]) if proc_names else "süreç"
        return f"Süreç uyarısı: {name} sürecinde şüpheli davranış veya çökme yöneticisi aktivitesi tespit edildi."
    elif code == "E0000097":
        if parts:
            return f"Güvenlik uyarısı: Süreç belleğinde {parts[0]} adresinde imzasız veya şüpheli kod enjeksiyonu tespit edildi."
        return "Güvenlik uyarısı: Süreç belleğinde imzasız veya şüpheli kod enjeksiyonu tespit edildi."
    elif code == "E00000AF":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys')]
        pname = clean_process_name(proc_names[0]) if proc_names else "ana süreç"
        dll_name = "modül dosyası"
        for p in parts:
            if p.endswith('.dll'):
                dll_name = p.split('\\')[-1]
                break
        return f"Modül yükleme: {dll_name} dosyası {pname} sürecine yüklendi."
    elif code == "E00000C3":
        return "Modül bellek taraması: Yüklü bir modülün bellek bölgesi tarandı."
    elif code == "E00000D9":
        return "Hata: Güvenli bellek bölgesi doğrulanamadı."
    elif code == "E00000E1":
        if parts:
            return f"Sürücü durum değişikliği: Durum kodu {parts[0]} olarak güncellendi."
        return "Sürücü durum değişikliği: Durum kodu güncellendi."
    elif code == "E00000EF":
        driver_name = "sürücü dosyası"
        for p in parts:
            if p.endswith('.sys'):
                driver_name = p.split('\\')[-1]
                break
        return f"Yüklenen {driver_name} sürücü dosyası tarandı."
    elif code == "E000012D":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys')]
        name = clean_process_name(proc_names[0]) if proc_names else "izlenen süreç"
        return f"Süreç bellek taraması: {name} sürecinde bellek adresi tarandı."
    elif code == "E000013B":
        return "İmza doğrulaması: Sürücü kod imzası doğrulandı."
    elif code == "E0000143":
        return "İşlem başarıyla tamamlandı."
    elif code == "E0000144":
        return "Hata: İşlem veya fonksiyon desteklenmiyor / uygulanmadı."
    elif code == "E0000145":
        return "Zamanlama kontrolü: Dahili zamanlama kalibrasyonu tamamlandı."
    elif code == "E0000148":
        return "Sistem kontrolü: İş parçacığı veya süreç bağlamı doğrulandı."
    elif code == "E000015E":
        return "Bağlantı hatası: İstemci ve sunucu arasındaki el sıkışma zaman aşımına uğradı."
    elif code == "E0000161":
        if len(parts) >= 2:
            return f"Zamanlama doğrulaması: Zaman Damgası Sayacı döngü kontrolü tamamlandı (döngü sayısı: {parts[0]}, frekans: {parts[1]})."
        return "Zamanlama doğrulaması: Zaman Damgası Sayacı döngü kontrolü tamamlandı."
    elif code == "E000016A":
        return "Sürücü durumu: Periyodik sağlık kontrolü tamamlandı."
    elif code == "E000016E":
        return "Sürücü durumu: Telemetri kalp atışı sinyali gönderildi."
    elif code == "E0000171":
        if parts:
            return f"Sürücü hata kodu bildirildi: {parts[0]}."
        return "Sürücü hata kodu bildirildi."
    elif code == "FFFFFFFF":
        if parts:
            status = translate_ntstatus(parts[0])
            return f"Hata detayları: {status} durumu döndü."
        return "Hata detayları: Nesne bulunamadı veya işlem başarısız oldu."
        
    # Genel VGK Fallback
    cleaned_args = sanitize_arguments(parts)
    if cleaned_args:
        return f"Sürücü olayı: {code} kodlu dahili olay başarıyla işlendi (detaylar: {', '.join(cleaned_args)})."
    return f"Sürücü olayı: {code} kodlu dahili olay başarıyla işlendi."

# İstemci (VGC) Olay Çevirici (Türkçe)
def translate_vgc_line(code, args):
    args = args.split('<<<')[0].strip()
    parts = [p.strip() for p in args.split(';') if p.strip()]
    
    if code == "0":
        if len(parts) >= 2:
            ver = parts[0]
            date_time = translate_date_time(parts[1])
            return f"Vanguard istemci sürümü {ver}, {date_time} tarihinde derlendi."
        return "Vanguard istemci sürüm bilgisi günlüğe kaydedildi."
    elif code == "-1":
        if parts:
            status = translate_ntstatus(parts[0])
            return f"Hata durumu: Süreç kimliği veya kod {status} döndürdü."
        return "Hata durumu: Kaynak veya yol adı bulunamadı."
    elif code in ("141", "67"):
        if parts:
            return f"Bağlantı noktası bağlantısı: {parts[0]} adresindeki sunucuya bağlanılıyor."
        return "Bağlantı noktası bağlantısı: El sıkışma dizisi başlatıldı."
    elif code == "71":
        if parts:
            return f"Ağ yanıtı: Sunucu HTTP durum kodu {parts[0]} döndürdü."
        return "Ağ yanıtı: Durum başarıyla alındı."
    elif code in ("187", "195"):
        return "Veri aktarım durumu: İşlem başarıyla tamamlandı."
    elif code == "181":
        return "Oturum başlatıldı: Oyun süreci için izleme oturumu kuruldu."
    elif code == "48":
        return "Oturum kapatıldı."
    elif code in ("191", "192", "194"):
        return "El sıkışma aşaması güncellendi."
    elif code in ("81", "162"):
        cleaned_args = sanitize_arguments(parts)
        if cleaned_args:
            joined = ", ".join(cleaned_args[0].split()) if len(cleaned_args) == 1 else ", ".join(cleaned_args)
            return f"Veri iletimi: Karşılaştırmalı gecikme doğrulandı (detaylar: {joined})."
        return "Veri iletimi: Karşılaştırmalı gecikme doğrulandı."
    elif code == "83":
        return "Nabız kontrolü doğrulandı."
    elif code in ("51", "52", "54"):
        return "İstemci başlatma adımı tamamlandı."
    elif code == "37":
        if parts:
            return f"Bellek bölgesi {parts[0]} taban adresinde eşlendi."
        return "Bellek bölgesi eşlendi."
    elif code == "39":
        return "Bellek bölgesi eşlenmesi kaldırıldı."
    elif code == "90":
        if parts:
            return f"Kalp atışı sinyali doğrulandı (değer: {parts[0]})."
        return "Kalp atışı sinyali doğrulandı."
    elif code in ("153", "155"):
        if parts:
            return f"Durum değişikliği olayı işlendi (yeni durum: {parts[0]})."
        return "Durum değişikliği olayı işlendi."
    
    # Özel VGC Olay Kod Eşleştirmeleri
    elif code == "139":
        val = parts[0] if parts else "bilinmiyor"
        return f"CPU çekirdek kontrolü: Mantıksal işlemci Core {val} üzerinde güvenlik taraması yapıldı."
    elif code == "163":
        val = parts[0] if parts else "bilinmiyor"
        return f"Gecikme kontrolü: Sunucu git-gel gecikme süresi {val} milisaniye olarak doğrulandı."
    elif code == "164":
        val = parts[0] if parts else "bilinmiyor"
        return f"El sıkışma durumu: Bağlantı el sıkışma paket sırası {val} doğrulandı."
    elif code == "165":
        return "Bağlantı ayakta tutma sinyali: Bağlantı durum kontrolü doğrulandı."
    elif code == "199":
        val = parts[0] if parts else "bilinmiyor"
        return f"Nabız sinyali: Durum raporu dizini {val} gönderildi."
    elif code == "160":
        val = parts[0] if parts else "1"
        return f"Kriptografik el sıkışma: İstemci anahtar değişim aşaması {val} doğrulandı."
    elif code == "91":
        return "Oturum durum kontrolü: Aktif oturum bağlantısı doğrulandı."
    elif code == "69":
        return "Bağlantı durumu: Sunucu ile güvenli bağlantı kuruldu."
    elif code == "70":
        return "Bağlantı durumu: İstemci bağlantı durumu güncellendi."
    elif code == "200":
        return "Bağlantı doğrulaması: Durum aktif."
    elif code == "208":
        return "Oturum parametreleri: Durum yapılandırması doğrulandı."
    elif code == "21":
        return "Başlatma kontrolü: Başlangıç dizisi onaylandı."
    elif code == "214":
        return "Oturum parametre güncellemesi: Dahili doğrulama tamamlandı."
    elif code == "6":
        return "Başlangıç doğrulaması: Güvenlik kimlik bilgileri onaylandı."
    elif code in ("72", "73"):
        return "Bağlantı durumu: Uç nokta durumu doğrulandı."
    elif code == "79":
        return "Bağlantı kesme olayı: Oturum bağlantısı başarıyla kesildi."
    elif code in ("84", "85", "89"):
        return "El sıkışma durumu: Doğrulama dizisi tamamlandı."
    elif code in ("93", "94"):
        return "El sıkışma dizisi: Doğrulama durumu güncellendi."
    
    # Genel VGC Fallback
    cleaned_args = sanitize_arguments(parts)
    desc = f"İstemci log olay numarası {code} gerçekleşti."
    if cleaned_args:
        desc += f" Bağlam detayları: {' '.join(cleaned_args)}."
    return desc

def process_log_line(line):
    vgk_match = re.match(r'^(\[[^\]]+\]\s+\[[^\]]+\]\s+\[)([^\]]+)(\]):(.*)', line)
    if vgk_match:
        prefix_start = vgk_match.group(1)
        code = vgk_match.group(2)
        prefix_end = vgk_match.group(3)
        rest = vgk_match.group(4)
        translation = translate_vgk_line(code, rest)
        timestamp = prefix_start.split(']')[0].strip('[')
        return f"[{timestamp}] {translation}"
        
    vgc_match = re.match(r'^(\[[^\]]+\]\s*\[)([^\]]+)(\]\s*\[[^\]]+\]\s*:\s*)(-?\d+)\s*:(.*)', line)
    if vgc_match:
        prefix_start = vgc_match.group(1)
        timestamp = vgc_match.group(2)
        prefix_end = vgc_match.group(3)
        code = vgc_match.group(4)
        rest = vgc_match.group(5)
        translation = translate_vgc_line(code, rest)
        
        date_time_parts = re.search(r'(\d+)/(\d+)/(\d+)\s+(\d+):(\d+):(\d+)', timestamp)
        if date_time_parts:
            m = date_time_parts.group(1)
            d = date_time_parts.group(2)
            y = date_time_parts.group(3)
            hr = date_time_parts.group(4)
            mn = date_time_parts.group(5)
            sc = date_time_parts.group(6)
            yr_full = "20" + y if len(y) == 2 else y
            timestamp_clean = f"{yr_full}-{m}-{d}_{hr}-{mn}-{sc}"
        else:
            timestamp_clean = timestamp
            
        return f"[{timestamp_clean}] {translation}"
        
    return line

def translate_file(in_path, out_path):
    line_count = 0
    try:
        decrypted_lines = decrypt_log_data(in_path)
        
        if decrypted_lines is not None:
            with open(out_path, 'w', encoding='utf-8') as outfile:
                for line in decrypted_lines:
                    if line.strip():
                        outfile.write(process_log_line(line) + '\n')
                        line_count += 1
        else:
            with open(in_path, 'r', encoding='utf-8', errors='ignore') as infile:
                with open(out_path, 'w', encoding='utf-8') as outfile:
                    for line in infile:
                        if line.strip():
                            outfile.write(process_log_line(line) + '\n')
                            line_count += 1
        return True, line_count
    except PermissionError:
        fallback_dir = os.path.join(get_desktop_path(), "Translated_Vanguard_Logs")
        os.makedirs(fallback_dir, exist_ok=True)
        fallback_out = os.path.join(fallback_dir, f"translated_{os.path.basename(in_path)}")
        print(f"[-] Hata - Yazma yetkisi yok: {out_path}")
        print(f"[*] Çıktı buraya yönlendiriliyor: {fallback_out}")
        return translate_file(in_path, fallback_out)

def main():
    if len(sys.argv) < 3:
        input_path = r"C:\Program Files\Riot Vanguard\Logs"
        desktop = get_desktop_path()
        output_path = os.path.join(desktop, "Translated_Vanguard_Logs")
        print(f"[*] Argüman girilmedi. Varsayılan yollar kullanılıyor:")
        print(f"[*] Girdi: {input_path}")
        print(f"[*] Çıktı: {output_path}")
        print("-" * 50)
    else:
        input_path = sys.argv[1]
        output_path = sys.argv[2]
    
    if not os.path.exists(input_path):
        print(f"Hata: Girdi yolu mevcut değil: {input_path}")
        sys.exit(1)
        
    if os.path.isdir(input_path):
        print(f"[*] Klasördeki tüm log dosyaları çevriliyor: {input_path}")
        
        out_dir = output_path
        try:
            os.makedirs(out_dir, exist_ok=True)
            test_file = os.path.join(out_dir, ".write_test")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except PermissionError:
            out_dir = os.path.join(get_desktop_path(), "Translated_Vanguard_Logs")
            os.makedirs(out_dir, exist_ok=True)
            print(f"[-] Hata - Klasöre yazma yetkisi yok: {output_path}")
            print(f"[*] Çıktı klasörü buraya yönlendirildi: {out_dir}")
            
        files = glob.glob(os.path.join(input_path, "*.txt")) + glob.glob(os.path.join(input_path, "*.log"))
        if not files:
            print("[-] Klasörde log veya metin dosyası bulunamadı.")
            return
            
        translated_count = 0
        for f in files:
            file_name = os.path.basename(f)
            if file_name.startswith("translated_"):
                continue
            out_file = os.path.join(out_dir, f"translated_{file_name}")
            try:
                success, line_cnt = translate_file(f, out_file)
                if success:
                    print(f"[+] Çevrildi: {file_name} ({line_cnt} satır)")
                    translated_count += 1
            except Exception as e:
                print(f"[-] Çeviri başarısız oldu {file_name}: {e}")
        print(f"[#] Tamamlandı! Başarıyla {translated_count} dosya çevrildi.")
        
    else:
        try:
            success, line_count = translate_file(input_path, output_path)
            if success:
                print(f"[+] Başarılı! {line_count} satır başarıyla çevrildi.")
        except Exception as e:
            print(f"[-] Çeviri hatası: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
