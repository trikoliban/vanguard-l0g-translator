import os
import re
import sys
import glob
import struct

# Day and Month mappings
DAYS = {"Mon": "Wednesday", "Tue": "Tuesday", "Wed": "Wednesday", "Thu": "Thursday", "Fri": "Friday", "Sat": "Saturday", "Sun": "Sunday"}
MONTHS = {
    "Jan": "January", "Feb": "February", "Mar": "March", "Apr": "April", 
    "May": "May", "Jun": "June", "Jul": "July", "Aug": "August", 
    "Sep": "September", "Oct": "October", "Nov": "November", "Dec": "December"
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

# Vanguard Decryption Constants (from decryptor (1).py)
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
                return None  # Plain text decrypted log or other format
            
            f.read(4) # version/padding
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
        print(f"[-] Error trying to decrypt {os.path.basename(file_path)}: {e}")
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

# Core VGK Translator
def translate_vgk_line(code, args):
    args = args.split('<<<')[0].strip()
    parts = [p.strip() for p in args.split(';') if p.strip()]
    
    if code == "1000002A":
        return "Driver communication channel successfully activated."
    elif code == "1000004A":
        if len(parts) >= 2:
            ver = parts[0]
            date_time = translate_date_time(parts[1])
            return f"Vanguard driver build version {ver} compiled on {date_time}."
        return "Vanguard driver version and build date verified."
    elif code == "1000004E":
        if len(parts) >= 3:
            return f"Operating system details: Windows version {parts[0]}.{parts[1]} build {parts[2]}."
        return "Operating system version information logged."
    elif code == "10000051":
        return "Driver status check: Internal driver routine completed."
    elif code == "1000006D":
        return "Vanguard kernel module vgk.sys successfully loaded."
    elif code == "100000FA":
        return "Game client process tracking terminated."
    elif code == "100000FB":
        return "Game client process tracking initialized."
    elif code in ("1000165", "10000165"):
        return "Driver status: Core telemetry check 165 completed."
    elif code in ("1000166", "10000166"):
        return "Driver status: Core telemetry check 166 completed."
    elif code == "B0000001":
        return "Driver initialization phase one completed."
    elif code == "B0000002":
        return "Driver initialization phase two completed."
    elif code == "B0000017":
        return "Security alert: Blocked loading of an insecure or unsigned driver."
    elif code in ("B0000028", "B0000041", "B0000043"):
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        if len(proc_names) >= 2:
            src = clean_process_name(proc_names[0])
            dst = clean_process_name(proc_names[1])
            return f"Access request: Process {src} requested access to process {dst}."
        return "Access request between active processes was audited."
    elif code in ("B0000029", "B0000042", "B0000044"):
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        if len(proc_names) >= 2:
            src = clean_process_name(proc_names[0])
            dst = clean_process_name(proc_names[1])
            return f"Handle creation: Process {src} opened a handle to process {dst}."
        return "Handle duplication or creation event was audited."
    elif code == "B000003B":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        name = clean_process_name(proc_names[0]) if proc_names else "monitored process"
        status_part = parts[-1] if parts else "00000000"
        status_text = translate_ntstatus(status_part)
        return f"Process terminated: Monitored process {name} has closed with status {status_text}."
    elif code == "B000003C":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        name = clean_process_name(proc_names[0]) if proc_names else "target process"
        return f"Process placed under surveillance: Process {name} is now closely monitored."
    elif code == "B00000B7":
        return "Operation completed successfully."
    elif code == "B00000D3":
        return "Driver status check: Signature database check completed."
    elif code == "B00000D8":
        return "Hardware and driver signature verification initiated."
    elif code == "B00000DE":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p.isalpha()]
        name = clean_process_name(proc_names[0]) if proc_names else "trusted service"
        return f"Trusted service process registered: {name}."
    elif code == "B00000DF":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys') or p == 'System']
        if len(proc_names) >= 2:
            src = clean_process_name(proc_names[0])
            dst = clean_process_name(proc_names[1])
            return f"Process interaction: Process {src} interacted with process {dst}."
        return "Inter-process driver interaction event logged."
    elif code == "B00000E7":
        if len(parts) >= 2:
            return f"Driver parameter calibration: Operation status confirmed (states: {parts[0]}, {parts[1]})."
        return "Driver parameter calibration: Operation status confirmed."
    elif code == "B00000F1":
        if parts:
            return f"Driver metric check: Value {parts[0]} reported."
        return "Driver metric check: Value reported."
    elif code == "B0000106":
        return "Kernel security check: Active critical system processes verified."
    elif code == "B0000124":
        if parts:
            return f"System build check: Value {parts[0]} verified."
        return "System build check: Value verified."
    elif code == "B0000133":
        return "Driver status query: Function returned status STATUS_NOT_SUPPORTED."
    elif code == "E0000045":
        return "Kernel allocation: System memory block allocated."
    elif code == "E0000050":
        if parts:
            status = translate_ntstatus(parts[0])
            return f"Error: Fail fast exception occurred with status {status}."
        return "Error: Fail fast exception occurred."
    elif code == "E0000054":
        return "Compatibility warning: Hardware virtualization or Trusted Platform Module status is incompatible."
    elif code == "E0000055":
        return "Security warning: Hypervisor-protected Code Integrity or Secure Boot is disabled."
    elif code == "E0000057":
        return "System integrity warning: Windows kernel debugging mode or test signing is enabled."
    elif code == "E000005A":
        return "Hardware restriction or BIOS verification failed."
    elif code in ("E0000067", "E000006C"):
        return "Driver status check: Internal code check completed."
    elif code == "E0000089":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys')]
        name = clean_process_name(proc_names[0]) if proc_names else "process"
        return f"Process alert: Suspicious behavior or crash handler activity detected in {name}."
    elif code == "E0000097":
        if parts:
            return f"Security alert: Unsigned or suspicious code injection detected in process memory at offset {parts[0]}."
        return "Security alert: Unsigned or suspicious code injection detected in process memory."
    elif code == "E00000AF":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys')]
        pname = clean_process_name(proc_names[0]) if proc_names else "host process"
        dll_name = "module file"
        for p in parts:
            if p.endswith('.dll'):
                dll_name = p.split('\\')[-1]
                break
        return f"Module load: Loaded file {dll_name} in process {pname}."
    elif code == "E00000C3":
        return "Module memory scan: Scanned memory region of a loaded module."
    elif code == "E00000D9":
        return "Error: Failed to verify secure memory region."
    elif code == "E00000E1":
        if parts:
            return f"Driver state change: State code updated to {parts[0]}."
        return "Driver state change: State code updated."
    elif code == "E00000EF":
        driver_name = "driver file"
        for p in parts:
            if p.endswith('.sys'):
                driver_name = p.split('\\')[-1]
                break
        return f"Loaded driver file {driver_name} scanned."
    elif code == "E000012D":
        proc_names = [p for p in parts if p.endswith('.exe') or p.endswith('.sys')]
        name = clean_process_name(proc_names[0]) if proc_names else "monitored process"
        return f"Process memory scan: Scanned memory offset in process {name}."
    elif code == "E000013B":
        return "Signature verification: Driver code signature verified."
    elif code == "E0000143":
        return "Operation completed successfully."
    elif code == "E0000144":
        return "Error: Operation or function is not implemented."
    elif code == "E0000145":
        return "Timing check: Internal timing calibration completed."
    elif code == "E0000148":
        return "System check: Thread or process context verified."
    elif code == "E000015E":
        return "Connection error: Handshake between client and server timed out."
    elif code == "E0000161":
        if len(parts) >= 2:
            return f"Timing verification: Time Stamp Counter cycle check completed (cycle count: {parts[0]}, frequency: {parts[1]})."
        return "Timing verification: Time Stamp Counter cycle check completed."
    elif code == "E000016A":
        return "Driver status: Periodic health check completed."
    elif code == "E000016E":
        return "Driver status: Telemetry heartbeat tick sent."
    elif code == "E0000171":
        if parts:
            return f"Driver error code reported: {parts[0]}."
        return "Driver error code reported."
    elif code == "FFFFFFFF":
        if parts:
            status = translate_ntstatus(parts[0])
            return f"Error details: Status returned {status}."
        return "Error details: Object not found or operation failed."
        
    # General Fallback
    cleaned_args = sanitize_arguments(parts)
    if cleaned_args:
        return f"Driver event: Internal event code {code} processed successfully (details: {', '.join(cleaned_args)})."
    return f"Driver event: Internal event code {code} processed successfully."

# Core VGC Translator
def translate_vgc_line(code, args):
    args = args.split('<<<')[0].strip()
    parts = [p.strip() for p in args.split(';') if p.strip()]
    
    if code == "0":
        if len(parts) >= 2:
            ver = parts[0]
            date_time = translate_date_time(parts[1])
            return f"Vanguard client build version {ver} compiled on {date_time}."
        return "Vanguard client version info logged."
    elif code == "-1":
        if parts:
            status = translate_ntstatus(parts[0])
            return f"Error status: Process ID or code returned {status}."
        return "Error status: Resource or path name was not found."
    elif code in ("141", "67"):
        if parts:
            return f"Endpoint connection: Connecting to server at {parts[0]}."
        return "Endpoint connection: Handshake sequence initiated."
    elif code == "71":
        if parts:
            return f"Network response: Server returned HTTP status code {parts[0]}."
        return "Network response: Status received successfully."
    elif code in ("187", "195"):
        return "Data transfer status: Operation completed successfully."
    elif code == "181":
        return "Session initialized: Monitoring session established for game process."
    elif code == "48":
        return "Session closed."
    elif code in ("191", "192", "194"):
        return "Handshake phase updated."
    elif code in ("81", "162"):
        cleaned_args = sanitize_arguments(parts)
        if cleaned_args:
            # Join multiple spaces with commas for readability
            joined = ", ".join(cleaned_args[0].split()) if len(cleaned_args) == 1 else ", ".join(cleaned_args)
            return f"Data transmission: Benchmark latency verified (details: {joined})."
        return "Data transmission: Benchmark latency verified."
    elif code == "83":
        return "Heartbeat check verified."
    elif code in ("51", "52", "54"):
        return "Client initialization step completed."
    elif code == "37":
        if parts:
            return f"Memory region mapped at base {parts[0]}."
        return "Memory region mapped."
    elif code == "39":
        return "Memory region unmapped."
    elif code == "90":
        if parts:
            return f"Heartbeat tick verified (value: {parts[0]})."
        return "Heartbeat tick verified."
    elif code == "155":
        if parts:
            return f"State change event processed (new state: {parts[0]})."
        return "State change event processed."
    
    # Specific VGC event code mappings
    elif code == "139":
        val = parts[0] if parts else "unknown"
        return f"CPU core check: Security scan executed on logical processor Core {val}."
    elif code == "163":
        val = parts[0] if parts else "unknown"
        return f"Latency check: Network round-trip latency of {val} milliseconds verified."
    elif code == "164":
        val = parts[0] if parts else "unknown"
        return f"Handshake state: Connection handshake package sequence {val} verified."
    elif code == "165":
        return "Keepalive tick: Connection status check verified."
    elif code == "199":
        val = parts[0] if parts else "unknown"
        return f"Heartbeat tick: Status report index {val} sent."
    elif code == "160":
        val = parts[0] if parts else "1"
        return f"Cryptographic handshake: Client key exchange phase {val} verified."
    elif code == "91":
        return "Session state check: Active session connection verified."
    elif code == "69":
        return "Connection state: Secure link established with server."
    elif code == "70":
        return "Connection state: Client connection state updated."
    elif code == "200":
        return "Connection verification: Status active."
    elif code == "208":
        return "Session parameters: State configuration verified."
    elif code == "21":
        return "Initialization check: Startup sequence confirmed."
    elif code == "214":
        return "Session parameter update: Internal validation completed."
    elif code == "6":
        return "Startup validation: Security credentials confirmed."
    elif code in ("72", "73"):
        return "Connection status: Endpoint state verified."
    elif code == "79":
        return "Disconnect event: Session disconnected successfully."
    elif code in ("84", "85", "89"):
        return "Handshake state: Verification sequence completed."
    elif code in ("93", "94"):
        return "Handshake sequence: Verification status updated."
    
    # General VGC Fallback
    cleaned_args = sanitize_arguments(parts)
    desc = f"Client log event number {code} occurred."
    if cleaned_args:
        desc += f" Context details: {' '.join(cleaned_args)}."
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
        print(f"[-] Permission denied writing to: {out_path}")
        print(f"[*] Redirecting output to: {fallback_out}")
        return translate_file(in_path, fallback_out)

def main():
    if len(sys.argv) < 3:
        # Default behavior if no arguments are provided (completely universal)
        input_path = r"C:\Program Files\Riot Vanguard\Logs"
        desktop = get_desktop_path()
        output_path = os.path.join(desktop, "Translated_Vanguard_Logs")
        print(f"[*] No arguments provided. Using defaults:")
        print(f"[*] Input: {input_path}")
        print(f"[*] Output: {output_path}")
        print("-" * 50)
    else:
        input_path = sys.argv[1]
        output_path = sys.argv[2]
    
    if not os.path.exists(input_path):
        print(f"Error: Input path does not exist: {input_path}")
        sys.exit(1)
        
    if os.path.isdir(input_path):
        print(f"[*] Translating all log files in directory: {input_path}")
        
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
            print(f"[-] Permission denied writing to directory: {output_path}")
            print(f"[*] Redirecting output directory to: {out_dir}")
            
        files = glob.glob(os.path.join(input_path, "*.txt")) + glob.glob(os.path.join(input_path, "*.log"))
        if not files:
            print("[-] No log or text files found in the directory.")
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
                    print(f"[+] Translated: {file_name} ({line_cnt} lines)")
                    translated_count += 1
            except Exception as e:
                print(f"[-] Failed to translate {file_name}: {e}")
        print(f"[#] Done! Successfully translated {translated_count} files.")
        
    else:
        try:
            success, line_count = translate_file(input_path, output_path)
            if success:
                print(f"[+] Success! Successfully translated {line_count} lines.")
        except Exception as e:
            print(f"[-] Error translating file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
