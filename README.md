# Vanguard Log Translator & Decryptor

A universal utility to automatically decrypt and translate Riot Vanguard anti-cheat kernel (`vgk.sys`) and client (`vgc.exe`) log files into clean, readable, plain English sentences.

Vanguard logs typically consist of raw event IDs, memory addresses, process IDs, and hex codes. This tool cleans up system identifiers (PIDs, hex pointers, handles) for privacy while translating cryptic event numbers into descriptive English actions.

## 🚀 Key Features

* **🔑 Hybrid Decryptor & Translator**: Automatically detects encrypted log files (magic header `pvpv`) and decrypts them on-the-fly using embedded RC4 structures before translating.
* **Anonymizer**: Strips raw process handles, thread IDs, process IDs (PIDs), and kernel memory addresses for security and clean reading.
* **🌐 VGC & VGK Translation**: Fully maps driver codes (e.g. `B000003C`, `B000003B`) and client codes (e.g. `139`, `163`, `164`, `199`) to human-readable explanations.
* **📁 Directory Batch Processing**: Supports translating single files or entire folders containing multiple log files.
* **📂 Smart Path Resolving**: Dynamically resolves the user's active Windows Desktop folder (resolves OneDrive, locale-specific folder names like `Masaüstü` to prevent Unicode path bugs).
* **🔒 System Permission Fallback**: Automatically redirects output to a desktop folder (`Translated_Vanguard_Logs`) if writing directly to protected system directories (like `C:\Program Files\Riot Vanguard\Logs`) is blocked by Windows.

## 📋 Translation Examples

### Vanguard Driver Build & Compile
* **Before**: `[2025-08-17_09-46-13] [!] [1000004A]: 1.17.12.4 ; Wed Aug  6 17:39:45 2025`
* **After**: `[2025-08-17_09-46-13] Vanguard driver build version 1.17.12.4 compiled on Wednesday August 6, 17:39:45 2025.`

### Process Surveillance
* **Before**: `[2025-08-17_09-46-23] [!] [B000003C]: 912 ; FFFF950F830B6080 ; 0 ; 1 ; csrss.exe`
* **After**: `[2025-08-17_09-46-23] Process placed under surveillance: Process csrss is now closely monitored.`

### Client Latency Reporting
* **Before**: `[2025-11-28_17-18-20] [19736][11/28/25 17:18:20][i]: 163: 110`
* **After**: `[2025-11-28_17-18-20] Latency check: Network round-trip latency of 110 milliseconds verified.`

---

## 🛠️ Usage

### Quick Start (Windows)
1. Double-click [vanguard_log_translator.bat](vanguard_log_translator.bat).
2. Choose option `3` to automatically scan default Riot Vanguard folders, decrypt all logs, and save translated output directly on your Desktop in a folder called `Translated_Vanguard_Logs`.
3. Alternatively, drag and drop any log file/folder directly onto the `vanguard_log_translator.bat` icon.

### Command Line
Translate a single file or a directory of files manually:
```bash
python vanguard_log_translator.py <input_file_or_directory> <output_file_or_directory>
```

---

## ⚙️ Requirements
* **OS**: Windows 10 / 11
* **Python**: Python 3.x installed
