# ⚡ PyScan-Recon — Multi-Threaded Network & Port Security Scanner

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg?logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20Termux-green.svg)](#installation)
[![Security Domain](https://img.shields.io/badge/Domain-Ethical%20Hacking%20%7C%20SOC%20Recon-purple.svg)](#)
[![Author](https://img.shields.io/badge/Author-Shubham%20Dhage-black.svg?logo=github)](https://github.com/ShubhamDhage874)

> **PyScan-Recon** is a high-speed, multi-threaded network reconnaissance and security audit tool written in pure Python. It conducts rapid TCP port discovery, identifies running services, grabs protocol application banners, highlights known CVE attack vectors, and exports audit logs to TXT and JSON reports.

---

## 🌟 Key Features

- ⚡ **Multi-Threaded Concurrency**: Worker-thread queue architecture scans 1,000 ports in less than 3 seconds.
- 🎯 **Banner Grabbing**: Interrogates active sockets to extract web server headers, SSH versions, and FTP banners.
- 🚨 **Vulnerability Risk Advisor**: Automatically flags dangerous cleartext protocols (Telnet `23`, FTP `21`, SMB `445`, VNC `5900`, Redis `6379`).
- 📱 **100% Cross-Platform**: Native execution across **Kali Linux**, **Ubuntu**, **Windows 10/11**, and **Termux (Android)** without raw packet driver (WinPcap/Npcap) requirements.
- 🎮 **Dual Operation Mode**: Interactive prompt-driven menu for beginners or full CLI command flags for advanced automation scripts.
- 📊 **Audit Export**: Clean reporting in standard `.txt` or machine-readable `.json` formats.

---

## 🚀 Installation & Setup

### 🪟 1. Windows (PowerShell / CMD)
```powershell
# 1. Clone the repository
git clone https://github.com/ShubhamDhage874/PyScan-Recon.git
cd PyScan-Recon

# 2. Install optional color enhancements
pip install -r requirements.txt

# 3. Launch PyScan-Recon
python pyscan.py
```

---

### 🐧 2. Linux (Kali Linux / Ubuntu / Debian)
```bash
# 1. Clone the repository
git clone https://github.com/ShubhamDhage874/PyScan-Recon.git
cd PyScan-Recon

# 2. Run one-click setup script (or install manually)
chmod +x install.sh
./install.sh

# Or run directly via Python
python3 pyscan.py
```

---

### 📱 3. Android (Termux)
```bash
# 1. Update Termux packages & install git + python
pkg update -y && pkg install git python -y

# 2. Clone the repository
git clone https://github.com/ShubhamDhage874/PyScan-Recon.git
cd PyScan-Recon

# 3. Install requirements and run
pip install -r requirements.txt
python pyscan.py
```

---

## 💻 Usage & Command Reference

### Interactive Mode (No Arguments)
Simply run the script to launch the interactive prompt menu:
```bash
python pyscan.py
```

### CLI Command Options
```bash
python pyscan.py -t <TARGET> [OPTIONS]
```

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Target IP address or hostname *(Required for CLI)* | None |
| `-p` | `--ports` | Ports to scan (`top`, `1-1024`, `80,443,8080`, `21-25`) | `top` |
| `-T` | `--threads` | Number of concurrent worker threads | `70` |
| `-timeout`| `--timeout` | Socket connection timeout in seconds | `1.0` |
| `-o` | `--output` | File path to export report (`.txt` or `.json`) | None |
| | `--no-banner` | Skip service banner grabbing | False |

---

## 📌 Practical Scanning Examples

#### 1. Quick Scan Top 25 Critical Ports on Localhost:
```bash
python pyscan.py -t 127.0.0.1 -p top
```

#### 2. Scan Standard 1 - 1000 Ports with 100 Threads:
```bash
python pyscan.py -t 192.168.1.1 -p 1-1000 -T 100
```

#### 3. Audit Specific Web & Database Ports and Save Report:
```bash
python pyscan.py -t scanme.nmap.org -p 21,22,80,443,3306,8080 -o audit_report.txt
```

#### 4. Export Structured Machine-Readable JSON Report:
```bash
python pyscan.py -t 192.168.1.50 -p top -o results.json
```

---

## 📋 Sample Terminal Output

```text
  ___       ____                             ____                       
 |  _ \ _   / ___|  ___ __ _ _ __           |  _ \  ___  ___  ___  _ __  
 | |_) | | | \___ \ / __/ _` | '_ \   _____  | |_) |/ _ \/ __|/ _ \| '_ \ 
 |  __/| |_| |___) | (_| (_| | | | | |_____| |  _ <|  __/ (__| (_) | | | |
 |_|    \__, |____/ \___\__,_|_| |_|         |_| \_\\___|\___|\___/|_| |_|
        |___/                                                           
  =============================================================
  Multi-Threaded Network Reconnaissance & Port Security Scanner
  =============================================================
  [ Author : Shubham Dhage | MCA @ IIMS Pune (SPPU) | Cyber Analyst ]
  [ System : Linux / Kali / Windows / Termux Compatible ]

[*] Target Host    : 192.168.1.1 (192.168.1.1)
[*] Ports to Scan  : 26 target ports
[*] Threads Active : 26 worker threads
[*] Socket Timeout : 1.0s
[*] Scan Initiated : 2026-10-19 18:16:39

===========================================================================
 [+] PORT    22/tcp OPEN → SSH        | OpenSSH 8.9p1 Ubuntu
 [+] PORT    80/tcp OPEN → HTTP       | Apache/2.4.52 (Ubuntu)
 [+] PORT   443/tcp OPEN → HTTPS      
===========================================================================

[✓] Scan Completed in 0.85 seconds.
[✓] Discovered 3 open port(s) on 192.168.1.1.
[✓] Scan report successfully saved to: audit_report.txt
```

---

## 👨‍💻 Author

**Shubham Dhage**  
- 🎓 **Master of Computer Applications (MCA)** — *Yashaswi Education Society's International Institute of Management Science (IIMS), Pune* (Affiliated to Savitribai Phule Pune University - SPPU)
- 🛡️ **Cyber Security & SOC Defense Practitioner**
- 🌐 **Portfolio**: [https://peppy-khapse-60d4b1.netlify.app/](https://peppy-khapse-60d4b1.netlify.app/) *(or your portfolio domain)*
- 🐙 **GitHub**: [@ShubhamDhage874](https://github.com/ShubhamDhage874)
- 💼 **LinkedIn**: [Shubham Dhage](https://www.linkedin.com/in/shubham-dhage-28a26429a)

---

## ⚖️ Legal & Ethical Disclaimer

> *This tool is developed for educational purposes, authorized security testing, and cyber defense research only. Scanning unauthorized networks without explicit prior written consent from the target infrastructure owner is strictly illegal under national cyber laws (such as the IT Act 2000 in India, CFAA in the US). Always practice ethical hacking in sandboxed environments or on systems you own.*
