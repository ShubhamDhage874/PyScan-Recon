#!/usr/bin/env python3
"""
=============================================================================
PyScan-Recon — Multi-Threaded Network & Port Security Scanner
Author: Shubham Dhage (MCA Student & Cyber Security Analyst)
GitHub: https://github.com/ShubhamDhage874
Cross-Platform: Kali Linux, Ubuntu, Windows 10/11, Termux (Android)
=============================================================================
"""

import sys
import os
import socket
import threading
import argparse
import time
import json
from datetime import datetime
from queue import Queue

# Force UTF-8 encoding on Windows to prevent charmap errors
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Cross-platform ANSI Color support
try:
    import colorama
    colorama.init(autoreset=True)
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = True

# Terminal Color Palette
C_CYAN    = "\033[96m"
C_PURPLE  = "\033[95m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_RED     = "\033[91m"
C_BOLD    = "\033[1m"
C_DIM     = "\033[2m"
C_RESET   = "\033[0m"

BANNER = f"""{C_PURPLE}{C_BOLD}
  ___       ____                             ____                       
 |  _ \\ _   / ___|  ___ __ _ _ __           |  _ \\  ___  ___  ___  _ __  
 | |_) | | | \\___ \\ / __/ _` | '_ \\   _____  | |_) |/ _ \\/ __|/ _ \\| '_ \\ 
 |  __/| |_| |___) | (_| (_| | | | | |_____| |  _ <|  __/ (__| (_) | | | |
 |_|    \\__, |____/ \\___\\__,_|_| |_|         |_| \\_\\\\___|\\___|\\___/|_| |_|
        |___/                                                           
{C_CYAN}  =============================================================
  Multi-Threaded Network Reconnaissance & Port Security Scanner
  =============================================================
{C_YELLOW}  [ Author : Shubham Dhage | MCA @ IIMS Pune (SPPU) | Cyber Analyst ]
  [ System : Linux / Kali / Windows / Termux Compatible ]
{C_RESET}"""

# Known Services & Vulnerability Risk Notes
SERVICE_DB = {
    20:   ("FTP-DATA", "File Transfer Protocol (Data channel)"),
    21:   ("FTP", "File Transfer - [RISK: Cleartext credentials transmission]"),
    22:   ("SSH", "Secure Shell (Encrypted Remote Administration)"),
    23:   ("TELNET", "Telnet - [CRITICAL RISK: Unencrypted legacy remote shell]"),
    25:   ("SMTP", "Simple Mail Transfer - [Check for Open Mail Relay]"),
    53:   ("DNS", "Domain Name System - [Audit for DNS Zone Transfer AXFR]"),
    69:   ("TFTP", "Trivial FTP - [RISK: No authentication mechanism]"),
    80:   ("HTTP", "Web Server - [Inspect web app headers & unencrypted traffic]"),
    110:  ("POP3", "Post Office Protocol - [Cleartext mailbox access]"),
    135:  ("RPC", "Microsoft RPC Endpoint Mapper"),
    139:  ("NetBIOS", "NetBIOS Session Service - [Risk of NetBIOS Enumeration]"),
    143:  ("IMAP", "Internet Message Access Protocol"),
    443:  ("HTTPS", "Secure Web Traffic (TLS/SSL Encrypted)"),
    445:  ("SMB", "Server Message Block - [CRITICAL: Inspect for EternalBlue / Samba vulnerabilities]"),
    993:  ("IMAPS", "IMAP over TLS/SSL"),
    995:  ("POP3S", "POP3 over TLS/SSL"),
    1433: ("MSSQL", "Microsoft SQL Server Database"),
    1521: ("ORACLE", "Oracle Database Listener"),
    2049: ("NFS", "Network File System - [Inspect for unrestricted exports]"),
    3306: ("MYSQL", "MySQL Database Service"),
    3389: ("RDP", "Remote Desktop Protocol - [Audit for BlueKeep & brute-force]"),
    5432: ("POSTGRESQL", "PostgreSQL Database Engine"),
    5900: ("VNC", "Virtual Network Computing Remote Desktop"),
    6379: ("REDIS", "Redis In-Memory Key-Value Store - [Check for unauthorized root bind]"),
    8080: ("HTTP-PROXY", "Alternative HTTP Web / Proxy Service"),
    8443: ("HTTPS-ALT", "Alternative Secure HTTPS Web Management"),
    27017:("MONGODB", "MongoDB NoSQL Database - [Verify authentication requirement]")
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
]

class PyScanner:
    def __init__(self, target, ports, threads=60, timeout=1.0, grab_banner=True):
        self.target = target
        self.ports = ports
        self.num_threads = min(threads, len(ports)) if ports else threads
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.queue = Queue()
        self.open_ports = []
        self.lock = threading.Lock()
        self.target_ip = None
        self.start_time = None
        self.end_time = None

    def resolve_target(self):
        try:
            self.target_ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            print(f"{C_RED}[!] Error: Could not resolve hostname '{self.target}'. Check IP or connection.{C_RESET}")
            return False

    def get_service_info(self, port):
        if port in SERVICE_DB:
            return SERVICE_DB[port]
        try:
            name = socket.getservbyport(port, "tcp").upper()
            return (name, "Standard TCP Service")
        except:
            return ("UNKNOWN", "Custom or Unregistered Port")

    def capture_banner(self, ip, port):
        """Attempts to grab the service application banner."""
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.2)
            s.connect((ip, port))
            
            # Send generic probe for HTTP/Services
            if port in [80, 8080]:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [21, 22, 25]:
                pass  # Services send welcome banner automatically
            else:
                s.send(b"\r\n")

            data = s.recv(1024)
            if data:
                clean_banner = data.decode("utf-8", errors="replace").strip()
                # Grab the first line of the banner
                banner = clean_banner.split("\n")[0].strip()[:65]
            s.close()
        except:
            pass
        return banner

    def scan_worker(self):
        while not self.queue.empty():
            try:
                port = self.queue.get_nowait()
            except:
                break

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target_ip, port))
                s.close()

                if result == 0:
                    service_name, risk_desc = self.get_service_info(port)
                    banner = ""
                    if self.grab_banner:
                        banner = self.capture_banner(self.target_ip, port)

                    with self.lock:
                        self.open_ports.append({
                            "port": port,
                            "service": service_name,
                            "risk": risk_desc,
                            "banner": banner
                        })
                        
                        banner_str = f" | {C_DIM}{banner}{C_RESET}" if banner else ""
                        risk_tag = f" {C_YELLOW}→ {risk_desc}{C_RESET}" if "[RISK" in risk_desc or "[CRITICAL" in risk_desc else ""
                        print(f" {C_GREEN}[+] PORT {port:5d}/tcp OPEN{C_RESET} → {C_BOLD}{service_name:10s}{C_RESET}{banner_str}{risk_tag}")

            except Exception:
                pass
            finally:
                self.queue.task_done()

    def run(self):
        if not self.resolve_target():
            return []

        print(f"\n{C_CYAN}[*] Target Host    : {C_BOLD}{self.target} ({self.target_ip}){C_RESET}")
        print(f"{C_CYAN}[*] Ports to Scan  : {C_BOLD}{len(self.ports)} target ports{C_RESET}")
        print(f"{C_CYAN}[*] Threads Active : {C_BOLD}{self.num_threads} worker threads{C_RESET}")
        print(f"{C_CYAN}[*] Socket Timeout : {C_BOLD}{self.timeout}s{C_RESET}")
        print(f"{C_CYAN}[*] Scan Initiated : {C_BOLD}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C_RESET}\n")
        print(f"{C_DIM}{'=' * 75}{C_RESET}")

        self.start_time = time.time()

        for port in self.ports:
            self.queue.put(port)

        threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=self.scan_worker)
            t.daemon = True
            t.start()
            threads.append(t)

        self.queue.join()
        self.end_time = time.time()

        duration = self.end_time - self.start_time
        print(f"{C_DIM}{'=' * 75}{C_RESET}\n")
        print(f"{C_BOLD}[✓] Scan Completed in {duration:.2f} seconds.{C_RESET}")
        print(f"{C_BOLD}[✓] Discovered {len(self.open_ports)} open port(s) on {self.target}.{C_RESET}\n")

        # Sort ports ascending
        self.open_ports.sort(key=lambda x: x["port"])
        return self.open_ports

    def export_report(self, filename):
        if not filename:
            return

        is_json = filename.lower().endswith(".json")
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            with open(filename, "w", encoding="utf-8") as f:
                if is_json:
                    data = {
                        "tool": "PyScan-Recon",
                        "author": "Shubham Dhage",
                        "target": self.target,
                        "target_ip": self.target_ip,
                        "scan_duration_sec": round(self.end_time - self.start_time, 2),
                        "timestamp": datetime.now().isoformat(),
                        "open_ports": self.open_ports
                    }
                    json.dump(data, f, indent=4)
                else:
                    f.write("=" * 70 + "\n")
                    f.write("   PyScan-Recon Security Reconnaissance Report\n")
                    f.write(f"   Target   : {self.target} ({self.target_ip})\n")
                    f.write(f"   Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"   Duration : {round(self.end_time - self.start_time, 2)} seconds\n")
                    f.write("=" * 70 + "\n\n")
                    for p in self.open_ports:
                        f.write(f"PORT {p['port']}/TCP  [OPEN]  Service: {p['service']}\n")
                        if p['banner']:
                            f.write(f"  Banner : {p['banner']}\n")
                        f.write(f"  Notes  : {p['risk']}\n\n")
                    f.write("=" * 70 + "\n")
                    f.write("Report generated by PyScan-Recon (Shubham Dhage)\n")
            print(f"{C_GREEN}[✓] Scan report successfully saved to: {filename}{C_RESET}")
        except Exception as e:
            print(f"{C_RED}[!] Failed to export report: {e}{C_RESET}")

def parse_port_range(port_str):
    """Parses port input like '80', '1-1000', '21,22,80,443', or 'top'."""
    if port_str.lower() == "top":
        return TOP_PORTS
    
    ports = set()
    parts = port_str.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            sub = part.split("-")
            start = int(sub[0])
            end = int(sub[1])
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(list(ports))

def interactive_mode():
    print(BANNER)
    print(f"{C_BOLD}Select Scan Profile:{C_RESET}")
    print(f"  {C_CYAN}[1]{C_RESET} Fast Scan (Top 25 Most Exploited / Critical Ports)")
    print(f"  {C_CYAN}[2]{C_RESET} Standard Scan (Common 1 - 1024 Well-Known Ports)")
    print(f"  {C_CYAN}[3]{C_RESET} Comprehensive Scan (1 - 5000 Extended Services)")
    print(f"  {C_CYAN}[4]{C_RESET} Custom Port Range (e.g. 21,22,80,443 or 8000-9000)")
    
    try:
        choice = input(f"\n{C_YELLOW}Enter your choice [1-4] (default: 1): {C_RESET}").strip() or "1"
        target = input(f"{C_YELLOW}Enter Target IP or Domain (e.g. scanme.nmap.org / 127.0.0.1): {C_RESET}").strip()
        if not target:
            print(f"{C_RED}[!] Target cannot be empty.{C_RESET}")
            return

        if choice == "1":
            ports = TOP_PORTS
        elif choice == "2":
            ports = list(range(1, 1025))
        elif choice == "3":
            ports = list(range(1, 5001))
        elif choice == "4":
            custom_range = input(f"{C_YELLOW}Enter ports (e.g. 21,22,80 or 1-100): {C_RESET}").strip()
            ports = parse_port_range(custom_range)
        else:
            ports = TOP_PORTS

        threads_in = input(f"{C_YELLOW}Enter Thread count [default: 70]: {C_RESET}").strip()
        threads = int(threads_in) if threads_in.isdigit() else 70

        save_choice = input(f"{C_YELLOW}Save report to file? (y/n) [default: y]: {C_RESET}").strip().lower() or "y"
        report_file = None
        if save_choice == "y":
            default_name = f"scan_{target.replace('.', '_')}.txt"
            user_filename = input(f"{C_YELLOW}Enter report filename [default: {default_name}]: {C_RESET}").strip()
            report_file = user_filename if user_filename else default_name

        scanner = PyScanner(target=target, ports=ports, threads=threads, timeout=1.0)
        scanner.run()
        if report_file:
            scanner.export_report(report_file)

    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] Scan aborted by user (Ctrl+C). Exiting...{C_RESET}")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="PyScan-Recon — Multi-Threaded Port & Service Scanner by Shubham Dhage",
        epilog="Examples:\n  python pyscan.py -t 127.0.0.1 -p top\n  python pyscan.py -t scanme.nmap.org -p 1-1000 -T 80 -o report.txt\n"
    )
    parser.add_argument("-t", "--target", help="Target IP address or Domain name")
    parser.add_argument("-p", "--ports", default="top", help="Port range (e.g., 'top', '1-1000', '80,443', '21-25')")
    parser.add_argument("-T", "--threads", type=int, default=70, help="Number of worker threads (default: 70)")
    parser.add_argument("-timeout", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", help="Save report to file (.txt or .json)")
    parser.add_argument("--no-banner", action="store_true", help="Disable service banner grabbing")

    args = parser.parse_args()

    # If no target specified via CLI, launch interactive menu
    if not args.target:
        interactive_mode()
        return

    print(BANNER)
    try:
        ports = parse_port_range(args.ports)
    except Exception as e:
        print(f"{C_RED}[!] Error parsing port range: {e}{C_RESET}")
        sys.exit(1)

    scanner = PyScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        grab_banner=not args.no_banner
    )

    try:
        scanner.run()
        if args.output:
            scanner.export_report(args.output)
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!] Scan aborted by user (Ctrl+C).{C_RESET}")

if __name__ == "__main__":
    main()
