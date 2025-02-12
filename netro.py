#!/usr/bin/env python3
"""
Gelişmiş Profesyonel Ağ Tarama ve Mapping Sistemi
- Synchronous & Asynchronous TCP/UDP port taraması (custom/full port seçenekleri)
- Protokol bazlı tarama (HTTP, FTP, SMTP, SSH örnekleri)
- SSL/TLS sertifika kontrolü
- Basit banner grabbing ve dummy CVE entegrasyonu
- CIDR üzerinden host keşfi (ping sweep)
- Ağ haritası: Yerel ARP tablosundan MAC adreslerinin alınması
- Detaylı network mapping: Her aktif host için OS tahmini (TTL’ye dayalı), MAC, IP bilgileri
- Raporlama: HTML, CSV raporları
- Grafiksel raporlama: Tkinter ile bar grafik
- Anomali tespiti: Açık port sayısı eşik değerini aşıyorsa uyarı
"""

import socket
import threading
import subprocess
import time
import json
import os
import ipaddress
import platform
import csv
import ssl
import asyncio
import tkinter as tk
from datetime import datetime

# ANSI Renk Kodları (terminal için)
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RESET  = "\033[0m"


def print_banner():
    print(f"""
{CYAN}
 _____                                _____ 
( ___ )------------------------------( ___ )
 |   |                                |   | 
 |   |  _   _        _                |   | 
 |   | | \ | |  ___ | |_  _ __  ___   |   | 
 |   | |  \| | / _ \| __|| '__|/ _ \  |   | 
 |   | | |\  ||  __/| |_ | |  | (_) | |   | 
 |   | |_| \_| \___| \__||_|   \___/  |   | 
 |___|        Network Scanner         |___| 
(_____)------------------------------(_____)
    
    Advanced Professional Network Scanning and Mapping System

    -TCP/UDP Port Scanning
    -Protocol-Based Scanning (HTTP, FTP, SMTP, SSH)
    -SSL/TLS Certificate Inspection
    -Network Mapping and OS Detection
    -Anomaly Detection & Reporting
    ***********************************************
    {RESET}
    """)

# Kullanım
print_banner()


# -----------------------
# Temel Fonksiyonlar
# -----------------------

def ping_host(host):
    """
    Verilen host'a ping atar.
    Windows: -n 1 -w 1000, Unix: -c 1 -W 1 kullanılır.
    """
    param = '-n' if platform.system().lower()=='windows' else '-c'
    timeout_param = '-w' if platform.system().lower()=='windows' else '-W'
    timeout_value = '1000' if platform.system().lower()=='windows' else '1'
    try:
        result = subprocess.run(
            ['ping', param, '1', timeout_param, timeout_value, host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception as e:
        print(f"{RED}Ping error ({host}): {e}{RESET}")
        return False

def tcp_scan_sync(ip, port, results):
    """
    Senkron TCP taraması: Verilen IP:port'a bağlanır,
    bağlantı kurulursa port "open" olarak, aksi halde "closed".
    Basit banner grabbing uygulanır.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = ""
        try:
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
            banner = sock.recv(1024).decode(errors="ignore").strip()
        except Exception:
            pass
        results[port] = {"status": "open", "banner": banner}
        sock.close()
    except Exception:
        results[port] = {"status": "closed"}

def udp_scan_sync(ip, port, results):
    """
    Senkron UDP taraması: UDP paketi gönderilir; yanıt alınırsa port "open" kabul edilir.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"Hello", (ip, port))
        data, _ = sock.recvfrom(1024)
        results[port] = {"status": "open", "response": data.decode(errors="ignore")}
        sock.close()
    except Exception:
        results[port] = {"status": "closed"}

# -----------------------
# Asenkron Tarama (asyncio)
# -----------------------

async def tcp_scan_async(ip, port):
    """
    asyncio kullanılarak asenkron TCP taraması.
    Bağlantı kurulursa port "open", banner grabbing denenir.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1)
        banner = ""
        try:
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            banner = (await asyncio.wait_for(reader.read(1024), timeout=1)).decode(errors="ignore").strip()
        except Exception:
            pass
        writer.close()
        await writer.wait_closed()
        return port, "open", banner
    except Exception:
        return port, "closed", ""

async def async_port_scan(ip, ports):
    """
    Asenkron port taraması; verilen port listesi için TCP taraması yapar.
    """
    tasks = []
    for port in ports:
        tasks.append(tcp_scan_async(ip, port))
    results = await asyncio.gather(*tasks)
    res = {}
    for port, status, banner in results:
        res[port] = {"status": status, "banner": banner}
    return res

# -----------------------
# Protokol Bazlı Tarama
# -----------------------

def protocol_scan(ip, port, protocol, results):
    """
    Belirtilen protokole göre tarama yapar.
    Örneğin: HTTP, FTP, SMTP, SSH gibi.
    (Burada örnek olarak HTTP için banner grabbing uygulanmıştır.)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        sock.connect((ip, port))
        banner = ""
        if protocol.lower() == "http":
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
            banner = sock.recv(1024).decode(errors="ignore").strip()
        elif protocol.lower() in ["ftp", "smtp", "ssh"]:
            banner = sock.recv(1024).decode(errors="ignore").strip()
        else:
            banner = sock.recv(1024).decode(errors="ignore").strip()
        results[port] = {"status": "open", "banner": banner, "protocol": protocol.upper()}
        sock.close()
    except Exception:
        results[port] = {"status": "closed", "protocol": protocol.upper()}

# -----------------------
# SSL/TLS Sertifika Kontrolü
# -----------------------

def ssl_scan(ip, port, results):
    """
    SSL/TLS bağlantısı kurarak sunucunun sertifika bilgilerini getirir.
    """
    context = ssl.create_default_context()
    try:
        sock = socket.create_connection((ip, port), timeout=3)
        ssl_sock = context.wrap_socket(sock, server_hostname=ip)
        cert = ssl_sock.getpeercert()
        ssl_sock.close()
        results[port] = {"status": "open", "ssl_cert": cert}
    except Exception as e:
        results[port] = {"status": "closed", "ssl_cert": None}

# -----------------------
# Dummy CVE Entegrasyonu
# -----------------------

def fetch_cve_data(banner):
    """
    Banner içeriğine bağlı olarak dummy CVE bilgisi döner.
    Gerçek uygulamada ilgili CVE API’lerine sorgu yapılmalıdır.
    """
    banner_lower = banner.lower() if banner else ""
    if "apache" in banner_lower:
        return "CVE-2017-15715"
    elif "nginx" in banner_lower:
        return "CVE-2013-2028"
    elif "ftp" in banner_lower:
        return "CVE-2015-3306"
    elif "smtp" in banner_lower:
        return "CVE-2018-XXXX"
    else:
        return "No CVE data"

# -----------------------
# Ağ Keşfi (CIDR Ping Sweep)
# -----------------------

def host_discovery(network):
    """
    CIDR şeklinde girilen ağ üzerinde ping atarak aktif hostları tespit eder.
    """
    active_hosts = []
    try:
        net = ipaddress.ip_network(network, strict=False)
    except Exception as e:
        print(f"{RED}Invalid network: {network}{RESET}")
        return active_hosts

    print(f"{GREEN}[*] Discovering hosts on {network}...{RESET}")
    threads = []
    lock = threading.Lock()

    def ping_and_add(ip):
        if ping_host(str(ip)):
            with lock:
                active_hosts.append(str(ip))
                print(f"{GREEN}[+] {ip} is alive{RESET}")

    for ip in net.hosts():
        t = threading.Thread(target=ping_and_add, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return active_hosts

# -----------------------
# Ağ Haritası (MAC Adresi Okuma)
# -----------------------

def get_mac_addresses():
    """
    Yerel ARP tablosunu okuyarak MAC adreslerini elde eder.
    Unix tabanlı sistemlerde "arp -a" komutu kullanılır.
    """
    mac_info = {}
    try:
        output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
        for line in output.splitlines():
            if "(" in line and ")" in line:
                parts = line.split()
                ip = parts[1].strip("()")
                try:
                    mac = parts[3]
                    mac_info[ip] = mac
                except IndexError:
                    continue
    except Exception as e:
        print(f"{RED}Error retrieving ARP table: {e}{RESET}")
    return mac_info

# -----------------------
# OS Tespiti (TTL’ye Dayalı)
# -----------------------

def detect_os(host):
    """
    Basit OS tespiti: ping çıktısındaki TTL değerine göre işletim sistemi tahmini yapar.
         <= 64: Linux/Unix
         <= 128: Windows
         <= 254: Network Device
    """
    try:
        output = subprocess.check_output(["ping", "-c", "1", host], universal_newlines=True)
        ttl_value = None
        for token in output.split():
            if "ttl=" in token.lower():
                try:
                    ttl_value = int(token.lower().split("ttl=")[1])
                except ValueError:
                    pass
                break
        if ttl_value is not None:
            if ttl_value <= 64:
                return "Linux/Unix"
            elif ttl_value <= 128:
                return "Windows"
            elif ttl_value <= 254:
                return "Network Device"
            else:
                return "Unknown"
        else:
            return "Unknown"
    except Exception as e:
        return "Unknown"

# -----------------------
# Detaylı Network Mapping
# -----------------------

def detailed_network_mapping(network):
    """
    Detaylı ağ haritalaması: CIDR aralığında aktif hostları tespit eder,
    her host için OS tahmini ve MAC adres bilgilerini getirir.
    """
    print(f"{GREEN}[*] Performing detailed network mapping on {network}...{RESET}")
    active_hosts = host_discovery(network)
    arp_table = get_mac_addresses()
    mapping = {}
    for host in active_hosts:
        os_guess = detect_os(host)
        mac = arp_table.get(host, "Unknown")
        mapping[host] = {"os": os_guess, "mac": mac}
        print(f"{GREEN}[+] {host}: OS = {os_guess}, MAC = {mac}{RESET}")
    return mapping

# -----------------------
# Raporlama Fonksiyonları
# -----------------------

def generate_html_report(results, target):
    """
    Tarama sonuçlarını profesyonel görünümlü HTML raporu olarak oluşturur.
    """
    html = f"""<html>
<head>
<meta charset="utf-8">
<title>Network Scan Report: {target}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 20px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; text-align: center; }}
  th {{ background-color: #4CAF50; color: white; }}
</style>
</head>
<body>
<h1>Network Scan Report: {target}</h1>
<p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<table>
<tr>
<th>IP Address</th>
<th>Protocol</th>
<th>Port</th>
<th>Status</th>
<th>Banner/Response</th>
<th>CVE Details</th>
</tr>
"""
    for ip, protocols in results.items():
        for proto, ports in protocols.items():
            for port, info in ports.items():
                protocol_display = proto.upper()
                banner = info.get("banner", info.get("response", ""))
                cve_info = fetch_cve_data(banner) if banner else "No CVE data"
                ssl_cert = info.get("ssl_cert", None)
                if ssl_cert:
                    ssl_info = f"Issuer: {ssl_cert.get('issuer')}, Exp: {ssl_cert.get('notAfter')}"
                else:
                    ssl_info = ""
                html += f"<tr><td>{ip}</td><td>{protocol_display}</td><td>{port}</td><td>{info['status']}</td><td>{banner} {ssl_info}</td><td>{cve_info}</td></tr>\n"
    html += "</table></body></html>"
    report_filename = f"scan_report_{target.replace('/', '_').replace('.', '_')}.html"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{CYAN}[+] HTML report generated: {report_filename}{RESET}")

def generate_csv_report(results, target):
    """
    Tarama sonuçlarını CSV formatında dışa aktarır.
    """
    report_filename = f"scan_report_{target.replace('/', '_').replace('.', '_')}.csv"
    with open(report_filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Protocol", "Port", "Status", "Banner/Response", "CVE Details"])
        for ip, protocols in results.items():
            for proto, ports in protocols.items():
                for port, info in ports.items():
                    protocol_display = proto.upper()
                    banner = info.get("banner", info.get("response", ""))
                    cve_info = fetch_cve_data(banner) if banner else "No CVE data"
                    writer.writerow([ip, protocol_display, port, info["status"], banner, cve_info])
    print(f"{CYAN}[+] CSV report generated: {report_filename}{RESET}")

def plot_graphical_report(results):
    """
    Tkinter kullanarak basit bir bar grafik oluşturur.
    Açık ve kapalı port sayısını gösterir; pencere 5 saniye açık kalır.
    """
    open_count = 0
    closed_count = 0
    for ip, protocols in results.items():
        for proto, ports in protocols.items():
            for port, info in ports.items():
                if info["status"] == "open":
                    open_count += 1
                else:
                    closed_count += 1
    width = 400
    height = 300
    root = tk.Tk()
    root.title("Port Status Distribution")
    canvas = tk.Canvas(root, width=width, height=height)
    canvas.pack()
    max_count = max(open_count, closed_count, 1)
    bar_width = 100
    open_bar_height = (open_count / max_count) * (height - 50)
    closed_bar_height = (closed_count / max_count) * (height - 50)
    canvas.create_rectangle(50, height - open_bar_height, 50 + bar_width, height, fill="green")
    canvas.create_text(50 + bar_width/2, height - open_bar_height - 10, text=f"Open: {open_count}")
    canvas.create_rectangle(200, height - closed_bar_height, 200 + bar_width, height, fill="red")
    canvas.create_text(200 + bar_width/2, height - closed_bar_height - 10, text=f"Closed: {closed_count}")
    root.after(5000, root.destroy)
    root.mainloop()
    print(f"{CYAN}[+] Graphical report displayed (window closed after 5 seconds).{RESET}")

# -----------------------
# Anomali Tespiti
# -----------------------

def anomaly_detection(results, threshold=10):
    """
    Açık port sayısı belirlenen eşik değeri aşıyorsa uyarı verir.
    """
    open_ports_total = 0
    for ip, protocols in results.items():
        for proto, ports in protocols.items():
            for port, info in ports.items():
                if info["status"] == "open":
                    open_ports_total += 1
    if open_ports_total > threshold:
        print(f"{YELLOW}[!] Anomaly detected: {open_ports_total} open ports (threshold: {threshold}).{RESET}")
    else:
        print(f"{GREEN}[+] Open port count ({open_ports_total}) is within normal limits.{RESET}")

# -----------------------
# İnteraktif Menü
# -----------------------

def print_menu():
    print(f"{YELLOW}=== Advanced Network Scanner ==={RESET}")
    print(f"{GREEN}1. Synchronous Single IP Scan (TCP/UDP; custom or full ports)")
    print(f"{GREEN}2. Asynchronous Single IP TCP Scan (asyncio)")
    print(f"{GREEN}3. Protocol-specific Scan (HTTP, FTP, SMTP, SSH)")
    print(f"{GREEN}4. SSL/TLS Certificate Scan")
    print(f"{GREEN}5. Network Discovery (CIDR Ping Sweep)")
    print(f"{GREEN}6. Basic Network Mapping (MAC addresses from ARP)")
    print(f"{GREEN}7. Detailed Network Mapping (OS, MAC, IP)")
    print(f"{RED}8. Exit{RESET}")
    choice = input(f"{YELLOW}Enter your choice (1-8): {RESET}")
    return choice

# -----------------------
# Main Fonksiyonu
# -----------------------

def main():
    while True:
        choice = print_menu()
        if choice == '1':
            ip = input(f"{YELLOW}Enter target IP: {RESET}")
            port_choice = input(f"{YELLOW}Scan custom ports or full scan? (c/f): {RESET}").lower()
            if port_choice == 'c':
                ports_input = input(f"{YELLOW}Enter ports (comma-separated): {RESET}")
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',')]
                except Exception:
                    print(f"{RED}Invalid port input. Using default ports 80,443.{RESET}")
                    ports = [80, 443]
            elif port_choice == 'f':
                # Full scan: 1 to 65535 (Note: very time-consuming)
                ports = list(range(1, 65536))
            else:
                print(f"{RED}Invalid choice. Using default ports 80,443.{RESET}")
                ports = [80, 443]
            results = {ip: {}}
            # Synchronous TCP scan (multithreading)
            tcp_results = {}
            threads = []
            for port in ports:
                t = threading.Thread(target=tcp_scan_sync, args=(ip, port, tcp_results))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            results[ip]["tcp"] = tcp_results
            # Synchronous UDP scan
            udp_results = {}
            threads = []
            for port in ports:
                t = threading.Thread(target=udp_scan_sync, args=(ip, port, udp_results))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            results[ip]["udp"] = udp_results
            anomaly_detection(results, threshold=10)
            generate_html_report(results, ip)
            generate_csv_report(results, ip)
            plot_graphical_report(results)
        elif choice == '2':
            ip = input(f"{YELLOW}Enter target IP: {RESET}")
            ports_input = input(f"{YELLOW}Enter ports (comma-separated): {RESET}")
            try:
                ports = [int(p.strip()) for p in ports_input.split(',')]
            except Exception:
                print(f"{RED}Invalid port input. Using default ports 80,443.{RESET}")
                ports = [80, 443]
            results = {ip: {}}
            print(f"{GREEN}[*] Starting asynchronous TCP scan on {ip}...{RESET}")
            loop = asyncio.get_event_loop()
            tcp_results = loop.run_until_complete(async_port_scan(ip, ports))
            results[ip]["tcp"] = tcp_results
            anomaly_detection(results, threshold=10)
            generate_html_report(results, ip)
            generate_csv_report(results, ip)
            plot_graphical_report(results)
        elif choice == '3':
            ip = input(f"{YELLOW}Enter target IP: {RESET}")
            ports_input = input(f"{YELLOW}Enter ports (comma-separated): {RESET}")
            protocol = input(f"{YELLOW}Enter protocol (HTTP/FTP/SMTP/SSH): {RESET}")
            try:
                ports = [int(p.strip()) for p in ports_input.split(',')]
            except Exception:
                print(f"{RED}Invalid port input. Using default port 80.{RESET}")
                ports = [80]
            results = {ip: {"proto": {}}}
            proto_results = {}
            threads = []
            for port in ports:
                t = threading.Thread(target=protocol_scan, args=(ip, port, protocol, proto_results))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            results[ip]["proto"] = proto_results
            anomaly_detection(results, threshold=5)
            generate_html_report(results, ip)
            generate_csv_report(results, ip)
            plot_graphical_report(results)
        elif choice == '4':
            ip = input(f"{YELLOW}Enter target IP for SSL/TLS scan: {RESET}")
            port_input = input(f"{YELLOW}Enter port (typically 443): {RESET}")
            try:
                port = int(port_input)
            except Exception:
                print(f"{RED}Invalid port input. Using port 443.{RESET}")
                port = 443
            results = {ip: {"ssl": {}}}
            ssl_results = {}
            ssl_scan(ip, port, ssl_results)
            results[ip]["ssl"] = ssl_results
            generate_html_report(results, ip)
            generate_csv_report(results, ip)
            plot_graphical_report(results)
        elif choice == '5':
            network = input(f"{YELLOW}Enter CIDR network (e.g., 192.168.1.0/24): {RESET}")
            hosts = host_discovery(network)
            if hosts:
                print(f"{GREEN}Discovered hosts: {', '.join(hosts)}{RESET}")
            else:
                print(f"{RED}No active hosts found.{RESET}")
        elif choice == '6':
            print(f"{GREEN}Fetching MAC addresses from ARP table...{RESET}")
            macs = get_mac_addresses()
            if macs:
                for ip_addr, mac in macs.items():
                    print(f"{ip_addr} => {mac}")
            else:
                print(f"{RED}No MAC address information found.{RESET}")
        elif choice == '7':
            network = input(f"{YELLOW}Enter CIDR network for detailed mapping (e.g., 192.168.1.0/24): {RESET}")
            mapping = detailed_network_mapping(network)
            # Oluşturulan detaylı mapping raporunu HTML olarak kaydedelim.
            html = f"""<html>
<head>
<meta charset="utf-8">
<title>Detailed Network Mapping Report: {network}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 20px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; text-align: center; }}
  th {{ background-color: #4CAF50; color: white; }}
</style>
</head>
<body>
<h1>Detailed Network Mapping Report: {network}</h1>
<p>Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<table>
<tr>
<th>IP Address</th>
<th>Operating System</th>
<th>MAC Address</th>
</tr>
"""
            for ip_addr, details in mapping.items():
                html += f"<tr><td>{ip_addr}</td><td>{details['os']}</td><td>{details['mac']}</td></tr>\n"
            html += "</table></body></html>"
            report_filename = f"detailed_mapping_{network.replace('/', '_').replace('.', '_')}.html"
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"{CYAN}[+] Detailed network mapping HTML report generated: {report_filename}{RESET}")
        elif choice == '8':
            print(f"{RED}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")

if __name__ == "__main__":
    main()
