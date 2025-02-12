Network Scanner

Advanced Professional Network Scanning and Mapping System
📌 Overview

Network Scanner is a powerful tool for network scanning and mapping. It performs TCP/UDP port scanning, protocol-based scanning, SSL/TLS certificate inspection, network discovery, and OS detection. Additionally, it includes anomaly detection and generates detailed HTML/CSV reports, making it an essential tool for network security analysis.
🎯 Features

✅ TCP/UDP Port Scanning (Synchronous & Asynchronous)

✅ Protocol-Based Scanning (HTTP, FTP, SMTP, SSH)

✅ SSL/TLS Certificate Inspection

✅ CIDR-Based Network Discovery (Ping Sweep)

✅ Network Mapping (MAC Address Extraction from ARP Table)

✅ OS Detection (Based on TTL Values)

✅ Anomaly Detection & Alerts

✅ Detailed Reporting (HTML, CSV, and Graphical Reports)
🚀 How It Works
1️⃣ Main Menu

When you run the program, it presents an interactive menu:

=== Advanced Network Scanner ===
1. Synchronous Single IP Scan (TCP/UDP; custom or full ports)
2. Asynchronous Single IP TCP Scan (asyncio)
3. Protocol-Specific Scan (HTTP, FTP, SMTP, SSH)
4. SSL/TLS Certificate Scan
5. Network Discovery (CIDR Ping Sweep)
6. Basic Network Mapping (MAC addresses from ARP)
7. Detailed Network Mapping (OS, MAC, IP)
8. Exit
Enter your choice (1-8):

You can select a scanning type based on your needs.
2️⃣ Scanning Methods
🔹 TCP/UDP Port Scanning

    Performs synchronous and asynchronous scanning to detect open/closed ports.
    Supports full range scanning (1-65535) or custom ports.

🔹 Protocol-Based Scanning

    Scans for open ports running specific protocols:
        HTTP, FTP, SMTP, SSH
        Performs banner grabbing to identify service versions.

🔹 SSL/TLS Certificate Inspection

    Checks for SSL/TLS certificates on a specified host and retrieves certificate details.

🔹 CIDR-Based Network Discovery

    Uses ping sweep to identify active hosts within a subnet.

🔹 Network Mapping

    Extracts MAC addresses from the local ARP table.
    Provides detailed network mapping, including OS detection based on TTL values.

🔹 Anomaly Detection

    If too many open ports are found, the tool generates an alert.
    Helps identify potential vulnerabilities or unusual activity.

📊 Reporting & Visualization

Network Scanner generates professional reports in multiple formats:

📄 HTML Report:

    Provides a detailed network scan report with port status, banners, and CVE details.
    Example: scan_report_192_168_1_1.html

📊 CSV Report:

    Saves results in a structured CSV format for further analysis.
    Example: scan_report_192_168_1_1.csv

📈 Graphical Report:

    Uses Tkinter to display a bar chart showing open vs. closed ports.
    The graph closes automatically after 5 seconds.

⚡ Installation & Usage
📥 Install Dependencies

Ensure you have Python 3.x installed, then install required packages:

pip install asyncio tkinter

▶️ Run the Scanner

Run the script in your terminal:

python network_scanner.py

🔐 Security Considerations

    Only use this tool on networks you own or have permission to scan.
    Unauthorized scanning may be illegal in some jurisdictions.
    Always comply with your local cybersecurity regulations.

📜 License

This project is licensed under the MIT License.
🛠 Future Enhancements

✔ CVE Database Integration (Real-time vulnerability detection)
✔ More Protocol Support (DNS, SNMP, Telnet)
✔ Advanced Graphical Dashboard

🚀 Developed for security professionals, system administrators, and ethical hackers.
Happy Scanning! 🛡️


