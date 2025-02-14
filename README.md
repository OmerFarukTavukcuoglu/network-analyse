<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
 </head>
<body>

<h1>🚀 Network Scanner</h1>
<h2>Advanced Professional Network Scanning and Mapping System</h2>

<h2>📌 Overview</h2>

<img src="https://github.com/user-attachments/assets/5197e6ee-b36d-42b3-b2df-df94cbcdc0fa" alt="Network Scanner" width="600">

<p>
    <b>Network Scanner</b> is a powerful tool for network scanning and mapping. It performs:
</p>

<ul>
    <li>🔹 TCP/UDP port scanning</li>
    <li>🔹 Protocol-based scanning</li>
    <li>🔹 SSL/TLS certificate inspection</li>
    <li>🔹 Network discovery</li>
    <li>🔹 OS detection</li>
    <li>🔹 Anomaly detection</li>
    <li>🔹 Generates detailed HTML/CSV reports</li>
</ul>

<p>It is an essential tool for <b>network security analysis</b>.</p>

<h2>🎯 Features</h2>

<ul>
    <li>✅ <b>TCP/UDP Port Scanning</b> (Synchronous & Asynchronous)</li>
    <li>✅ <b>Protocol-Based Scanning</b> (HTTP, FTP, SMTP, SSH)</li>
    <li>✅ <b>SSL/TLS Certificate Inspection</b></li>
    <li>✅ <b>CIDR-Based Network Discovery</b> (Ping Sweep)</li>
    <li>✅ <b>Network Mapping</b> (MAC Address Extraction from ARP Table)</li>
    <li>✅ <b>OS Detection</b> (Based on TTL Values)</li>
    <li>✅ <b>Anomaly Detection & Alerts</b></li>
    <li>✅ <b>Detailed Reporting</b> (HTML, CSV, and Graphical Reports)</li>
</ul>

<h2>🚀 How It Works</h2>

<h3>1️⃣ Main Menu</h3>
<p>When you run the program, it presents an interactive menu:</p>

<pre>
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
</pre>

<p>You can select a scanning type based on your needs.</p>

<h3>2️⃣ Scanning Methods</h3>

<h4>🔹 TCP/UDP Port Scanning</h4>
<ul>
    <li>Performs synchronous and asynchronous scanning to detect open/closed ports.</li>
    <li>Supports full range scanning (1-65535) or custom ports.</li>
</ul>

<h4>🔹 Protocol-Based Scanning</h4>
<ul>
    <li>Scans for open ports running specific protocols:</li>
    <li>➡ HTTP, FTP, SMTP, SSH</li>
    <li>➡ Performs banner grabbing to identify service versions.</li>
</ul>

<h4>🔹 SSL/TLS Certificate Inspection</h4>
<ul>
    <li>Checks for SSL/TLS certificates on a specified host and retrieves certificate details.</li>
</ul>

<h4>🔹 CIDR-Based Network Discovery</h4>
<ul>
    <li>Uses ping sweep to identify active hosts within a subnet.</li>
</ul>

<h4>🔹 Network Mapping</h4>
<ul>
    <li>Extracts MAC addresses from the local ARP table.</li>
    <li>Provides detailed network mapping, including OS detection based on TTL values.</li>
</ul>

<h4>🔹 Anomaly Detection</h4>
<ul>
    <li>If too many open ports are found, the tool generates an alert.</li>
    <li>Helps identify potential vulnerabilities or unusual activity.</li>
</ul>

<h2>📊 Reporting & Visualization</h2>

<p><b>Network Scanner generates professional reports in multiple formats:</b></p>

<h3>📄 HTML Report</h3>
<ul>
    <li>Provides a detailed network scan report with port status, banners, and CVE details.</li>
    <li>Example: <b>scan_report_192_168_1_1.html</b></li>
</ul>

<h3>📊 CSV Report</h3>
<ul>
    <li>Saves results in a structured CSV format for further analysis.</li>
    <li>Example: <b>scan_report_192_168_1_1.csv</b></li>
</ul>

<h3>📈 Graphical Report</h3>
<ul>
    <li>Uses Tkinter to display a bar chart showing open vs. closed ports.</li>
    <li>The graph closes automatically after 5 seconds.</li>
</ul>

<h2>⚡ Installation & Usage</h2>

<h3>📥 Install Dependencies</h3>
<p>Ensure you have Python 3.x installed, then install required packages:</p>

<pre>
<code>pip install asyncio tkinter</code>
</pre>

<h3>▶️ Run the Scanner</h3>
<p>Run the script in your terminal:</p>

<pre>
<code>python network_scanner.py</code>
</pre>

<h2>🔐 Security Considerations</h2>

<ul>
    <li>⚠️ <b>Only use this tool on networks you own or have permission to scan.</b></li>
    <li>⚠️ <b>Unauthorized scanning may be illegal in some jurisdictions.</b></li>
    <li>⚠️ <b>Always comply with your local cybersecurity regulations.</b></li>
</ul>

<h2>📜 License</h2>
<p>This project is licensed under the <b>MIT License</b>.</p>

<h2>🛠 Future Enhancements</h2>

<ul>
    <li>✔ CVE Database Integration (Real-time vulnerability detection)</li>
    <li>✔ More Protocol Support (DNS, SNMP, Telnet)</li>
    <li>✔ Advanced Graphical Dashboard</li>
</ul>

<h2>🚀 Developed for security professionals, system administrators, and ethical hackers.</h2>
<h3>Happy Scanning! 🛡️</h3>

</body>
</html>
