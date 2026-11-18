# Authorized Port Scanner & Service Fingerprinter

## 1. Concept Overview
- **Category**: Level 3 – Ethical Hacking & Network Reconnaissance Fundamentals
- **Cybersecurity Concept**: Network Ports, TCP Handshake, Service Identification, Banner Grabbing, Risk Assessment
- **Key Capabilities**:
  1. **Multi-threaded TCP Connect Engine**: Uses `concurrent.futures.ThreadPoolExecutor` (50 threads) to scan dozens/hundreds of ports in 1-2 seconds.
  2. **Service Name Mapping**: Maps raw port numbers to standardized services (`socket.getservbyport`).
  3. **Banner Grabbing**: Connects and receives the greeting/header from open services (e.g., grabs `SSH-2.0-OpenSSH_6.6.1p1` and `Apache/2.4.7` banner versions).
  4. **High-Risk Port Alerting**: Automatically warns about exposed legacy or high-risk services:
     - Port 21 (FTP - unencrypted plaintext)
     - Port 23 (Telnet - critical plaintext credentials)
     - Port 445 (SMB - WannaCry / EternalBlue lateral movement)
     - Port 3389 (RDP - brute force target)
     - Ports 1433/3306/5432 (Exposed Database servers)
  5. **Authorization Gate**: Enforces ethical security practices and disclaimer before scanning.

---

## 2. Quick Run Guide

### A. Interactive Menu (Best for Live Interview Demo)
```powershell
cd d:\CyberSecurity_Projects\Port_Scanner
py port_scanner.py
```
Presents presets for **Localhost (127.0.0.1)** and the official authorized test target **scanme.nmap.org**.

---

### B. Command-Line Usage

1. **Scan your local computer's Top 20 ports:**
   ```powershell
   py port_scanner.py scan 127.0.0.1 -p top
   ```

2. **Scan the official authorized Nmap target (includes banner grabbing):**
   ```powershell
   py port_scanner.py scan scanme.nmap.org -p 22,80,443
   ```
   *(Notice how it grabs the real OpenSSH and Apache versions in the output table!)*

3. **Scan a custom port range:**
   ```powershell
   py port_scanner.py scan 127.0.0.1 -p 1-1024
   ```

4. **Export results as JSON (for SIEM or penetration testing reports):**
   ```powershell
   py port_scanner.py scan scanme.nmap.org -p 22,80 --json
   ```
