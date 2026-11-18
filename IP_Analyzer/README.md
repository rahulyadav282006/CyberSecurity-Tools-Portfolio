# IP Address Analyzer & Subnet Calculator

## 1. Concept Overview
- **Category**: Level 2 – Core Networking and Reconnaissance
- **Cybersecurity Concept**: IPv4 / IPv6, CIDR Subnetting, Scope Classification, OSINT Geolocation & Threat Recon
- **Key Concepts Covered**:
  1. **Scope Classification**: Differentiates RFC 1918 Private networks (internal LAN) from Globally Routable (Public internet), Loopback (`127.0.0.1`), Link-Local (`169.254.x.x`), and Multicast.
  2. **Subnet Math & Binary Logic**: Converts IPs and subnet masks to 32-bit (IPv4) / 128-bit (IPv6) binary blocks to demonstrate bitwise AND operations for network addresses, broadcast addresses, and usable host ranges.
  3. **Cisco / Firewall Wildcard Mask**: Computes inverted masks (`0.0.0.255`) used in Firewall ACLs and routing protocols (OSPF).
  4. **Reconnaissance & OSINT**: Performs Reverse DNS (PTR) resolution and pulls live GeoIP, ASN, and ISP ownership data for public IPs.

---

## 2. Quick Run Guide

### A. Interactive Menu (Great for presentations)
```powershell
cd d:\CyberSecurity_Projects\IP_Analyzer
py ip_analyzer.py
```

### B. Command-Line Usage

1. **Analyze an internal LAN IP with CIDR subnet:**
   ```powershell
   py ip_analyzer.py inspect 192.168.1.100/24
   ```

2. **Recon a public IP (GeoIP + ISP + ASN + Reverse DNS):**
   ```powershell
   py ip_analyzer.py inspect 8.8.8.8
   py ip_analyzer.py inspect 1.1.1.1
   ```

3. **Inspect an IPv6 address:**
   ```powershell
   py ip_analyzer.py inspect 2606:4700:4700::1111
   ```

4. **Calculate subnet planning breakdown (/22 network):**
   ```powershell
   py ip_analyzer.py subnet 10.0.0.0/22
   ```

5. **Output clean JSON for automation or SIEM pipelines:**
   ```powershell
   py ip_analyzer.py inspect 1.1.1.1 --json
   ```
