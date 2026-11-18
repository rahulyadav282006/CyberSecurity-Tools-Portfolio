# HTTP Security Header Analyzer

## 1. Concept Overview
- **Category**: Level 2 – Core Networking and Web Security
- **Cybersecurity Concept**: OWASP Security Misconfiguration (A05:2021) & Web Defense Headers
- **Audited Headers**:
  1. `Strict-Transport-Security (HSTS)`: Prevents SSL stripping & MITM cookie hijacking.
  2. `Content-Security-Policy (CSP)`: Primary mitigation against Cross-Site Scripting (XSS).
  3. `X-Frame-Options`: Blocks Clickjacking / iframe UI redress attacks.
  4. `X-Content-Type-Options`: Forces `nosniff` against MIME confusion attacks.
  5. `Referrer-Policy`: Prevents leaking sensitive URL query parameters to external sites.
  6. `Permissions-Policy`: Restricts browser hardware access (camera, microphone, geolocation).
  7. **Server Banner Disclosures**: Flags `Server`, `X-Powered-By`, and framework version leaks.

---

## 2. Output Presentation (Clean & Modern)

1. **Terminal Table Scorecard**: Clean ASCII scorecard with pass/fail tags, threat descriptions, and letter grades (A+ to F).
2. **Visual HTML Dashboard (`audit_report.html`)**: Automatically opens a polished cybersecurity audit report in your browser with circular score badges and remediation snippets.

---

## 3. Quick Run Guide

### A. Scan Any Website (Auto-opens HTML Dashboard)
```powershell
cd d:\CyberSecurity_Projects\HTTP_Header_Analyzer
py http_header_analyzer.py scan https://github.com
```

### B. Terminal-Only Mode
```powershell
py http_header_analyzer.py scan https://github.com --no-browser
py http_header_analyzer.py scan http://example.com --no-browser
```

### C. Interactive Menu
```powershell
py http_header_analyzer.py
```
