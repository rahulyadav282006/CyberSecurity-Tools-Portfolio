#  Failed Login Detector & Live SOC Dashboard

## 1. Concept Overview
- **Category**: Level 3 – Ethical Hacking & Security Monitoring
- **Cybersecurity Concept**: Authentication Attacks, Brute-Force & Password Spraying Detection, Account Takeover, Automated IP Blacklisting
- **Key Architecture**:
  1. **Demo Login Web Portal (`http://localhost:8080`)**: Realistic corporate login portal where users (or attackers) attempt to sign in.
  2. **Live SOC Radar Dashboard (`http://localhost:8080/soc`)**: Real-time SOC analyst view polling live events, firing security alarms, and managing active IP quarantines.
  3. **Sliding Time-Window Engine**: Detects $\ge 5$ failed logins within 60 seconds.
  4. **Account Takeover Detection**: Alerts when an attacker fails multiple times and then succeeds (cracked password).
  5. **Automated Active Defense**: Quarantines offending IP for 45 seconds and generates ready-to-run Windows Firewall rules.
  6. **1-Click Attack Simulator**: Test button to simulate an external brute-force campaign instantly without manual typing.

---

## 2. Quick Run Guide

```powershell
cd d:\CyberSecurity_Projects\Failed_Login_Detector
py app.py
```

Running this command will start the server and **automatically open 2 tabs in your browser**:
1. **Tab 1 (`http://localhost:8080`)**: The Employee Login Portal.
2. **Tab 2 (`http://localhost:8080/soc`)**: The Live SOC Analyst Radar.

---

## 3. How to Perform 

1. **Demonstrate Normal Login**:
   - Go to Tab 1, enter `rahul` / `CyberSecurity#1`.
   - Result: Successful sign-in. Notice Tab 2 logs a green `ACCEPTED` event.

2. **Demonstrate Brute-Force Detection & Auto-Lockout**:
   - Enter `admin` and type 5 random wrong passwords.
   - Result: On the 5th attempt, the login portal displays:  
     `🚫 ACCESS BLOCKED BY SOC DEFENDER (Quarantined for 45s)`
   - Switch to Tab 2: You will see the **Quarantined & Blocked Attacker IPs** table with an active countdown and a generated Windows Firewall rule (`New-NetFirewallRule`).

3. **Demonstrate 1-Click Simulator**:
   - Click the red button: `⚡ Run Live Brute-Force Attack (5 Fast Fails)`.
   - Watch Tab 2 instantly trigger a high-severity alert for an external IP (`185.220.101.5`).
