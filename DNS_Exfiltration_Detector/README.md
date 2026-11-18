# Project: DNS Exfiltration & Covert Tunneling Hunter (Live SOC Radar & Active Defense)

## 1. Concept & Threat Narrative
- **The Attack Vector**: When enterprise network perimeters block all outbound HTTP, HTTPS, SSH, and USB access, Advanced Persistent Threats (APTs) and modern ransomware use **DNS Covert Channels (UDP Port 53)**. They read sensitive internal files, break them into encoded chunks, and stream them out as DNS subdomain lookups to an attacker-controlled apex server without triggering traditional firewalls.
- **The Defense Solution**: An enterprise-grade threat hunting engine that performs real-time deep protocol inspection on DNS traffic, calculates Shannon Entropy, models burst query rates, renders **Wireshark-style raw hex dumps**, reconstructs the stolen payload, and halts the exfiltration mid-air using **Active DNS Sinkholing (0.0.0.0)**.

---

## 2. Advanced Features Implemented

1. **Live Packet-by-Packet Flight Animation**:
   Simulates realistic network latency with packet transmission counters (`[PACKET 1/4] IN-FLIGHT`).
2. **Wireshark-Style Raw Packet Hex Dump**:
   Displays byte offsets and ASCII side-by-side:
   ```text
   0000   35 33 36 35 36 33 37 32 65 37 34 34 31 36 34 6d   |53656372e744164m|
   ```
3. **Reconstructed Payload Assembler**:
   Extracts and decodes the stolen data chunk-by-chunk in real-time.
4. **ACTIVE DEFENSE: Real-Time DNS Sinkholing**:
   Once risk crosses 75%, the detector automatically **injects `0.0.0.0` into the DNS resolver**, instantly killing the covert channel before the remaining file can leak!



Real World Scenario (Company ke andar kya hota hai):


Victim (Company ka Computer): Ek office ka computer hai jisme company ke Customer Credit Cards, Passwords, ya Secret Code rakha hai.

Company ki Security: Company ne USB block kar di, email block kar diya, Google Drive band kar diya taaki koi data bahar na bhej sake.

Attacker (Hacker): Hacker ne computer mein ek chhota sa virus (malware) daal diya. Virus ne dekha ki baaki sab band hai, lekin DNS (Domain Name Server - Port 53) khula hai.

Hacker ka Server: Hacker ne internet par ek server khada kiya hai: attacker-c2.net.

Chori Kaise Hoti Hai: Virus us computer ki file (passwords.txt) ko padhta hai, use Hex/Base64 code mein badalta hai, aur internet par request bhejta hai: 53656372...attacker-c2.net Company ke router se yeh data nikal kar Hacker ke server par chala jata hai!

## 3. How to Run the Demo for an 

### Step 1: Open PowerShell and Launch the Threat Hunter
```powershell
cd d:\CyberSecurity_Projects\DNS_Exfiltration_Detector
py dns_exfiltration_detector.py
```

### Step 2: Show Normal Enterprise Traffic
At the `[Threat-Hunter] Enter query > ` prompt, type:
```text
portal.corp.local
```
- **Result**: `0% Risk Score [🟢 NORMAL TRAFFIC]` (Proves no false alarms).

### Step 3: Run the Animated Cyber Warfare & Sinkhole Lab!
At the prompt, type:
```text
simulate
```
1. Type a sensitive test string (e.g. `Confidential_Salary_Report_2026`).
2. Type target file name (e.g. `company_secrets.txt`).
3. **Watch the live show:**
   - Packets stream with real-time delays.
   - Wireshark-style Hex Dumps print on screen.
   - Payload is decoded live: `Decoded chunk: "Confidential"`.
   - On the 3rd packet, **🚨 REAL-TIME SOC ALARM: THREAT DETECTED & SINKHOLE APPLIED!** fires!
   - Shows: `DNS Resolver injected response: bad-c2-server.net -> 0.0.0.0 (Sinkholed!)`.
   - **Attack is halted mid-stream!**

---

## 4. Direct 1-Line CLI Commands
```powershell
# Inspect single query
py dns_exfiltration_detector.py inspect "portal.corp.local"

# Run direct simulation from terminal
py dns_exfiltration_detector.py simulate --secret "DB_Master_Pass#2026" --file "passwords.txt"
```
