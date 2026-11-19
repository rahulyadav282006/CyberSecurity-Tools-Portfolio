# Forensic Duplicate File Finder & Malware Disguise Radar

## 1. Concept Overview
- **Category**: Level 1 – Python Fundamentals & Digital Forensics Investigation
- **Cybersecurity Concept**: Malware Masquerading (MITRE ATT&CK T1036), Anti-Forensics Detection, File Hash Verification, Storage Waste Auditing
- **Why It Matters in Security**:
  Attackers frequently drop identical malicious payloads under different benign-looking names (e.g. taking `svchost.exe` and renaming it `chrome_update.exe` in `Temp` or `Downloads`). This tool scans directories at high speed, verifies exact duplicate hashes, and flags **Disguised Duplicates** where identical files pretend to be different files.

---

## 2. High-Performance 3-Stage Pipeline

```text
 [Files on Disk]
       │
       ▼
 1. File Size Matching (Filter 1)
    • Fast O(1) filter eliminates ~90% of non-matching files instantly without disk hashing.
       │
       ▼
 2. Partial Hash Check (Filter 2 - First 4 KB)
    • Reads first 4KB of candidate files to avoid hashing entire multi-GB files.
       │
       ▼
 3. Full Cryptographic SHA-256 Digest (Filter 3)
    • 64 KB chunked streaming for 100% cryptographic duplicate guarantee.
```

---

## 3. Combined 3-in-1 Output Architecture (Zero Clutter)

1. **[1] Category & Storage Breakdown**:
   Summarizes wasted space across Documents, Images, Videos, Archives, and Suspicious Executables.
2. **[2] Forensic Grid Table**:
   Clean, compact table displaying ID, Primary File Name, Size, Duplicate Copies, Wasted Space, and Security Status (`⚠️ DISGUISED NAMES` or `🚨 SUSPICIOUS STAGING`).
3. **[3] Interactive Action Console**:
   - Type any **ID number** (e.g. `1`) to expand full file paths & SHA-256 on demand.
   - Type **`q <ID>`** (e.g. `q 1`) to isolate duplicates of that specific set safely to `forensic_quarantine/`.
   - Type **`q all`** to isolate all duplicate copies safely.
   - Type **`html`** to open the interactive visual browser dashboard.

---

## 4. Security Status Explanations (What Interviewers Will Ask)

- **`🚨 SUSPICIOUS STAGING`**:
  Triggered when duplicate executable/script files (`.exe`, `.bat`, `.ps1`) are detected in common attacker staging folders (e.g., `Downloads`, `Temp`, `AppData`, `Public`). In forensics, malware droppers stage secondary payloads in these directories.
- **`⚠️ DISGUISED NAMES`**:
  Triggered when two or more files share the **exact same SHA-256 hash**, but have completely different filenames or extensions (MITRE ATT&CK T1036 - Masquerading).
- **`📄 EXACT DUPLICATE`**:
  Standard benign duplicate files with identical names and identical hashes.

---

## 5. How to Run the Tool

```powershell
cd d:\CyberSecurity_Projects\Duplicate_File_Finder

# Run tool (it will prompt you for any folder path):
py duplicate_finder.py

# Or scan any custom path directly from terminal:
py duplicate_finder.py "C:\Users\Rahul\Downloads"
```
