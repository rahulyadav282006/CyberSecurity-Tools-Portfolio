# 🛡️ Enterprise Secure Notes Tool & Anti-Ransomware Vault

An enterprise-grade, zero-knowledge, encrypted-at-rest CLI application to store multi-file confidential notes, credentials, and security audit logs with **Notepad Auto-Integration**, **OS Read-Only Locks**, **Anti-Ransomware Shadow Backups**, and **Forensic Incident Logging (`alert_file.txt`)**.

---

## 🎯 Key Innovations for Cybersecurity Interviews

1. **Notepad Auto-Launch + Zero-Trace Shredding**:
   - Opens Windows Notepad automatically so the user writes/edits comfortably in a GUI.
   - Upon closing Notepad, the ephemeral temporary file is overwritten with zeroes and random bytes (`secure_shred_file`) before deletion to eliminate forensic data recovery from unallocated disk sectors.
2. **Multi-File Named Storage**:
   - Store separate encrypted notes (e.g. `wifi_pass`, `bank_details`, `server_keys`) in `vault_notes/<name>.enc`.
3. **OS-Level Read-Only Protection (`attrib +R`)**:
   - Windows Read-Only file attribute is automatically enforced on all `.enc` files.
   - Attackers opening `.enc` in Notepad are blocked by Windows from overwriting or modifying the file.
4. **Anti-Ransomware Encrypted Shadow Backups**:
   - Every save creates a secondary encrypted copy in `vault_backups/`.
   - If an attacker deletes or destroys the primary file, the tool detects it and offers a **1-click restore** using the Master Password.
5. **Digital Forensics Incident Logging (`alert_file.txt`)**:
   - Every note's SHA-256 hash is tracked in a manifest.
   - Any bit-flip, tamper, or external modification logs a timestamped incident report with expected vs actual hashes in `alert_file.txt`.
6. **OWASP-Compliant Cryptography**:
   - **AES-256-GCM** (Galois/Counter Mode) with 96-bit CSPRNG nonces (`os.urandom`).
   - **PBKDF2-HMAC-SHA256** with **600,000 rounds** and a 128-bit salt to prevent GPU dictionary attacks.

---

## 📁 Project Directory Structure

```text
Secure_Notes_Tool/
│
├── vault_notes/             # Encrypted notes storage (.enc files with Read-Only Lock)
│   ├── wifi_pass.enc
│   └── bank_details.enc
│
├── vault_backups/           # Encrypted shadow backups (Anti-Ransomware recovery)
│   ├── wifi_pass.bak.enc
│   └── bank_details.bak.enc
│
├── alert_file.txt           # Forensic audit logs (tamper and deletion incident reports)
├── crypto_manager.py        # AES-256-GCM engine, PBKDF2 KDF, and secure file shredder
├── secure_notes.py          # Main CLI application with auto-Notepad sync
├── requirements.txt         # Dependencies (cryptography)
└── README.md                # Documentation
```

---

## 🚀 Running the Main Interactive Tool

```powershell
cd D:\CyberSecurity_Projects\Secure_Notes_Tool
py secure_notes.py
```

### Menu Overview:
```text
====================================================================
      🛡️  SECURE NOTES TOOL - ZERO-KNOWLEDGE ENCRYPTED VAULT     
     AES-256-GCM | Notepad Auto-Sync | Anti-Ransomware Defense   
====================================================================

--- MAIN MENU ---
1. [🔑] Enter / Unlock Master Password
2. [📝] Write / Create Note (Opens Notepad)
3. [📖] View / Read Note (Opens Notepad)
4. [🗑️] Delete Note (Requires Master Password)
5. [🚨] Security Alerts & Tamper Logs (alert_file.txt)
6. [🛡️] Restore Note from Encrypted Backup (Anti-Ransomware)
7. [❌] Exit & Lock
```

---

## 💬 Cybersecurity Interview Questions & Answers

### Q1: What happens if an attacker opens the encrypted `.enc` file in Notepad?
> **Answer**: The file content is ciphertext (base64-encoded AES-256-GCM encrypted bytes). Furthermore, because our tool enforces the Windows OS Read-Only attribute (`attrib +R`), Notepad will warn the attacker that the file cannot be saved or overwritten.

### Q2: What happens if an attacker forcibly edits or flips a single byte in the ciphertext?
> **Answer**: AES-256-GCM uses an authenticated Galois tag. Any bit manipulation corrupts the tag verification. The tool refuses decryption and logs a forensic incident report in `alert_file.txt` detailing the timestamp, target file, and SHA-256 hash mismatch.

### Q3: What happens if ransomware or an attacker deletes a note completely?
> **Answer**: The tool maintains an automated encrypted shadow backup in `vault_backups/`. The user can enter their Master Password in Option 5 and recover 100% of their note in seconds.

### Q4: Why shred temporary files instead of standard `os.remove()`?
> **Answer**: Normal file deletion simply marks filesystem pointers as free, leaving raw plaintext in unallocated disk space recoverable via digital forensics tools (like Autopsy or Photorec). Our `secure_shred_file()` overwrites the file sectors with random bytes and zeroes before unlinking.
