# SHA-256 Hash Generator & Verifier

## 1. Concept Overview
- **Cybersecurity Concept**: Cryptographic Hashing & Data Integrity
- **Algorithm**: Secure Hash Algorithm 256-bit (SHA-256)
- **Key Properties Demonstrated**:
  1. **Deterministic**: Same input always yields the exact same 64-character hex digest.
  2. **Pre-image Resistance (One-Way)**: Impossible to reverse the hash back into original data.
  3. **Avalanche Effect**: Changing just 1 bit or character causes ~50% of the entire output bits to flip.
  4. **HMAC (Hash-based Message Authentication Code)**: Combines a secret key with data to prove authenticity.

---

## 2. Quick Run Guide

### A. Interactive Menu (Great for presentations)
```powershell
cd d:\CyberSecurity_Projects\HashGenerator
py hash_generator.py
```

### B. Command-Line Usage

1. **Hash a plain text string:**
   ```powershell
   py hash_generator.py text "CyberSecurity"
   ```

2. **Generate SHA-256 hash of any file:**
   ```powershell
   py hash_generator.py file d:\CyberSecurity_Projects\fileSecurity\file_encryptor.py
   ```

3. **Verify file checksum against expected vendor hash:**
   ```powershell
   py hash_generator.py verify <file_path> <expected_checksum>
   ```

4. **Demonstrate the Avalanche Effect:**
   ```powershell
   py hash_generator.py avalanche "Password123" "Password124"
   ```

5. **Generate HMAC-SHA256 with a secret key:**
   ```powershell
   py hash_generator.py hmac "Transfer $500 to Bob" --key "MySecretKey"
   ```

