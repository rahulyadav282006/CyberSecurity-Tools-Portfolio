"""
Secure Notes Tool - Enterprise Encrypted Vault & Incident Defense
==================================================================
Features:
- Clean 3-Option Core Workflow
- Automatic Windows Notepad Integration with Ephemeral Shredding
- Multi-Note Management (Named Notes)
- OS-Level Read-Only Anti-Wipe Protection (attrib +R)
- Anti-Ransomware Shadow Backups (vault_backups/)
- Forensic Incident Audit Logging (alert_file.txt)
"""

import sys
import os
import stat
import json
import uuid
import getpass
import subprocess
import shutil
from datetime import datetime
from base64 import b64encode, b64decode

from crypto_manager import (
    generate_salt,
    derive_key,
    encrypt_text,
    decrypt_text,
    calculate_sha256,
    secure_shred_file,
    InvalidPasswordError,
    TamperDetectedError,
    KDF_ITERATIONS
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "vault_notes")
BACKUP_DIR = os.path.join(BASE_DIR, "vault_backups")
CONFIG_FILE = os.path.join(BASE_DIR, "vault_config.json")
ALERT_FILE = os.path.join(BASE_DIR, "alert_file.txt")
MANIFEST_FILE = os.path.join(BASE_DIR, "vault_manifest.json")

# Ensure required directories exist and protect backup folder
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
try:
    subprocess.run(["attrib", "+H", "+S", BACKUP_DIR], capture_output=True, text=True)
except Exception:
    pass


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"


def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 68)
    print("      🛡️  SECURE NOTES TOOL - ZERO-KNOWLEDGE ENCRYPTED VAULT     ")
    print("     AES-256-GCM | Notepad Auto-Sync | Anti-Ransomware Defense   ")
    print("=" * 68 + f"{Colors.RESET}\n")


def set_file_readonly(file_path: str, readonly: bool = True):
    """Set or remove Windows OS Read-Only attribute to prevent unauthorized file writes."""
    if not os.path.exists(file_path):
        return
    try:
        if readonly:
            os.chmod(file_path, stat.S_IREAD)
            subprocess.run(["attrib", "+R", file_path], capture_output=True, text=True)
        else:
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            subprocess.run(["attrib", "-R", file_path], capture_output=True, text=True)
    except Exception:
        pass


def log_security_incident(event_type: str, note_name: str, details: str):
    """Log tamper and security events to alert_file.txt with forensic timestamps."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = (
        f"\n" + "=" * 68 + "\n"
        f"[🚨 SECURITY INCIDENT DETECTED]\n"
        f"Timestamp   : {now_str}\n"
        f"Event Type  : {event_type}\n"
        f"Target Note : {note_name}\n"
        f"Details     : {details}\n"
        f"Status      : Access Blocked / Integrity Violation Recorded\n"
        + "=" * 68 + "\n"
    )
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(report)


class VaultManager:
    def __init__(self):
        self.salt: bytes = b""
        self.key: bytes = b""
        self.unlocked: bool = False
        self.manifest: dict = self.load_manifest()
        self.alerted_missing: set = set()

    def is_setup(self) -> bool:
        return os.path.exists(CONFIG_FILE)

    def load_manifest(self) -> dict:
        if os.path.exists(MANIFEST_FILE):
            try:
                with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_manifest(self):
        try:
            with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
                json.dump(self.manifest, f, indent=2)
        except Exception:
            pass

    def setup_master_password(self, password: str):
        """First time setup: generates salt and verifier token."""
        self.salt = generate_salt()
        self.key = derive_key(password, self.salt)

        # Encrypt a verification token to validate password in future sessions
        verifier = encrypt_text("VAULT_AUTHENTICATED_OK", self.key)

        config_data = {
            "cipher": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": KDF_ITERATIONS,
            "salt": b64encode(self.salt).decode("utf-8"),
            "verifier": verifier,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        
        self.unlocked = True

    def unlock(self, password: str) -> bool:
        """Unlock vault using master password."""
        if not self.is_setup():
            return False

        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)

        self.salt = b64decode(config["salt"])
        candidate_key = derive_key(password, self.salt)

        # Verify key against the verification token
        try:
            token = decrypt_text(config["verifier"], candidate_key)
            if token == "VAULT_AUTHENTICATED_OK":
                self.key = candidate_key
                self.unlocked = True
                return True
        except (InvalidPasswordError, TamperDetectedError):
            pass

        return False

    def list_notes(self) -> list:
        """Return list of note names and check for unauthorized file deletions."""
        notes = []
        if not os.path.exists(VAULT_DIR):
            return notes

        existing_on_disk = set()
        for f in os.listdir(VAULT_DIR):
            if f.endswith(".enc"):
                note_name = f[:-4]
                existing_on_disk.add(note_name)
                full_path = os.path.join(VAULT_DIR, f)
                mod_time = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M:%S")
                notes.append({
                    "name": note_name,
                    "file": f,
                    "updated_at": mod_time,
                    "path": full_path
                })

        # Check if any note in manifest is missing from disk without authorized deletion (alert once per session)
        for tracked_note in list(self.manifest.keys()):
            if tracked_note not in existing_on_disk:
                if tracked_note not in self.alerted_missing:
                    self.alerted_missing.add(tracked_note)
                    details = f"File '{tracked_note}.enc' was deleted outside the tool by an unauthorized user or malware!"
                    log_security_incident("UNAUTHORIZED_FILE_DELETION_DETECTED", tracked_note, details)
                    print(f"\n{Colors.RED}{Colors.BOLD}[🚨 SECURITY ALERT] Unauthorized File Deletion Detected!")
                    print(f"Note '{tracked_note}.enc' is missing from vault_notes/!")
                    print(f"Incident logged once in alert_file.txt.")
                    print(f"--> Use Option 6 to RESTORE it from backup, or Option 4 to permanently DELETE/DISMISS it.{Colors.RESET}")

        return notes

    def write_note_via_notepad(self, note_name: str) -> bool:
        """
        Creates ephemeral temp file, opens Notepad for the user,
        encrypts upon close, writes Read-Only encrypted file & backup,
        then forensically shreds temp plaintext.
        """
        note_name = note_name.strip().replace(" ", "_")
        target_file = os.path.join(VAULT_DIR, f"{note_name}.enc")
        backup_file = os.path.join(BACKUP_DIR, f"{note_name}.bak.enc")
        
        # Pre-fill content if note already exists
        existing_content = ""
        if os.path.exists(target_file):
            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    payload = json.load(f)["payload"]
                existing_content = decrypt_text(payload, self.key)
            except Exception as e:
                print(f"{Colors.RED}[!] Could not read existing note: {e}{Colors.RESET}")
                return False

        # Create ephemeral temp file
        temp_dir = os.environ.get("TEMP", BASE_DIR)
        temp_file = os.path.join(temp_dir, f"sec_note_{uuid.uuid4().hex[:8]}.txt")

        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(existing_content)

            print(f"\n{Colors.YELLOW}[*] Opening Notepad for '{note_name}'...{Colors.RESET}")
            print(f"{Colors.CYAN}[*] Tip: Write or edit your note, press Ctrl+S to save, then CLOSE Notepad.{Colors.RESET}")
            
            # Synchronously launch Notepad (blocks until user closes Notepad)
            subprocess.run(["notepad.exe", temp_file])

            # Read back user input
            with open(temp_file, "r", encoding="utf-8") as f:
                new_content = f.read()

            if not new_content.strip():
                print(f"{Colors.YELLOW}[!] Note is empty. Nothing saved.{Colors.RESET}")
                return False

            # Encrypt note content with AES-256-GCM
            encrypted_payload = encrypt_text(new_content, self.key)
            
            packet = {
                "note_name": note_name,
                "cipher": "AES-256-GCM",
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "payload": encrypted_payload
            }

            # Remove read-only before writing
            if os.path.exists(target_file):
                set_file_readonly(target_file, False)

            with open(target_file, "w", encoding="utf-8") as f:
                json.dump(packet, f, indent=2)

            # Calculate hash & update manifest immediately while unlocked
            self.manifest[note_name] = {
                "sha256": calculate_sha256(target_file),
                "saved_at": packet["saved_at"]
            }
            self.save_manifest()

            # Apply OS Read-Only Protection
            set_file_readonly(target_file, True)

            # Create Encrypted Shadow Backup
            if os.path.exists(backup_file):
                set_file_readonly(backup_file, False)
            shutil.copy2(target_file, backup_file)
            set_file_readonly(backup_file, True)

            print(f"{Colors.GREEN}[+] Success! Note '{note_name}' encrypted & saved with Read-Only Lock!{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Encrypted Shadow Backup synced to vault_backups/{Colors.RESET}")
            return True

        finally:
            # Forensically shred ephemeral plaintext file
            secure_shred_file(temp_file)

    def view_note_via_notepad(self, note_name: str) -> bool:
        """
        Decrypts note in memory, displays in Notepad for comfortable reading/editing,
        and shreds temp file immediately after Notepad closes.
        """
        target_file = os.path.join(VAULT_DIR, f"{note_name}.enc")
        
        if not os.path.exists(target_file):
            print(f"{Colors.RED}[-] Note '{note_name}' does not exist!{Colors.RESET}")
            # Check if backup exists
            backup_file = os.path.join(BACKUP_DIR, f"{note_name}.bak.enc")
            if os.path.exists(backup_file):
                print(f"{Colors.YELLOW}[!] An encrypted shadow backup WAS found. Use Option 5 to restore it.{Colors.RESET}")
            return False

        # Verify against manifest hash
        current_hash = calculate_sha256(target_file)
        expected_info = self.manifest.get(note_name, {})
        expected_hash = expected_info.get("sha256")

        if expected_hash and current_hash != expected_hash:
            details = f"File hash mismatch! Expected: {expected_hash[:16]}..., Actual: {current_hash[:16]}..."
            log_security_incident("UNAUTHORIZED_MODIFICATION_OR_TAMPER", note_name, details)
            print(f"\n{Colors.RED}{Colors.BOLD}[🚨 SECURITY ALERT] Integrity Compromised!")
            print(f"File '{note_name}.enc' was modified outside the tool by an unauthorized user!")
            print(f"Incident logged in alert_file.txt{Colors.RESET}")

        # Attempt AES-GCM Decryption
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                packet = json.load(f)
            decrypted_text = decrypt_text(packet["payload"], self.key)
        except (InvalidPasswordError, TamperDetectedError) as e:
            details = f"AES-GCM Authentication Tag failed: {e}"
            log_security_incident("CRYPTO_INTEGRITY_FAILURE", note_name, details)
            print(f"\n{Colors.RED}[🚨 DECRYPTION REFUSED] Tamper detected! {e}{Colors.RESET}")
            return False

        # Open in Notepad
        temp_dir = os.environ.get("TEMP", BASE_DIR)
        temp_file = os.path.join(temp_dir, f"sec_view_{uuid.uuid4().hex[:8]}.txt")

        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(decrypted_text)

            print(f"\n{Colors.YELLOW}[*] Opening decrypted note '{note_name}' in Notepad...{Colors.RESET}")
            print(f"{Colors.CYAN}[*] View or edit your note. When done, save and CLOSE Notepad.{Colors.RESET}")
            
            subprocess.run(["notepad.exe", temp_file])

            # Check if user made modifications while viewing
            with open(temp_file, "r", encoding="utf-8") as f:
                updated_content = f.read()

            if updated_content != decrypted_text and updated_content.strip():
                # Re-encrypt updated content
                set_file_readonly(target_file, False)
                packet["payload"] = encrypt_text(updated_content, self.key)
                packet["saved_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(target_file, "w", encoding="utf-8") as f:
                    json.dump(packet, f, indent=2)
                # Calculate hash & update manifest immediately while unlocked
                self.manifest[note_name] = {
                    "sha256": calculate_sha256(target_file),
                    "saved_at": packet["saved_at"]
                }
                self.save_manifest()

                # Apply OS Read-Only Protection
                set_file_readonly(target_file, True)

                # Update backup
                backup_file = os.path.join(BACKUP_DIR, f"{note_name}.bak.enc")
                if os.path.exists(backup_file):
                    set_file_readonly(backup_file, False)
                shutil.copy2(target_file, backup_file)
                set_file_readonly(backup_file, True)
                print(f"{Colors.GREEN}[+] Note updates re-encrypted and saved securely!{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}[+] Note closed. Plaintext wiped from memory.{Colors.RESET}")

            return True

        finally:
            secure_shred_file(temp_file)

    def restore_from_backup(self, note_name: str) -> bool:
        """Restore a missing or corrupted note from encrypted shadow backup."""
        backup_file = os.path.join(BACKUP_DIR, f"{note_name}.bak.enc")
        target_file = os.path.join(VAULT_DIR, f"{note_name}.enc")

        if not os.path.exists(backup_file):
            print(f"{Colors.RED}[-] No shadow backup found for '{note_name}'.{Colors.RESET}")
            return False

        # Verify backup integrity
        try:
            with open(backup_file, "r", encoding="utf-8") as f:
                packet = json.load(f)
            # Test decrypt
            decrypt_text(packet["payload"], self.key)
        except Exception as e:
            print(f"{Colors.RED}[-] Backup file itself is corrupted: {e}{Colors.RESET}")
            return False

        if os.path.exists(target_file):
            set_file_readonly(target_file, False)

        shutil.copy2(backup_file, target_file)
        set_file_readonly(target_file, True)

        self.manifest[note_name] = {
            "sha256": calculate_sha256(target_file),
            "saved_at": packet.get("saved_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        }
        self.save_manifest()
        self.alerted_missing.discard(note_name)

        log_security_incident("BACKUP_RESTORE_EXECUTED", note_name, "Restored note from encrypted shadow backup.")
        print(f"{Colors.GREEN}[+] Success! Note '{note_name}' restored from encrypted shadow backup!{Colors.RESET}")
        return True

    def delete_note(self, note_name: str, password: str) -> bool:
        """
        Permanently delete a note and its backup upon Master Password verification.
        Distinguishes authorized deletion from unauthorized deletion.
        """
        if not self.unlock(password):
            print(f"{Colors.RED}[-] Incorrect Master Password! Deletion aborted.{Colors.RESET}")
            log_security_incident("UNAUTHORIZED_DELETION_ATTEMPT", note_name, "Failed password verification during note deletion request.")
            return False

        target_file = os.path.join(VAULT_DIR, f"{note_name}.enc")
        backup_file = os.path.join(BACKUP_DIR, f"{note_name}.bak.enc")

        if not os.path.exists(target_file) and not os.path.exists(backup_file):
            print(f"{Colors.RED}[-] Note '{note_name}' does not exist.{Colors.RESET}")
            return False

        # Remove from manifest first so no unauthorized missing file alarm triggers
        if note_name in self.manifest:
            del self.manifest[note_name]
            self.save_manifest()
        self.alerted_missing.discard(note_name)

        # Shred and remove main encrypted file
        if os.path.exists(target_file):
            set_file_readonly(target_file, False)
            secure_shred_file(target_file)

        # Remove backup
        if os.path.exists(backup_file):
            set_file_readonly(backup_file, False)
            secure_shred_file(backup_file)

        print(f"{Colors.GREEN}[+] Success! Note '{note_name}' and its shadow backup were permanently deleted by authorized user.{Colors.RESET}")
        return True


def display_alert_logs():
    """Display incident forensics log."""
    if not os.path.exists(ALERT_FILE) or os.path.getsize(ALERT_FILE) == 0:
        print(f"\n{Colors.GREEN}[+] No security incidents or tampering detected. All files intact.{Colors.RESET}")
        return

    print(f"\n{Colors.RED}{Colors.BOLD}--- SECURITY INCIDENT FORENSIC LOG (alert_file.txt) ---{Colors.RESET}")
    with open(ALERT_FILE, "r", encoding="utf-8") as f:
        print(f.read())


def main():
    print_banner()
    vault = VaultManager()

    # Step 1: Password Check / Setup
    if not vault.is_setup():
        print(f"{Colors.YELLOW}[!] Welcome! First-time setup: Create your Master Password.{Colors.RESET}")
        while True:
            p1 = getpass.getpass("Enter Master Password (min 8 chars): ")
            if len(p1) < 8:
                print(f"{Colors.RED}[-] Password too short. Enter at least 8 characters.{Colors.RESET}")
                continue
            p2 = getpass.getpass("Confirm Master Password: ")
            if p1 != p2:
                print(f"{Colors.RED}[-] Passwords do not match. Try again.{Colors.RESET}")
                continue
            break
        vault.setup_master_password(p1)
        print(f"{Colors.GREEN}[+] Master Password created! Vault is ready.{Colors.RESET}\n")

    # Interactive Loop
    while True:
        print(f"\n{Colors.BOLD}--- MAIN MENU ---{Colors.RESET}")
        print("1. [🔑] Enter / Unlock Master Password")
        print("2. [📝] Write / Create Note (Opens Notepad)")
        print("3. [📖] View / Read Note (Opens Notepad)")
        print("4. [🗑️] Delete Note (Requires Master Password)")
        print("5. [🚨] Security Alerts & Tamper Logs (alert_file.txt)")
        print("6. [🛡️] Restore Note from Encrypted Backup (Anti-Ransomware)")
        print("7. [❌] Exit & Lock")

        choice = input(f"\n{Colors.CYAN}Select an option [1-7]: {Colors.RESET}").strip()

        if choice == "1":
            if vault.unlocked:
                print(f"{Colors.GREEN}[+] Vault is already unlocked and active.{Colors.RESET}")
            else:
                pw = getpass.getpass("Enter Master Password: ")
                if vault.unlock(pw):
                    print(f"{Colors.GREEN}[+] Vault unlocked successfully!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[-] Incorrect password! Access denied.{Colors.RESET}")

        elif choice == "2":
            if not vault.unlocked:
                pw = getpass.getpass("Enter Master Password to create note: ")
                if not vault.unlock(pw):
                    print(f"{Colors.RED}[-] Incorrect password! Access denied.{Colors.RESET}")
                    continue

            name = input("Enter Note Name (e.g., wifi_pass, bank_info, work_secrets): ").strip()
            if not name:
                print(f"{Colors.RED}[-] Note name cannot be empty.{Colors.RESET}")
                continue
            vault.write_note_via_notepad(name)

        elif choice == "3":
            if not vault.unlocked:
                pw = getpass.getpass("Enter Master Password to view notes: ")
                if not vault.unlock(pw):
                    print(f"{Colors.RED}[-] Incorrect password! Access denied.{Colors.RESET}")
                    continue

            notes = vault.list_notes()
            if not notes:
                print(f"{Colors.YELLOW}[!] No notes found in vault. Create one with Option 2 first!{Colors.RESET}")
                continue

            print(f"\n{Colors.CYAN}--- Available Encrypted Notes ---{Colors.RESET}")
            for idx, n in enumerate(notes, 1):
                print(f"[{idx}] {n['name']}  (Last updated: {n['updated_at']})")

            sel = input("\nEnter Note Number or Note Name: ").strip()
            target_name = ""
            if sel.isdigit() and 1 <= int(sel) <= len(notes):
                target_name = notes[int(sel) - 1]["name"]
            else:
                target_name = sel

            if target_name:
                vault.view_note_via_notepad(target_name)

        elif choice == "4":
            notes = vault.list_notes()
            if not notes:
                print(f"{Colors.YELLOW}[!] No notes available to delete.{Colors.RESET}")
                continue

            print(f"\n{Colors.CYAN}--- Delete Note (Authorized Deletion) ---{Colors.RESET}")
            for idx, n in enumerate(notes, 1):
                print(f"[{idx}] {n['name']}")

            sel = input("\nEnter Note Number or Note Name to DELETE: ").strip()
            target_name = ""
            if sel.isdigit() and 1 <= int(sel) <= len(notes):
                target_name = notes[int(sel) - 1]["name"]
            else:
                target_name = sel

            if not target_name:
                continue

            confirm = input(f"Are you sure you want to permanently delete '{target_name}'? (y/N): ").strip().lower()
            if confirm == "y":
                del_pw = getpass.getpass("Enter Master Password to confirm authorized deletion: ")
                vault.delete_note(target_name, del_pw)
            else:
                print("Deletion cancelled.")

        elif choice == "5":
            display_alert_logs()

        elif choice == "6":
            if not vault.unlocked:
                pw = getpass.getpass("Enter Master Password to restore: ")
                if not vault.unlock(pw):
                    print(f"{Colors.RED}[-] Incorrect password! Access denied.{Colors.RESET}")
                    continue

            # List backups
            backups = [f[:-8] for f in os.listdir(BACKUP_DIR) if f.endswith(".bak.enc")]
            if not backups:
                print(f"{Colors.YELLOW}[!] No backups found in vault_backups/{Colors.RESET}")
                continue

            print(f"\n{Colors.CYAN}--- Available Shadow Backups ---{Colors.RESET}")
            for idx, b in enumerate(backups, 1):
                print(f"[{idx}] {b}")

            sel = input("\nEnter Note Name to restore: ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(backups):
                sel = backups[int(sel) - 1]

            vault.restore_from_backup(sel)

        elif choice == "7":
            print(f"\n{Colors.GREEN}[*] Wiping session keys and locking vault... Goodbye!{Colors.RESET}\n")
            vault.key = b""
            vault.unlocked = False
            break

        else:
            print(f"{Colors.RED}[-] Invalid option. Please select 1 to 7.{Colors.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Program closed by user.{Colors.RESET}")
        sys.exit(0)
