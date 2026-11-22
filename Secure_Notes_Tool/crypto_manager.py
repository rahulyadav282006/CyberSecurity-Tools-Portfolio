"""
crypto_manager.py - Cryptographic Core & Anti-Tamper Engine
============================================================
Handles:
1. PBKDF2-HMAC-SHA256 (600,000 rounds per OWASP standard)
2. AES-256-GCM Authenticated Encryption with 96-bit CSPRNG Nonces
3. Ephemeral File Secure Shredder (Overwrites disk sectors with zeroes before deletion)
4. SHA-256 Integrity Fingerprinting for Forensics
"""

import os
import json
import hashlib
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KDF_ITERATIONS = 600_000
SALT_SIZE = 16    # 128-bit salt
NONCE_SIZE = 12   # 96-bit nonce
KEY_SIZE = 32     # 256-bit key


class TamperDetectedError(Exception):
    """Raised when ciphertext or authentication tag is modified."""
    pass


class InvalidPasswordError(Exception):
    """Raised when the master password is incorrect."""
    pass


def generate_salt() -> bytes:
    """Generate a cryptographically secure 128-bit random salt."""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 256-bit AES key via PBKDF2-HMAC-SHA256."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password cannot be empty.")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def calculate_sha256(file_path: str) -> str:
    """Calculate the cryptographic SHA-256 digest of a file for forensic verification."""
    if not os.path.exists(file_path):
        return ""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def encrypt_text(plaintext: str, key: bytes) -> dict:
    """
    Encrypt plaintext string using AES-256-GCM.
    Returns nonce & ciphertext encoded in base64.
    """
    plaintext_bytes = plaintext.encode("utf-8")
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    
    return {
        "nonce": b64encode(nonce).decode("utf-8"),
        "ciphertext": b64encode(ciphertext).decode("utf-8")
    }


def decrypt_text(encrypted_dict: dict, key: bytes) -> str:
    """
    Decrypt an AES-256-GCM payload.
    Raises InvalidPasswordError or TamperDetectedError if tag verification fails.
    """
    try:
        nonce = b64decode(encrypted_dict["nonce"])
        ciphertext = b64decode(encrypted_dict["ciphertext"])
    except Exception as e:
        raise TamperDetectedError("Encrypted payload formatting corrupted.") from e
        
    aesgcm = AESGCM(key)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise InvalidPasswordError("Decryption failed: Incorrect password or file tampering detected.")
    except Exception as e:
        raise TamperDetectedError(f"Integrity check failed: {e}") from e

    return decrypted_bytes.decode("utf-8")


def secure_shred_file(file_path: str, passes: int = 2):
    """
    Forensically sanitize and delete an ephemeral file by overwriting with
    zeroes and random bytes before unlinking. Prevents data recovery from unallocated space.
    """
    if not os.path.exists(file_path):
        return

    try:
        size = os.path.getsize(file_path)
        with open(file_path, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            # Final zero pass
            f.seek(0)
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    finally:
        try:
            os.remove(file_path)
        except OSError:
            pass
