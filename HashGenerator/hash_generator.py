"""Cryptographic Hash Generator & Verifier (SHA-256 / SHA-family / MD5 / HMAC).

Demonstrates core cryptographic hashing concepts:
- One-way hashing (pre-image resistance)
- Avalanche effect demonstration (small change -> totally different hash)
- File integrity hash generation (chunked streaming for large files)
- Hash verification / checksum matching against vendor digests
- HMAC (Hash-based Message Authentication Code) with secret key

Usage:
    py hash_generator.py                             # Interactive CLI
    py hash_generator.py text "hello"                # Hash plain text
    py hash_generator.py file <path>                 # Hash a file
    py hash_generator.py verify <path> <expected>    # Verify file against checksum
    py hash_generator.py avalanche "cat" "cot"       # Demonstrate avalanche effect
    py hash_generator.py hmac "data" --key "secret"  # Generate HMAC-SHA256
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from pathlib import Path

SUPPORTED_ALGORITHMS = ("sha256", "sha512", "sha3_256", "sha1", "md5")
CHUNK_SIZE = 65536


def hash_text(text: str, algorithm: str = "sha256") -> str:
    """Compute the cryptographic hash of a text string."""
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Supported: {', '.join(SUPPORTED_ALGORITHMS)}")
    hasher = hashlib.new(algo)
    hasher.update(text.encode("utf-8"))
    return hasher.hexdigest()


def hash_file(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of a file by streaming chunks."""
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Supported: {', '.join(SUPPORTED_ALGORITHMS)}")

    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.new(algo)
    with file_path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_all_algorithms(data: bytes) -> dict[str, str]:
    """Compute digests for all major algorithms at once (useful for comparison)."""
    results: dict[str, str] = {}
    for algo in SUPPORTED_ALGORITHMS:
        h = hashlib.new(algo)
        h.update(data)
        results[algo] = h.hexdigest()
    return results


def verify_hash(file_path: Path, expected_hash: str, algorithm: str = "sha256") -> tuple[bool, str]:
    """Verify whether a file's calculated hash matches the expected hash."""
    calculated = hash_file(file_path, algorithm=algorithm)
    matches = calculated.lower().strip() == expected_hash.lower().strip()
    return matches, calculated


def generate_hmac(data: str, secret_key: str, algorithm: str = "sha256") -> str:
    """Generate Hash-based Message Authentication Code (HMAC) using a secret key."""
    return hmac.new(
        secret_key.encode("utf-8"),
        data.encode("utf-8"),
        algorithm,
    ).hexdigest()


def demonstrate_avalanche(text1: str, text2: str, algorithm: str = "sha256") -> dict[str, any]:
    """Demonstrate the Avalanche Effect: tiny input change produces totally different hash."""
    h1 = hash_text(text1, algorithm)
    h2 = hash_text(text2, algorithm)

    # Convert hex digests to binary strings to calculate bit difference
    b1 = bin(int(h1, 16))[2:].zfill(len(h1) * 4)
    b2 = bin(int(h2, 16))[2:].zfill(len(h2) * 4)

    total_bits = len(b1)
    diff_bits = sum(c1 != c2 for c1, c2 in zip(b1, b2))
    percent_diff = (diff_bits / total_bits) * 100

    return {
        "input1": text1,
        "input2": text2,
        "hash1": h1,
        "hash2": h2,
        "total_bits": total_bits,
        "diff_bits": diff_bits,
        "percent_diff": round(percent_diff, 2),
    }


def interactive_menu() -> None:
    """Run an interactive CLI menu for students and presentations."""
    while True:
        print("\n" + "=" * 55)
        print("🔐 SHA-256 & Cryptographic Hash Suite")
        print("=" * 55)
        print("1. Hash a Text String (Single / All Algorithms)")
        print("2. Hash a File (SHA-256)")
        print("3. Verify File Integrity (Check Expected Checksum)")
        print("4. Demonstrate Avalanche Effect (Cybersecurity Concept)")
        print("5. Generate HMAC with Secret Key (Message Authentication)")
        print("6. Exit")
        print("=" * 55)

        choice = input("Select an option (1-6): ").strip()
        if choice == "6":
            print("Goodbye!")
            break

        if choice == "1":
            text = input("\nEnter text to hash: ")
            show_all = input("Show all algorithms (SHA256, SHA512, SHA1, MD5)? (y/n) [n]: ").strip().lower()
            if show_all == "y":
                digests = hash_all_algorithms(text.encode("utf-8"))
                print("\nCryptographic Digests:")
                for algo, digest in digests.items():
                    warning = " ⚠️ (Broken for security)" if algo in ("md5", "sha1") else ""
                    print(f"  {algo.upper():<10}: {digest}{warning}")
            else:
                algo = input("Algorithm (default: sha256): ").strip() or "sha256"
                try:
                    digest = hash_text(text, algo)
                    print(f"\n[{algo.upper()}] Digest: {digest}")
                except ValueError as err:
                    print(f"Error: {err}")

        elif choice == "2":
            path_str = input("\nEnter file path: ").strip().strip('"').strip("'")
            algo = input("Algorithm [sha256]: ").strip() or "sha256"
            try:
                digest = hash_file(Path(path_str), algo)
                size = Path(path_str).stat().st_size
                print(f"\nFile: {path_str} ({size:,} bytes)")
                print(f"[{algo.upper()}]: {digest}")
            except Exception as err:
                print(f"Error: {err}")

        elif choice == "3":
            path_str = input("\nEnter file path: ").strip().strip('"').strip("'")
            expected = input("Paste expected checksum / hash: ").strip()
            algo = input("Algorithm [sha256]: ").strip() or "sha256"
            try:
                matches, calc = verify_hash(Path(path_str), expected, algo)
                print(f"\nCalculated : {calc}")
                print(f"Expected   : {expected.lower()}")
                if matches:
                    print("✅ VERIFIED: File is authentic and untampered!")
                else:
                    print("❌ INTEGRITY FAILED: Hashes do NOT match! File may be corrupt or tampered.")
            except Exception as err:
                print(f"Error: {err}")

        elif choice == "4":
            print("\nDemonstrating the Avalanche Effect...")
            t1 = input("Enter first text [e.g. 'Password123']: ").strip() or "Password123"
            t2 = input("Enter slightly altered text [e.g. 'Password124']: ").strip() or "Password124"
            res = demonstrate_avalanche(t1, t2)
            print(f"\nInput 1: '{res['input1']}'")
            print(f"Hash 1 : {res['hash1']}")
            print(f"\nInput 2: '{res['input2']}'")
            print(f"Hash 2 : {res['hash2']}")
            print(f"\nResult : {res['diff_bits']} out of {res['total_bits']} bits changed ({res['percent_diff']}%)")
            print("Notice: Changing just 1 single character flips roughly ~50% of all hash bits!")

        elif choice == "5":
            msg = input("\nEnter message to sign: ")
            key = input("Enter secret key: ")
            mac = generate_hmac(msg, key)
            print(f"\n[HMAC-SHA256]: {mac}")
            print("Use this to verify authenticity: only someone with the secret key can generate this code.")


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Cryptographic Hash Generator & Verifier (SHA-256 / SHA-family / HMAC)."
    )
    sub = parser.add_subparsers(dest="command")

    # Text subcommand
    p_text = sub.add_parser("text", help="Hash a string")
    p_text.add_argument("data", help="Text to hash")
    p_text.add_argument("-a", "--algo", default="sha256", choices=SUPPORTED_ALGORITHMS, help="Hash algorithm")

    # File subcommand
    p_file = sub.add_parser("file", help="Hash a file")
    p_file.add_argument("path", type=Path, help="File to hash")
    p_file.add_argument("-a", "--algo", default="sha256", choices=SUPPORTED_ALGORITHMS, help="Hash algorithm")

    # Verify subcommand
    p_ver = sub.add_parser("verify", help="Verify a file against expected hash")
    p_ver.add_argument("path", type=Path, help="File to verify")
    p_ver.add_argument("expected", help="Expected hash string")
    p_ver.add_argument("-a", "--algo", default="sha256", choices=SUPPORTED_ALGORITHMS, help="Hash algorithm")

    # Avalanche subcommand
    p_ava = sub.add_parser("avalanche", help="Demonstrate the avalanche effect")
    p_ava.add_argument("text1", help="First text string")
    p_ava.add_argument("text2", help="Second slightly modified string")

    # HMAC subcommand
    p_hmac = sub.add_parser("hmac", help="Generate HMAC-SHA256")
    p_hmac.add_argument("data", help="Message data")
    p_hmac.add_argument("--key", required=True, help="Secret key")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        interactive_menu()
        return 0

    try:
        if args.command == "text":
            print(hash_text(args.data, args.algo))
        elif args.command == "file":
            print(hash_file(args.path, args.algo))
        elif args.command == "verify":
            matches, calc = verify_hash(args.path, args.expected, args.algo)
            print(f"Calculated: {calc}")
            print(f"Expected  : {args.expected.lower()}")
            if matches:
                print("Status    : OK (Integrity Verified)")
                return 0
            print("Status    : FAILED (Hash Mismatch)")
            return 1
        elif args.command == "avalanche":
            res = demonstrate_avalanche(args.text1, args.text2)
            print(f"Input 1: {res['input1']} -> {res['hash1']}")
            print(f"Input 2: {res['input2']} -> {res['hash2']}")
            print(f"Bits Changed: {res['diff_bits']} / {res['total_bits']} ({res['percent_diff']}%)")
        elif args.command == "hmac":
            print(generate_hmac(args.data, args.key))
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

