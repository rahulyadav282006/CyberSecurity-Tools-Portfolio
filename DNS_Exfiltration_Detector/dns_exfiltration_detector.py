"""DNS Data Exfiltration & Covert Channel Hunter (Live SOC Radar & Active Defense).

Enterprise Threat Hunting Simulation & Defense Engine.

Features:
1. Live Packet Transmission & Flight Animation (Real-time network streaming delay)
2. Wireshark-Style Raw Hex Dump Inspector (Shows raw byte offsets & ASCII breakdown)
3. Multi-Vector Statistical Forensics:
   - Subdomain Label Length Anomaly (RFC 1035 compliance)
   - Shannon Entropy Calculation (Base64 / Hex binary density)
   - Sliding Time-Window Query Burst Rate
4. Reconstructed Payload Assembler: Recovers the stolen file chunk-by-chunk in real-time
5. ACTIVE DEFENSE: Real-Time DNS Sinkholing (0.0.0.0 Injection)
   Halts the attack mid-stream once confidence threshold is crossed!
6. Zero external dependencies (pure Python standard library).

Usage:
    py dns_exfiltration_detector.py                         # Live interactive prompt
    py dns_exfiltration_detector.py simulate                # Run live exfiltration & defense lab
    py dns_exfiltration_detector.py inspect <query>         # Inspect single query
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import math
import re
import sys
import time
from pathlib import Path
from typing import Any

# Detection Thresholds based on RFC 1035 and SANS Cyber Threat Intelligence benchmarks
MAX_NORMAL_LABEL_LENGTH = 30        # Normal sub domains 4 or 6 letter ka hota hai  agar 30 se upar hua toh vo hacker hai
ENTROPY_TUNNELING_THRESHOLD = 3.65   # hacker random english use karta hai tho agar uska entorpy 3.65se jada hai hto vo hacker nhi tho normal 2.8 enropty hota hai simpe english words  ka
BURST_QUERY_THRESHOLD = 5           # agar systems se 30 seconds ma 5 se jada query or packet send huaa hai tho vo hacker hai
WINDOW_SECONDS = 30                 #  30 second ke andar

# whitelist  subdomain hai jo hamara tool detect nahi kare or false alert de 
STANDARD_SAFE_DOMAINS = {
    "example.com", "example.net", "example.org", "test.lan", "corp.local", "internal.network",
}


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon Entropy of a string to detect encoded data."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = collections.Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def extract_domain_parts(query_name: str) -> tuple[str, str, str]:
    """Extract (subdomain_payload, apex_domain, full_domain)."""
    cleaned = query_name.strip().rstrip(".").lower()
    parts = cleaned.split(".")
    if len(parts) <= 2:
        return "", cleaned, cleaned

    apex = f"{parts[-2]}.{parts[-1]}"
    subdomain = ".".join(parts[:-2])
    return subdomain, apex, cleaned


def format_hex_dump(data_bytes: bytes) -> str:
    """Format raw bytes as a Wireshark-style hex dump with offsets and ASCII representation."""
    lines = []
    for i in range(0, len(data_bytes), 16):
        chunk = data_bytes[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  {i:04x}   {hex_part:<48}   |{ascii_part}|")
    return "\n".join(lines)


def attempt_decode_payload(subdomain: str) -> tuple[bool, str, str]:
    """Attempt to decode hex, base32, or base64 data to prove active data exfiltration."""
    # Split by dot to find the actual payload segment (ignore sequence tags like sq1, seq1, p1)
    parts = subdomain.split(".")
    payload_candidates = [p for p in parts if not re.fullmatch(r"(sq|seq|p|pkt|chunk)?\d+", p, re.IGNORECASE)]
    
    clean_sub = payload_candidates[0] if payload_candidates else subdomain.replace(".", "").replace("-", "")
    clean_sub = clean_sub.replace("-", "")

    if len(clean_sub) < 4:
        return False, "", "Too short"

    # 1. First check Hex / Base16 (Strict Hex validation)
    if re.fullmatch(r"[0-9a-fA-F]+", clean_sub) and len(clean_sub) % 2 == 0:
        try:
            raw_bytes = binascii.unhexlify(clean_sub)
            decoded = raw_bytes.decode("utf-8", errors="ignore")
            # If at least 60% characters are standard printable ASCII
            if decoded and sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded) >= 0.60:
                return True, decoded, "HEX (Base16)"
        except Exception:
            pass

    # 2. Try Base32
    pad_b32 = clean_sub.upper() + "=" * ((8 - len(clean_sub) % 8) % 8)
    if re.fullmatch(r"[A-Z2-7=]+", pad_b32) and len(pad_b32) >= 8:
        try:
            raw_bytes = base64.b32decode(pad_b32)
            decoded = raw_bytes.decode("utf-8", errors="ignore")
            if decoded and sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded) >= 0.60:
                return True, decoded, "Base32"
        except Exception:
            pass

    # 3. Try Base64
    pad_b64 = clean_sub + "=" * ((4 - len(clean_sub) % 4) % 4)
    if re.fullmatch(r"[A-Za-z0-9+/=]+", pad_b64) and not re.fullmatch(r"[0-9a-fA-F]+", clean_sub):
        try:
            raw_bytes = base64.b64decode(pad_b64)
            decoded = raw_bytes.decode("utf-8", errors="ignore")
            if decoded and sum(32 <= ord(c) <= 126 for c in decoded) / len(decoded) >= 0.60:
                return True, decoded, "Base64"
        except Exception:
            pass

    return False, "", "Unknown / Encrypted"


class DNSTracker:
    """Threat hunting correlation and active defense sinkhole engine."""

    def __init__(self) -> None:
        self.domain_history: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)
        self.exfiltrated_chunks: dict[str, list[str]] = collections.defaultdict(list)
        self.sinkholed_domains: set[str] = set()

    def record_query(self, query_name: str, client_ip: str = "192.168.1.50", qtype: str = "A") -> dict[str, Any]:
        """Analyze a DNS query against multiple statistical and heuristic models."""
        subdomain, apex, full_domain = extract_domain_parts(query_name)
        now = time.time()

        # Check if already sinkholed
        if apex in self.sinkholed_domains:
            return {
                "query": full_domain,
                "subdomain": subdomain,
                "apex": apex,
                "client_ip": client_ip,
                "qtype": qtype.upper(),
                "longest_label": len(subdomain),
                "entropy": calculate_entropy(subdomain.replace(".", "")),
                "burst_count": len(self.domain_history[apex]),
                "risk_score": 100,
                "verdict": "SINKHOLED_BLOCKED",
                "verdict_badge": "🛑 BLOCKED (SINKHOLE ACTIVE)",
                "action": "ATTACK BLOCKED: DNS Resolver actively responding with 0.0.0.0. Exfiltration halted.",
                "indicators": [{"flag": "Active DNS Sinkhole Enforced", "weight": 0, "detail": "Traffic dropped to 0.0.0.0 sinkhole."}],
                "decoded_data": None,
                "encoding": None,
                "sinkholed": True,
            }

        history = self.domain_history[apex]
        history.append(now)
        while history and (now - history[0] > WINDOW_SECONDS):
            history.popleft()

        burst_count = len(history)
        longest_label_len = max((len(part) for part in subdomain.split(".")), default=0)
        subdomain_entropy = calculate_entropy(subdomain.replace(".", ""))

        risk_score = 0
        indicators: list[dict[str, Any]] = []

        # 1. Label Length Anomaly
        if longest_label_len > MAX_NORMAL_LABEL_LENGTH:
            pts = 35 if longest_label_len > 45 else 20
            risk_score += pts
            indicators.append(
                {
                    "flag": f"Abnormal Subdomain Label Length ({longest_label_len} chars)",
                    "weight": pts,
                    "detail": "Exceeds standard enterprise naming; typical of covert payload packing.",
                }
            )

        # 2. Shannon Entropy of Subdomain (Information Density)
        if subdomain_entropy >= ENTROPY_TUNNELING_THRESHOLD:
            pts = 30 if subdomain_entropy > 4.1 else 20
            risk_score += pts
            indicators.append(
                {
                    "flag": f"High Subdomain Entropy ({subdomain_entropy} bits)",
                    "weight": pts,
                    "detail": "High lexical randomness indicative of Base64 / Hex binary exfiltration.",
                }
            )

        # 3. Frequency Burst / Exfiltration Rate
        if burst_count >= BURST_QUERY_THRESHOLD:
            risk_score += 25
            indicators.append(
                {
                    "flag": f"High Query Burst Rate ({burst_count} queries in {WINDOW_SECONDS}s)",
                    "weight": 25,
                    "detail": f"Burst queries targeting apex '{apex}' consistent with multi-packet data leak.",
                }
            )

        # 4. Large TXT / NULL Query abuse
        if qtype.upper() in ("TXT", "NULL"):
            risk_score += 15
            indicators.append(
                {
                    "flag": f"Suspicious Record Type ({qtype.upper()})",
                    "weight": 15,
                    "detail": "Attackers exploit TXT/NULL queries for bi-directional command-and-control (C2).",
                }
            )

        # 5. Payload Reconstruction & Decoding
        is_decoded, decoded_payload, encoding_type = attempt_decode_payload(subdomain)
        if is_decoded and len(decoded_payload) >= 3:
            pts = 50
            risk_score += pts
            indicators.append(
                {
                    "flag": f"Covert Payload Decoded via {encoding_type}",
                    "weight": pts,
                    "detail": f"Decoded chunk: '{decoded_payload[:40]}'",
                }
            )
            self.exfiltrated_chunks[apex].append(decoded_payload)

        risk_score = min(100, risk_score)

        # Active Defense: Apply DNS Sinkhole if risk >= 65% (Active exfiltration confirmed)
        sinkholed = False
        if risk_score >= 65:
            self.sinkholed_domains.add(apex)
            sinkholed = True
            verdict = "CONFIRMED_EXFILTRATION"
            verdict_badge = "🔴 ACTIVE EXFILTRATION (SINKHOLE TRIGGERED)"
            action = "ACTIVE DEFENSE ENGAGED: Injected 0.0.0.0 sinkhole into DNS resolver. Channel TERMINATED!"
        elif risk_score >= 35:
            verdict = "SUSPICIOUS_TUNNELING"
            verdict_badge = "🟡 SUSPICIOUS TUNNEL"
            action = "INVESTIGATE: Elevated entropy or label length. Monitor client IP for C2 activity."
        else:
            verdict = "BENIGN"
            verdict_badge = "🟢 NORMAL TRAFFIC"
            action = "NORMAL: Standard domain lookup. No exfiltration markers detected."

        return {
            "query": full_domain,
            "subdomain": subdomain,
            "apex": apex,
            "client_ip": client_ip,
            "qtype": qtype.upper(),
            "burst_count": burst_count,
            "entropy": subdomain_entropy,
            "longest_label": longest_label_len,
            "risk_score": risk_score,
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "action": action,
            "indicators": indicators,
            "decoded_data": decoded_payload if is_decoded else None,
            "encoding": encoding_type if is_decoded else None,
            "sinkholed": sinkholed,
        }


def print_cyber_warfare_header() -> None:
    """Print the visual threat simulation banner."""
    print("\n" + "╔" + "═" * 76 + "╗")
    print("║   ⚔️  LIVE DNS COVERT CHANNEL & DATA EXFILTRATION THREAT LAB (PORT 53)     ║")
    print("╚" + "═" * 76 + "╝")
    print(" [VICTIM HOST: 192.168.1.50]                [ATTACKER C2: 185.220.101.5]")
    print(" [Firewall Status: ALL HTTP/HTTPS BLOCKED]  [Covert DNS Listener: Active UDP 53]")
    print(" " + "─" * 76)


def run_live_attack_simulation(secret_data: str, target_file_name: str = "passwords.txt", apex_domain: str = "bad-c2-server.net") -> None:
    """Feature 1 & 2: Live packet streaming animation, Wireshark hex dumps, and mid-stream DNS sinkholing."""
    print_cyber_warfare_header()
    print(f"\n[+] TARGET SENSITIVE FILE  : '{target_file_name}' ({len(secret_data)} bytes)")
    print(f"[+] ORIGINAL FILE CONTENT  : \"{secret_data}\"")
    print(f"[+] ATTACKER APEX C2 DOMAIN: '{apex_domain}'")
    print("\n[!] Victim firewall blocks all outbound Web/FTP traffic.")
    print("[!] Malware activates DNS Tunneling: Chunking file into covert UDP queries...")
    print(" " + "═" * 76)

    # Encode file into realistic DNS tunneling chunks (36-40 chars per query)
    hex_str = binascii.hexlify(secret_data.encode("utf-8")).decode("utf-8")
    chunk_size = 36  # Realistic tunneling chunk size (> 30 char RFC baseline)
    raw_chunks = [hex_str[i : i + chunk_size] for i in range(0, len(hex_str), chunk_size)]
    total_packets = len(raw_chunks)

    tracker = DNSTracker()
    reconstructed_bytes = ""

    for idx, chunk in enumerate(raw_chunks, start=1):
        query = f"{chunk}.sq{idx}.{apex_domain}"
        
        # Real-time packet flight delay
        time.sleep(0.4)

        print(f"\n>>> [PACKET {idx}/{total_packets}] IN-FLIGHT: UDP 53 ---> {query}")
        
        # Wireshark-Style Hex Dump
        raw_payload = chunk.encode("utf-8")
        print("    ┌─── WIRESHARK RAW PACKET HEX DUMP ─────────────────────────")
        print(format_hex_dump(raw_payload))
        print("    └───────────────────────────────────────────────────────────")

        # Detector sniffs and processes the query
        res = tracker.record_query(query, client_ip="192.168.1.50")
        
        # Show analysis line
        status_icon = "🟢" if res["risk_score"] < 35 else ("🟡" if res["risk_score"] < 75 else "🔴")
        print(f"    • Forensic Analysis: Entropy={res['entropy']} bits | LabelLen={res['longest_label']} | Risk={res['risk_score']}% {status_icon}")

        if res.get("decoded_data"):
            reconstructed_bytes += res["decoded_data"]
            print(f"    • Decoded Chunk    : \"{res['decoded_data']}\" via {res['encoding']}")

        # Feature 2: Active Defense (DNS Sinkhole Triggered Mid-Stream)
        if res.get("sinkholed"):
            print("\n" + "!" * 78)
            print("🚨 REAL-TIME SOC ALARM: THREAT DETECTED & SINKHOLE APPLIED!")
            print("!" * 78)
            print(f" [!] Threshold Crossed : Risk Score reached {res['risk_score']}% on Packet {idx}/{total_packets}")
            print(f" [!] Exfiltrated File  : '{target_file_name}' (Attack interrupted at {int((idx/total_packets)*100)}% completion)")
            print(f" [!] Intercepted Data  : \"{reconstructed_bytes}\"")
            print(" [⚡ ACTIVE DEFENSE ENGAGED]:")
            print(f"     DNS Resolver injected response: {apex_domain} -> 0.0.0.0 (Sinkholed!)")
            print("     Firewall Rule: Inbound/Outbound UDP Port 53 to 185.220.101.5 BLOCKED.")
            print("     ATTACK TERMINATED MID-STREAM! Remaining data could not leave the network.")
            print("!" * 78 + "\n")
            return

    print("\n" + "═" * 76)
    print(f"✅ Simulation Complete. Final Reconstructed Payload: \"{reconstructed_bytes}\"")
    print("═" * 76 + "\n")


def display_audit_report(res: dict[str, Any]) -> None:
    """Print an auditable forensic report table."""
    score = res["risk_score"]
    badge = res["verdict_badge"]

    print("\n" + "═" * 78)
    print(" 📡 DNS EXFILTRATION & THREAT HUNTING REPORT")
    print("═" * 78)
    print(f" Target Query   : {res['query']}")
    print(f" Apex Domain    : {res['apex']} | Record Type: {res['qtype']}")
    print(f" Metrics        : Entropy: {res['entropy']} bits | Label Len: {res['longest_label']} | Burst: {res['burst_count']} q/30s")
    print(f" Risk Assessment: {score}% Risk Score  [{badge}]")
    print("─" * 78)

    print("\n 🎯 ACTIONABLE INCIDENT RESPONSE DECISION:")
    print(f"    {res['action']}")

    if res.get("decoded_data"):
        print("\n 🔓 RECONSTRUCTED & DECODED EXFILTRATED DATA:")
        print(f"    Encoding : {res['encoding']}")
        print(f"    Payload  : \"{res['decoded_data']}\"")

    print("\n" + "─" * 78)
    print(f" {'#':<2} {'DETECTED INDICATOR':<35} {'WEIGHT':<10} {'FORENSIC EVIDENCE'}")
    print("─" * 78)

    if not res["indicators"]:
        print("    Clean! Query complies with normal RFC 1035 lexical and statistical baselines.")
    else:
        for idx, item in enumerate(res["indicators"], start=1):
            penalty_str = f"+{item['weight']} pts"
            print(f" {idx:<2} {item['flag']:<35} {penalty_str:<10} {item['detail']}")

    print("═" * 78 + "\n")


def interactive_threat_hunter() -> None:
    """Prompt-based real-time analysis interface."""
    tracker = DNSTracker()

    print("\n" + "=" * 68)
    print("🛡️  DNS EXFILTRATION & COVERT TUNNELING DETECTOR (Threat Hunter)")
    print("=" * 68)
    print("Commands:")
    print("  • Type or paste any DNS query (e.g., 'portal.corp.local')")
    print("  • Type 'simulate' to launch live warfare animation & sinkhole lab")
    print("  • Type 'exit' to quit")
    print("=" * 68)

    while True:
        try:
            user_input = input("\n[Threat-Hunter] Enter query > ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                print("Exiting Threat Hunter. Defend the perimeter!")
                break

            if user_input.lower() == "simulate":
                secret = input("\nEnter sensitive text to leak [e.g. 'DB_Master_Pass#2026']: ").strip() or "DB_Master_Pass#2026"
                filename = input("Target filename to steal [e.g. 'company_secrets.txt']: ").strip() or "company_secrets.txt"
                run_live_attack_simulation(secret, target_file_name=filename)
            else:
                res = tracker.record_query(user_input)
                display_audit_report(res)

        except KeyboardInterrupt:
            print("\n[!] Stopped by analyst.")
            break
        except Exception as err:
            print(f"Error during analysis: {err}")


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="DNS Exfiltration & Covert Tunneling Detector (Enterprise Threat Hunter)."
    )
    sub = parser.add_subparsers(dest="command")

    p_inspect = sub.add_parser("inspect", help="Inspect a single DNS query")
    p_inspect.add_argument("query", help="Query string (e.g. 'portal.corp.local')")
    p_inspect.add_argument("--type", default="A", help="DNS query type (A, TXT, CNAME)")
    p_inspect.add_argument("--json", action="store_true", help="Output audit report as raw JSON")

    p_sim = sub.add_parser("simulate", help="Launch live animated cyber warfare & sinkhole simulation")
    p_sim.add_argument("--secret", default="SecretAdminPass123_Confidential", help="Secret text to exfiltrate")
    p_sim.add_argument("--file", default="company_secrets.txt", help="Filename of the stolen data")
    p_sim.add_argument("--domain", default="bad-c2-server.net", help="Target apex domain")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        interactive_threat_hunter()
        return 0

    tracker = DNSTracker()

    try:
        if args.command == "inspect":
            res = tracker.record_query(args.query, qtype=args.type)
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                display_audit_report(res)

        elif args.command == "simulate":
            run_live_attack_simulation(args.secret, target_file_name=args.file, apex_domain=args.domain)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
