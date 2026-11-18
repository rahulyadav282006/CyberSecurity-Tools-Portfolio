"""Authorized Port Scanner & Service Banner Fingerprinter.

(Level 3 - Ethical Hacking & Network Reconnaissance Fundamentals).

Features:
- Multi-threaded TCP connect scan (concurrent.futures) for fast execution
- Service name mapping via socket standard library and fallback database
- Banner grabbing for service fingerprinting and version detection
- High-risk / legacy protocol alerting (Telnet 23, FTP 21, SMB 445, RDP 3389)
- Authorization gate & legal disclaimer to enforce ethical security practices
- Clean terminal scorecard table + JSON export
- Zero external dependencies (pure Python standard library)

Usage:
    py port_scanner.py                         # Interactive CLI menu
    py port_scanner.py scan 127.0.0.1          # Scan localhost top 20 ports
    py port_scanner.py scan 127.0.0.1 -p 1-1024 # Scan standard ports 1-1024
    py port_scanner.py scan scanme.nmap.org -p 22,80,443 # Scan specific ports
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import time
from typing import Any

# Top common ports for fast default scanning
TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]

# High-risk / unencrypted / sensitive ports that require immediate security attention
HIGH_RISK_PORTS = {
    21: "FTP (Plaintext credentials, unencrypted file transfer)",
    23: "Telnet (CRITICAL: Plaintext remote access, easily intercepted)",
    25: "SMTP (Open mail relay risk if misconfigured)",
    135: "RPC (Windows Remote Procedure Call, frequent exploit target)",
    139: "NetBIOS (LAN reconnaissance / legacy sharing)",
    445: "SMB (WannaCry / EternalBlue / lateral movement risk)",
    1433: "MS-SQL (Exposed database port)",
    3306: "MySQL (Exposed database port)",
    3389: "RDP (Windows Remote Desktop, brute-force target)",
    5432: "PostgreSQL (Exposed database port)",
}

COMMON_SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "OracleDB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy/Alt",
}


def resolve_target(target: str) -> tuple[str, str]:
    """Resolve a target hostname or IP to (canonical_name, ip_address)."""
    try:
        ip = socket.gethostbyname(target)
        try:
            name, _, _ = socket.gethostbyaddr(ip)
        except OSError:
            name = target
        return name, ip
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}': {exc}") from exc


def parse_port_range(port_spec: str) -> list[int]:
    """Parse port specs like '80', '22,80,443', '1-100', 'top20' into a sorted list of ints."""
    cleaned = port_spec.strip().lower()
    if cleaned in ("top", "top20", "default"):
        return TOP_20_PORTS

    ports: set[int] = set()
    parts = cleaned.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Invalid port range '{part}'. Ports must be 1-65535.")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} out of range (1-65535).")
            ports.add(p)

    return sorted(ports)


def grab_banner(target_ip: str, port: int, timeout: float = 1.0) -> str:
    """Attempt to grab raw service banner for service identification."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))

            # Trigger banners on web/text services
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in (21, 22, 25, 110, 143):
                pass  # These services talk first (greeting banner)
            else:
                s.sendall(b"\r\n")

            data = s.recv(1024)
            # Clean and sanitize banner output
            banner = data.decode("utf-8", errors="ignore").strip()
            # Extract first line or server header
            if "Server:" in banner:
                match = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
                if match:
                    return f"Server: {match.group(1).strip()}"
            first_line = banner.splitlines()[0] if banner else ""
            return first_line[:60] if first_line else "No banner returned"
    except (socket.timeout, OSError):
        return "No banner returned"


def scan_single_port(target_ip: str, port: int, timeout: float = 1.0) -> dict[str, Any] | None:
    """Perform a TCP connect handshake on a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                # Door is open!
                # Identify service name
                try:
                    svc_name = socket.getservbyport(port, "tcp")
                except OSError:
                    svc_name = COMMON_SERVICE_NAMES.get(port, "unknown")

                # Grab service banner
                banner = grab_banner(target_ip, port, timeout=timeout)
                risk_note = HIGH_RISK_PORTS.get(port, None)

                return {
                    "port": port,
                    "state": "OPEN",
                    "service": svc_name,
                    "banner": banner,
                    "risk": risk_note,
                }
    except OSError:
        pass
    return None


def run_port_scan(
    target: str,
    ports: list[int],
    max_threads: int = 50,
    timeout: float = 1.0,
) -> dict[str, Any]:
    """Scan target ports using multi-threaded worker pool."""
    hostname, target_ip = resolve_target(target)
    start_time = time.time()
    open_ports: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_map = {
            executor.submit(scan_single_port, target_ip, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            if res is not None:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    duration = time.time() - start_time

    return {
        "target": target,
        "hostname": hostname,
        "ip": target_ip,
        "total_scanned": len(ports),
        "open_count": len(open_ports),
        "closed_or_filtered": len(ports) - len(open_ports),
        "duration_seconds": round(duration, 2),
        "open_ports": open_ports,
    }


def display_results_table(data: dict[str, Any]) -> None:
    """Print a clean, professional security scorecard table."""
    print("\n" + "═" * 78)
    print(" 🎯 AUTHORIZED PORT & SERVICE DISCOVERY REPORT")
    print("═" * 78)
    print(f" Target Host : {data['target']} ({data['hostname']})")
    print(f" IP Address  : {data['ip']}")
    print(f" Ports Tested: {data['total_scanned']} | Open: {data['open_count']} | Scan Time: {data['duration_seconds']}s")
    print("─" * 78)

    if not data["open_ports"]:
        print(" [!] No open ports detected in the scanned range (all closed or filtered).")
        print("═" * 78 + "\n")
        return

    print(f" {'PORT':<8} {'STATE':<8} {'SERVICE':<12} {'BANNER / VERSION / RISK NOTE':<48}")
    print("─" * 78)

    for item in data["open_ports"]:
        port_label = f"{item['port']}/tcp"
        svc = item["service"][:11]
        banner = item["banner"]
        if item["risk"]:
            note = f"⚠️ {item['risk'][:44]}"
        else:
            note = banner[:45] if banner != "No banner returned" else "Banner: None"

        print(f" {port_label:<8} {'[OPEN]':<8} {svc:<12} {note:<48}")

    print("─" * 78)

    # Highlight any critical security risks
    risky = [p for p in data["open_ports"] if p.get("risk")]
    if risky:
        print(" ⚠️ SECURITY FINDINGS & RECOMMENDATIONS:")
        for r in risky:
            print(f"    • Port {r['port']} ({r['service'].upper()}): {r['risk']}")
            if r["port"] in (21, 23):
                print("      Fix: Disable unencrypted legacy protocol. Migrate to SSH (Port 22) or SFTP.")
            elif r["port"] in (1433, 3306, 5432):
                print("      Fix: Restrict database port to localhost / VPN via firewall rules.")
            elif r["port"] == 3389:
                print("      Fix: Put RDP behind a VPN / Zero-Trust gateway and enable MFA.")
    else:
        print(" ✅ Clean! No legacy unencrypted high-risk ports detected.")

    print("═" * 78 + "\n")


def interactive_menu() -> None:
    """Run interactive CLI menu with ethical authorization prompt."""
    print("\n" + "=" * 60)
    print("🛡️  Level 3: Authorized Port Scanner & Service Fingerprinter")
    print("=" * 60)
    print("⚠️  LEGAL NOTICE: Only scan systems you own or have explicit,")
    print("   written authorization to test (e.g. localhost, home lab,")
    print("   or authorized testing endpoints like scanme.nmap.org).")
    print("=" * 60)

    auth = input("\nDo you have authorization to scan your intended target? (y/n) [y]: ").strip().lower() or "y"
    if auth != "y":
        print("Scan aborted. Always ensure authorized scope.")
        return

    while True:
        print("\nPreset Targets:")
        print("1. Localhost (127.0.0.1) - Safe local computer check")
        print("2. Authorized Public Test (scanme.nmap.org)")
        print("3. Custom Host / IP & Custom Ports")
        print("4. Exit")

        choice = input("\nSelect option (1-4): ").strip()
        if choice == "4":
            print("Exiting scanner. Stay safe!")
            break

        if choice == "1":
            target = "127.0.0.1"
            ports = TOP_20_PORTS
        elif choice == "2":
            target = "scanme.nmap.org"
            ports = [22, 80, 443, 9929, 31337]
        elif choice == "3":
            target = input("Enter target IP or hostname: ").strip()
            if not target:
                continue
            ports_in = input("Enter ports (e.g. '80,443', '1-100', or 'top') [top]: ").strip() or "top"
            try:
                ports = parse_port_range(ports_in)
            except ValueError as err:
                print(f"Error: {err}")
                continue
        else:
            print("Invalid choice.")
            continue

        print(f"\n[+] Starting authorized scan on {target} ({len(ports)} ports)...")
        try:
            results = run_port_scan(target, ports, max_threads=40, timeout=1.0)
            display_results_table(results)
        except Exception as err:
            print(f"Scan failed: {err}")


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Authorized Port Scanner & Service Banner Fingerprinter (Level 3 Ethical Hacking)."
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan a target host")
    p_scan.add_argument("target", help="Target hostname or IP (e.g. 127.0.0.1, scanme.nmap.org)")
    p_scan.add_argument("-p", "--ports", default="top", help="Ports to scan: 'top', '22,80,443', '1-1024'")
    p_scan.add_argument("-t", "--timeout", type=float, default=1.0, help="Socket timeout per port (seconds)")
    p_scan.add_argument("-w", "--threads", type=int, default=50, help="Max worker threads (default: 50)")
    p_scan.add_argument("--json", action="store_true", help="Output results as raw JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        interactive_menu()
        return 0

    try:
        ports = parse_port_range(args.ports)
        data = run_port_scan(args.target, ports, max_threads=args.threads, timeout=args.timeout)

        if args.json:
            print(json.dumps(data, indent=2))
        else:
            display_results_table(data)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
