"""IP Address Analyzer & Subnet Calculator (Level 2 - Core Networking & Reconnaissance).

Features:
- IPv4 & IPv6 parsing and validation
- Scope classification: Public, Private (RFC 1918), Loopback, Link-Local, Multicast, Reserved
- Subnet analysis: Network address, Broadcast, Netmask, Wildcard mask, Host range, Usable host count
- Binary representation of IP and Subnet mask (great for explaining bitwise AND operations)
- Free public GeoIP & ASN lookup (via ip-api.com without extra API keys)
- Reverse DNS (PTR) lookup
- Subnet host calculator / CIDR planner
- Interactive CLI + command-line arguments

Usage:
    py ip_analyzer.py                            # Interactive menu
    py ip_analyzer.py inspect 192.168.1.50/24    # Analyze IPv4 with CIDR
    py ip_analyzer.py inspect 8.8.8.8            # Analyze public IP with GeoIP
    py ip_analyzer.py inspect 2001:4860:4860::8888 # Analyze IPv6 address
    py ip_analyzer.py subnet 10.0.0.0/22         # Full subnet planning breakdown
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import urllib.error
import urllib.request
from typing import Any


def format_binary(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Format an IP address as dot/colon separated binary blocks."""
    if isinstance(ip_obj, ipaddress.IPv4Address):
        raw_bin = f"{int(ip_obj):032b}"
        return ".".join(raw_bin[i : i + 8] for i in range(0, 32, 8))
    # IPv6
    raw_bin = f"{int(ip_obj):0128b}"  #Converts an IP address like 192.168.1.1 into raw 0s and 1s
    return ":".join(raw_bin[i : i + 16] for i in range(0, 128, 16))

#Check karta hai ki IP ka type kya hai — Private (RFC 1918), Public (Internet), Loopback (127.0.0.1), ya Multicast.

def classify_scope(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[str]:
    """Identify all RFC security classifications for an IP."""
    tags: list[str] = []
    if ip_obj.is_private:
        tags.append("Private (RFC 1918 / RFC 4193 - Internal)")
    if ip_obj.is_global:
        tags.append("Public / Globally Routable (Internet-facing)")
    if ip_obj.is_loopback:
        tags.append("Loopback (Localhost)")
    if ip_obj.is_link_local:
        tags.append("Link-Local (Auto-configured)")
    if ip_obj.is_multicast:
        tags.append("Multicast")
    if ip_obj.is_reserved:
        tags.append("Reserved (IETF)")
    return tags or ["Unspecified"]

#IP address se uska associated Domain Name (PTR record) dhoondhta hai (jaise 1.1.1.1 

# one.one.one.one)
def reverse_dns_lookup(ip_str: str) -> str:
    """Perform a reverse DNS (PTR) lookup to find associated domain."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return "No PTR record found"
#Public IP ko internet API (ip-api.com) par bhej kar uski Country, City, ISP aur ASN organization details fetch karta ha

def fetch_geoip(ip_str: str, timeout: float = 4.0) -> dict[str, Any] | None:
    """Fetch GeoIP & ASN data for public IPs using ip-api.com."""
    url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"
    req = urllib.request.Request(url, headers={"User-Agent": "CyberSecurity-IPAnalyzer/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success":
                return data
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        pass
    return None

#Subnet mask ke bits ko invert (ulats) karke Wildcard Mask banata hai, jo Cisco Firewalls aur ACL rules mein use hota hai.
def calculate_wildcard_mask(netmask: ipaddress.IPv4Address) -> str:
    """Calculate the Cisco/Firewall wildcard (inverse) mask."""
    mask_int = int(netmask)
    wildcard_int = ~mask_int & 0xFFFFFFFF
    return str(ipaddress.IPv4Address(wildcard_int))

#Saare functions ko combine karke IP ka full analysis karta hai (usable host range, network address, broadcast, GeoIP, etc.).
def analyze_network(target: str, fetch_geo: bool = True) -> dict[str, Any]:
    """Perform full networking and security inspection of an IP / CIDR."""
    # Handle plain IP or IP/mask
    try:
        network = ipaddress.ip_network(target, strict=False)
        # If user passed a single IP, extract the specific address
        if "/" in target:
            interface = ipaddress.ip_interface(target)
            ip_obj = interface.ip
        else:
            ip_obj = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address or CIDR notation: '{target}' ({exc})") from exc

    is_ipv4 = ip_obj.version == 4
    scope_tags = classify_scope(ip_obj)
    ptr_record = reverse_dns_lookup(str(ip_obj))

    result: dict[str, Any] = {
        "input": target,
        "version": f"IPv{ip_obj.version}",
        "address": str(ip_obj),
        "compressed": ip_obj.compressed,
        "exploded": ip_obj.exploded,
        "binary": format_binary(ip_obj),
        "scope": scope_tags,
        "is_private": ip_obj.is_private,
        "is_public": ip_obj.is_global,
        "reverse_dns": ptr_record,
        "cidr_prefix": network.prefixlen,
        "network_address": str(network.network_address),
        "total_addresses": network.num_addresses,
    }

    if is_ipv4:
        netmask = network.netmask
        broadcast = network.broadcast_address
        wildcard = calculate_wildcard_mask(netmask)
        usable_hosts = max(0, network.num_addresses - 2) if network.prefixlen < 31 else network.num_addresses

        if network.prefixlen < 31:
            first_host = str(network.network_address + 1)
            last_host = str(network.broadcast_address - 1)
        else:
            first_host = str(network.network_address)
            last_host = str(network.broadcast_address)

        result.update(
            {
                "netmask": str(netmask),
                "netmask_binary": format_binary(netmask),
                "wildcard_mask": wildcard,
                "broadcast_address": str(broadcast),
                "first_usable_host": first_host,
                "last_usable_host": last_host,
                "usable_hosts": usable_hosts,
            }
        )

    # Optional GeoIP for public IPs
    result["geoip"] = None
    if fetch_geo and ip_obj.is_global:
        result["geoip"] = fetch_geoip(str(ip_obj))

    return result

# Analyzed data ko clean, structured aur professional terminal report (3 sections) mein print karta hai.
def display_analysis(res: dict[str, Any]) -> None:
    """Pretty print the analysis result in an interview/demo friendly layout."""
    print("\n" + "=" * 65)
    print(f"🌐 IP ADDRESS & NETWORK ANALYSIS : {res['input']}")
    print("=" * 65)

    print("\n[1] IP Address Identification")
    print(f"  • Address          : {res['address']}")
    print(f"  • Protocol Version : {res['version']}")
    print(f"  • Scope / Type     : {', '.join(res['scope'])}")
    print(f"  • Reverse DNS (PTR): {res['reverse_dns']}")
    print(f"  • Binary Form      : {res['binary']}")

    if "netmask" in res:
        print("\n[2] Subnet & Addressing Details (IPv4)")
        print(f"  • CIDR Notation    : /{res['cidr_prefix']}")
        print(f"  • Subnet Mask      : {res['netmask']}")
        print(f"  • Subnet in Binary : {res['netmask_binary']}")
        print(f"  • Wildcard Mask    : {res['wildcard_mask']} (ACLs / OSPF)")
        print(f"  • Network Address  : {res['network_address']}")
        print(f"  • Broadcast Address: {res['broadcast_address']}")
        print(f"  • Usable Host Range: {res['first_usable_host']} -> {res['last_usable_host']}")
        print(f"  • Total Addresses  : {res['total_addresses']:,}")
        print(f"  • Usable Host Count: {res['usable_hosts']:,}")
    else:
        print("\n[2] Subnet Details (IPv6)")
        print(f"  • Prefix Length    : /{res['cidr_prefix']}")
        print(f"  • Network Address  : {res['network_address']}")
        print(f"  • Exploded Form    : {res['exploded']}")
        print(f"  • Total Addresses  : 2^{128 - res['cidr_prefix']} ({res['total_addresses']})")

    # GeoIP section
    geo = res.get("geoip")
    print("\n[3] Geolocation & Threat Reconnaissance")
    if geo:
        print(f"  • Country / City   : {geo.get('country', 'N/A')}, {geo.get('city', 'N/A')} ({geo.get('zip', 'N/A')})")
        print(f"  • Coordinates      : Lat {geo.get('lat')}, Lon {geo.get('lon')}")
        print(f"  • ISP              : {geo.get('isp', 'N/A')}")
        print(f"  • Organization     : {geo.get('org', 'N/A')}")
        print(f"  • Autonomous System: {geo.get('as', 'N/A')}")
    elif res.get("is_private"):
        print("  • Private RFC 1918 Address: Not publicly routable over the Internet.")
        print("  • Threat Context: Internal LAN address (typically protected behind NAT/Firewall).")
    elif not res.get("is_public"):
        print("  • Non-routable / Special-purpose IP: No public Geolocation available.")
    else:
        print("  • Public IP, but Geolocation lookup timed out or was skipped.")

    print("=" * 65 + "\n")

#User ko screen par 1-se-5 tak ka simple menu dikhata hai taaki bina commands yaad kiye tool use kiya ja sake.
def interactive_menu() -> None:
    """Run an interactive CLI menu."""
    while True:
        print("\n" + "=" * 55)
        print("🔍 Level 2: IP Address Analyzer & Subnet Tool")
        print("=" * 55)
        print("1. Inspect IP / Subnet (e.g. 192.168.1.1 or 10.0.0.0/24)")
        print("2. Analyze Public IP (with GeoIP & ASN Recon)")
        print("3. Analyze IPv6 Address")
        print("4. Quick Subnet Calculator (/8 to /30)")
        print("5. Exit")
        print("=" * 55)

        choice = input("Enter choice (1-5): ").strip()
        if choice == "5":
            print("Exiting tool. Happy networking!")
            break

        if choice in ("1", "2", "3"):
            default = "8.8.8.8" if choice == "2" else ("2001:4860:4860::8888" if choice == "3" else "192.168.1.50/24")
            target = input(f"Enter target IP or CIDR [{default}]: ").strip() or default
            try:
                res = analyze_network(target)
                display_analysis(res)
            except ValueError as err:
                print(f"Error: {err}")

        elif choice == "4":
            ip_base = input("Enter network base IP [192.168.1.0]: ").strip() or "192.168.1.0"
            prefix = input("Enter CIDR prefix (e.g. 24, 26, 28) [24]: ").strip() or "24"
            try:
                res = analyze_network(f"{ip_base}/{prefix}", fetch_geo=False)
                display_analysis(res)
            except ValueError as err:
                print(f"Error: {err}")

#Terminal command-line arguments (jaise inspect, subnet, --json) ko handle aur parse karta hai.
def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="IP Address Analyzer & Subnet Calculator (Level 2 Cybersecurity)."
    )
    sub = parser.add_subparsers(dest="command")

    p_inspect = sub.add_parser("inspect", help="Inspect an IP or CIDR network")
    p_inspect.add_argument("target", help="IP address or CIDR (e.g. 8.8.8.8 or 192.168.0.0/24)")
    p_inspect.add_argument("--no-geo", action="store_true", help="Skip public GeoIP lookup")
    p_inspect.add_argument("--json", action="store_true", help="Output results as raw JSON")

    p_subnet = sub.add_parser("subnet", help="Subnet planning & host breakdown")
    p_subnet.add_argument("cidr", help="CIDR network (e.g. 10.0.0.0/22)")
    p_subnet.add_argument("--json", action="store_true", help="Output results as raw JSON")

    return parser

#Script ka starting entry-point hai — decide karta hai ki interactive menu kholna hai ya direct CLI command execute karni hai.
def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        interactive_menu()
        return 0

    try:
        if args.command == "inspect":
            data = analyze_network(args.target, fetch_geo=not args.no_geo)
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                display_analysis(data)
        elif args.command == "subnet":
            data = analyze_network(args.cidr, fetch_geo=False)
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                display_analysis(data)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
