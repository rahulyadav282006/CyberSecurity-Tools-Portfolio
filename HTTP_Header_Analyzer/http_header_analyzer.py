"""HTTP Security Header Analyzer (Level 2 - Web Security & OWASP Misconfiguration).

Audits web applications against OWASP Recommended Security Headers:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options (Clickjacking defense)
- X-Content-Type-Options (MIME-sniffing defense)
- Referrer-Policy
- Permissions-Policy
- Information Leakage detection (Server banners, X-Powered-By)

Features:
- Clean, compact Terminal Table Scorecard (easy to read in 2 seconds)
- Automatic interactive HTML Audit Dashboard (opens in browser)
- JSON export for security pipelines
- Zero external dependencies (pure Python standard library)

Usage:
    py http_header_analyzer.py                           # Interactive CLI
    py http_header_analyzer.py scan https://github.com  # Scan & auto-open HTML report
    py http_header_analyzer.py scan https://example.com --no-browser # Terminal only
"""

from __future__ import annotations  #Python ke modern Type Hinting

import argparse    #Terminal ke Command-Line Arguments ko professional banana
import html    #Security & Sanitization ke liye.
import json    #Data ko JSON format mein save/read karne ke liye.
import ssl    #  Secure HTTPS (TLS/SSL) encryption context create karne ke liye.
import sys  #  Python runtime aur Operating System exit codes control karne ke liye.
import urllib.error
import urllib.parse
import urllib.request  #Network & Web Requests handle karne ke liye (bina requests library install kiye).
import webbrowser  #Computer ke Default Web Browser (Chrome/Edge)
from pathlib import Path  #Cross-platform File & Folder Paths handle
from typing import Any   #Professional code documentation / code readability

# OWASP Recommended Security Headers
SECURITY_RULES = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "short_name": "HSTS",
        "weight": 20,
        "threat": "SSL Strip / MITM Downgrade",
        "purpose": "Enforces HTTPS connections and prevents cookie hijacking over plaintext HTTP.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "short_name": "CSP",
        "weight": 25,
        "threat": "XSS & Data Injection",
        "purpose": "Restricts sources of executable scripts, stopping Cross-Site Scripting attacks.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "short_name": "XFO",
        "weight": 15,
        "threat": "Clickjacking (UI Redress)",
        "purpose": "Prevents attacker sites from framing this application inside hidden iframes.",
        "recommended": "DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "short_name": "XCTO",
        "weight": 10,
        "threat": "MIME Sniffing Attack",
        "purpose": "Forces the browser to respect declared MIME types, stopping disguised script execution.",
        "recommended": "nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "short_name": "RP",
        "weight": 10,
        "threat": "Sensitive URL Leakage",
        "purpose": "Prevents leaking private query tokens or internal URLs in the HTTP Referer header.",
        "recommended": "strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "short_name": "PP",
        "weight": 10,
        "threat": "Unauthorized Hardware API",
        "purpose": "Restricts browser access to camera, microphone, geolocation, and payment APIs.",
        "recommended": "geolocation=(), microphone=(), camera=()",
    },
}

DISCLOSURE_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "via",
)
#User ke input URL ko check karta hai aur agar aage https:// nahi laga hai, toh automatically jod kar valid format banata hai.

def normalize_url(url: str) -> str:
    """Ensure URL has a valid scheme."""
    cleaned = url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned

#Target website ko ek real browser ki tarah HTTP request bhejta hai aur server ke saare response headers capture karke lata hai.

def fetch_headers(target_url: str, timeout: float = 6.0) -> tuple[int, dict[str, str], str]:
    """Fetch HTTP response headers using Python standard library."""
    parsed = urllib.parse.urlsplit(target_url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {target_url}")

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecurity-Auditor/1.0"},
        method="GET",
    )
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status_code = resp.status
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            return status_code, raw_headers, resp.geturl()
    except urllib.error.HTTPError as err:
        raw_headers = {k.lower(): v for k, v in err.headers.items()}
        return err.code, raw_headers, target_url

#0-se-100 ke numerical score ke basis par website ko security grade (A+, A, B, C, D, F) aur badge color assign karta hai.


def calculate_grade(score: int) -> tuple[str, str, str]:
    """Calculate letter grade, status message, and hex badge color."""
    if score >= 90:
        return "A+", "EXCELLENT - Hardened against major web attacks.", "#22c55e"
    if score >= 80:
        return "A", "VERY GOOD - Strong baseline security headers.", "#16a34a"
    if score >= 70:
        return "B", "GOOD - Some recommended headers missing.", "#3b82f6"
    if score >= 50:
        return "C", "WARNING - Missing multiple defense-in-depth headers.", "#f59e0b"
    if score >= 35:
        return "D", "POOR - High risk of XSS, Clickjacking, or downgrade.", "#f97316"
    return "F", "CRITICAL - Extremely vulnerable web server configuration.", "#ef4444"
# Captured headers ko OWASP rules se match karta hai — missing security headers aur server version leaks par points deduct karke audit result banata hai.
  
def audit_headers(url: str, timeout: float = 6.0) -> dict[str, Any]:
    """Perform security assessment of HTTP response headers."""
    target_url = normalize_url(url)
    status_code, headers, final_url = fetch_headers(target_url, timeout=timeout)

    score = 100
    checklist: list[dict[str, Any]] = []
    disclosures: list[dict[str, str]] = []

    # Check each security rule
    for key, rule in SECURITY_RULES.items():
        present = key in headers
        actual_val = headers.get(key, "")
        if not present:
            score -= rule["weight"]

        checklist.append(
            {
                "key": key,
                "name": rule["name"],
                "short_name": rule["short_name"],
                "status": "PASS" if present else "FAIL",
                "threat": rule["threat"],
                "purpose": rule["purpose"],
                "penalty": rule["weight"],
                "value": actual_val,
                "recommended": rule["recommended"],
            }
        )

    # Check information disclosures
    for disc in DISCLOSURE_HEADERS:
        if disc in headers:
            disclosures.append({"header": disc, "value": headers[disc]})
            score -= 5

    score = max(0, min(100, score))
    grade, summary, color = calculate_grade(score)

    return {
        "target_url": target_url,
        "final_url": final_url,
        "status_code": status_code,
        "score": score,
        "grade": grade,
        "color": color,
        "summary": summary,
        "checklist": checklist,
        "disclosures": disclosures,
    }

#Terminal par clean ASCII scorecard table print karta hai jisme har header ka PASS/FAIL status aur mitigated attack 2 second mein dikh jata hai.


def display_terminal_table(data: dict[str, Any]) -> None:
    """Print a clean, easy-to-read ASCII scorecard table."""
    grade = data["grade"]
    score = data["score"]

    print("\n" + "═" * 78)
    print(f" 🛡️  HTTP SECURITY HEADER SCORECARD : {data['target_url']}")
    print("═" * 78)
    print(f" HTTP Status : {data['status_code']} | Score: {score}/100 | Grade: [{grade}] -> {data['summary']}")
    print("─" * 78)
    print(f" {'#':<2} {'SECURITY HEADER':<28} {'STATUS':<10} {'THREAT MITIGATED':<34}")
    print("─" * 78)

    for idx, item in enumerate(data["checklist"], start=1):
        status_tag = " [ PASS ] " if item["status"] == "PASS" else " [ FAIL ] "
        print(f" {idx:<2} {item['name']:<28} {status_tag:<10} {item['threat']:<34}")

    print("─" * 78)

    # Server banner leakage
    if data["disclosures"]:
        print(" ⚠️  INFORMATION DISCLOSURES DETECTED:")
        for disc in data["disclosures"]:
            print(f"    • Leaked header '{disc['header']}': '{disc['value']}' (helps attacker recon)")
    else:
        print(" ✅ Clean! No server banner / framework version disclosure detected.")

    print("═" * 78 + "\n")

#Saare audit results ko ek visual, modern HTML web dashboard (audit_report.html) mein convert karke save karta hai.
def generate_html_report(data: dict[str, Any], output_path: Path) -> Path:
    """Generate a modern, beautiful HTML security dashboard report."""
    rows_html = []
    for item in data["checklist"]:
        is_pass = item["status"] == "PASS"
        badge = (
            '<span class="badge pass">PASS</span>'
            if is_pass
            else '<span class="badge fail">FAIL (-' + str(item["penalty"]) + " pts)</span>"
        )
        val_display = (
            f"<code>{html.escape(item['value'][:80])}{'...' if len(item['value']) > 80 else ''}</code>"
            if is_pass
            else f'<span class="fix">Recommended: <code>{html.escape(item["recommended"])}</code></span>'
        )

        rows_html.append(
            f"""
            <tr>
                <td><strong>{html.escape(item['name'])}</strong><br><small>{html.escape(item['threat'])}</small></td>
                <td>{badge}</td>
                <td>{val_display}</td>
            </tr>
            """
        )

    disc_html = ""
    if data["disclosures"]:
        items = "".join(
            f"<li><code>{html.escape(d['header'])}: {html.escape(d['value'])}</code></li>"
            for d in data["disclosures"]
        )
        disc_html = f"""
        <div class="card warning">
            <h3>⚠️ Information Disclosure Leaks</h3>
            <p>The web server leaks technical version details to external attackers:</p>
            <ul>{items}</ul>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Audit - {html.escape(data['target_url'])}</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{ background: #0f172a; color: #e2e8f0; padding: 30px 20px; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; background: #1e293b; padding: 25px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }}
    .title h1 {{ font-size: 24px; color: #f8fafc; margin-bottom: 6px; }}
    .title p {{ color: #94a3b8; font-size: 14px; }}
    .score-box {{ text-align: center; background: #0f172a; padding: 15px 25px; border-radius: 10px; border: 2px solid {data['color']}; }}
    .score-grade {{ font-size: 40px; font-weight: 800; color: {data['color']}; line-height: 1; }}
    .score-pts {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
    .card {{ background: #1e293b; border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }}
    .card h2 {{ font-size: 18px; margin-bottom: 15px; color: #38bdf8; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; padding: 12px; font-size: 13px; color: #94a3b8; border-bottom: 1px solid #334155; }}
    td {{ padding: 14px 12px; border-bottom: 1px solid #334155; font-size: 14px; vertical-align: top; }}
    small {{ color: #94a3b8; font-size: 12px; }}
    code {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; font-size: 12px; color: #38bdf8; word-break: break-all; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; }}
    .badge.pass {{ background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid #22c55e; }}
    .badge.fail {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444; }}
    .fix {{ color: #f59e0b; font-size: 13px; }}
    .warning {{ border-left: 4px solid #f59e0b; }}
    .warning h3 {{ color: #f59e0b; font-size: 16px; margin-bottom: 8px; }}
    .warning ul {{ margin-left: 20px; margin-top: 10px; }}
    .remediation {{ background: #0b1329; border: 1px solid #1e293b; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 13px; color: #a5f3fc; overflow-x: auto; line-height: 1.6; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="title">
            <h1>🛡️ HTTP Security Header Audit</h1>
            <p>Target: <strong>{html.escape(data['target_url'])}</strong> (Status: {data['status_code']})</p>
            <p style="margin-top: 4px; color: {data['color']};"><strong>{data['summary']}</strong></p>
        </div>
        <div class="score-box">
            <div class="score-grade">{data['grade']}</div>
            <div class="score-pts">{data['score']} / 100</div>
        </div>
    </div>

    {disc_html}

    <div class="card">
        <h2>Security Headers Evaluation Checklist</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 35%;">Header & Threat</th>
                    <th style="width: 20%;">Status</th>
                    <th style="width: 45%;">Value / Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Remediation Guide (Nginx Configuration)</h2>
        <div class="remediation">
# Add these directives to your Nginx server block:<br>
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;<br>
add_header X-Frame-Options "DENY" always;<br>
add_header X-Content-Type-Options "nosniff" always;<br>
add_header Referrer-Policy "strict-origin-when-cross-origin" always;<br>
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;<br>
add_header Content-Security-Policy "default-src 'self';" always;<br>
server_tokens off; # Hide server banner<br>
        </div>
    </div>
</div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path

#   Terminal mein ek simple 1-se-3 ka numbered menu chalata hai taaki bina commands yaad kiye koi bhi site scan ki ja sake.
def interactive_menu() -> None:
    """Run an interactive CLI menu."""
    while True:
        print("\n" + "=" * 55)
        print("🛡️  Level 2: HTTP Security Header Analyzer")
        print("=" * 55)
        print("1. Scan a Website (Generates Table + Opens Visual HTML)")
        print("2. Scan Insecure Site (example.com - Grade F Demo)")
        print("3. Exit")
        print("=" * 55)

        choice = input("Enter choice (1-3): ").strip()
        if choice == "3":
            print("Exiting tool. Stay secure!")
            break

        target = "https://github.com" if choice == "1" else "http://example.com"
        user_url = input(f"Enter target URL [{target}]: ").strip() or target

        try:
            print(f"\nAnalyzing headers for {user_url}...")
            result = audit_headers(user_url)
            display_terminal_table(result)

            report_file = Path("audit_report.html").resolve()
            generate_html_report(result, report_file)
            print(f"🌐 Visual HTML Report generated: {report_file}")
            webbrowser.open(report_file.as_uri())
        except Exception as err:
            print(f"Error during scan: {err}")
#Terminal command-line arguments (jaise scan, --no-browser, --json) ko read aur parse karta hai.

def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="HTTP Security Header Analyzer (OWASP Web Security Audit Tool)."
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Audit a web application's HTTP response headers")
    p_scan.add_argument("url", help="Target URL (e.g. https://github.com)")
    p_scan.add_argument("-t", "--timeout", type=float, default=6.0, help="Request timeout in seconds")
    p_scan.add_argument("-o", "--output", type=Path, default=Path("audit_report.html"), help="HTML output path")
    p_scan.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    p_scan.add_argument("--json", action="store_true", help="Output audit report as raw JSON")

    return parser

#Program ka main entry-point hai — decide karta hai ki interactive menu dikhana hai ya direct scan run karke browser kholna hai.
def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        interactive_menu()
        return 0

    try:
        report = audit_headers(args.url, timeout=args.timeout)

        if args.json:
            print(json.dumps(report, indent=2))
            return 0

        # Print clean ASCII scorecard
        display_terminal_table(report)

        # Generate HTML report
        out_path = generate_html_report(report, args.output.resolve())
        print(f"🌐 Visual HTML Report saved: {out_path}")

        if not args.no_browser:
            webbrowser.open(out_path.as_uri())

    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
