"""Failed Login Detector & Interactive Web Honeypot / SOC Dashboard.

(Project 17: Authentication Attacks & Brute-Force Detection).

All 4 Killer Features Fully Implemented:
1. Attacker ki Live "Jasoosi" (GeoIP & ISP Recon via ip-api.com)
2. "Account Takeover" Detection (Password cracked after brute-force)
3. Built-in "Attack Simulator" (One-click realistic Tor/External attack)
4. 1-Click "Active Defense / Auto-Blocker" (Executes real Windows Firewall block command)

Usage:
    py app.py               # Starts web server and auto-opens browser
    py app.py --port 8080   # Custom port
"""

from __future__ import annotations

import argparse
import html
import http.server
import json
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Security Thresholds
MAX_FAILED_ATTEMPTS = 5         # Exceeding this triggers brute-force alert & IP block
BLOCK_DURATION_SECONDS = 45      # Temporary IP quarantine time
SLIDING_WINDOW_SECONDS = 60      # Window to count rapid failed attempts

# Known authorized users in the demo database
DEMO_USERS = {
    "admin": "SecurePass2026!",
    "rahul": "CyberSecurity#1",
    "john": "P@ssword123",
}

LOG_FILE = Path("auth_events.log")

# Cache GeoIP results to avoid redundant API hits
GEOIP_CACHE: dict[str, dict[str, Any]] = {}


def fetch_geoip_recon(ip: str) -> dict[str, Any]:
    """Live Jasoosi: Fetch country, city, ISP and organization for an IP."""
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]

    # Special handling for local/private IPs
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith(("192.168.", "10.", "172.16.")):
        recon = {
            "country": "Local / Internal LAN",
            "city": "Private Network",
            "isp": "Localhost / Internal Interface",
            "org": "Internal Workstation",
            "is_private": True,
        }
        GEOIP_CACHE[ip] = recon
        return recon

    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query"
    req = urllib.request.Request(url, headers={"User-Agent": "SOC-Radar/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                recon = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "as": data.get("as", "Unknown"),
                    "is_private": False,
                }
                GEOIP_CACHE[ip] = recon
                return recon
    except Exception:
        pass

    recon = {
        "country": "External Threat",
        "city": "Unknown",
        "isp": "Unknown ISP",
        "org": "Unknown Org",
        "is_private": False,
    }
    GEOIP_CACHE[ip] = recon
    return recon


class SecurityEngine:
    """Thread-safe detection, live threat intelligence, and IP blacklisting engine."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failed_history: dict[str, deque[float]] = defaultdict(deque)
        self.targeted_users: dict[str, set[str]] = defaultdict(set)
        self.blocked_ips: dict[str, float] = {}
        self.recent_events: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.firewall_applied_ips: set[str] = set()

    def is_blocked(self, ip: str) -> tuple[bool, int]:
        """Check if an IP is currently blocked; returns (is_blocked, remaining_seconds)."""
        with self.lock:
            now = time.time()
            if ip in self.blocked_ips:
                exp = self.blocked_ips[ip]
                if now < exp:
                    return True, int(exp - now)
                del self.blocked_ips[ip]
        return False, 0

    def unblock_ip(self, ip: str) -> None:
        """Manually unblock an IP."""
        with self.lock:
            self.blocked_ips.pop(ip, None)
            self.failed_history.pop(ip, None)
            self.targeted_users.pop(ip, None)
            self.firewall_applied_ips.discard(ip)

    def apply_real_firewall_block(self, ip: str) -> tuple[bool, str]:
        """Feature 4: 1-Click Active Defense - Executes real Windows Firewall block command."""
        rule_name = f"SOC_AutoBlock_{ip.replace(':', '_')}"
        # Windows netsh command (works seamlessly across Windows versions)
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            with self.lock:
                self.firewall_applied_ips.add(ip)
            return True, f"Firewall Rule Added: Blocked {ip} (Netsh Output: {res.stdout.strip()})"
        except Exception as err:
            return False, f"Firewall execution failed (requires Administrator privilege): {err}"

    def record_attempt(self, ip: str, username: str, success: bool) -> dict[str, Any]:
        """Process an authentication attempt, evaluate security rules & trigger alerts."""
        with self.lock:
            now = time.time()
            timestamp_str = datetime.now(timezone.utc).strftime("%H:%M:%S")

            # Feature 1: Live GeoIP Recon on the incoming IP
            recon = fetch_geoip_recon(ip)

            event = {
                "time": timestamp_str,
                "ip": ip,
                "username": username,
                "success": success,
                "action": "ACCEPTED" if success else "REJECTED",
                "country": recon["country"],
                "isp": recon["isp"],
            }
            self.recent_events.insert(0, event)
            if len(self.recent_events) > 50:
                self.recent_events.pop()

            # Append to persistent log file
            try:
                with LOG_FILE.open("a", encoding="utf-8") as f:
                    status_text = "SUCCESS" if success else "FAILED"
                    f.write(f"[{timestamp_str}] IP={ip} ({recon['country']}) USER={username} STATUS={status_text}\n")
            except OSError:
                pass

            # Feature 2: Account Takeover Alert (Password cracked after brute-force)
            history = self.failed_history[ip]
            recent_fails = [t for t in history if now - t <= SLIDING_WINDOW_SECONDS]
            if success and len(recent_fails) >= 3:
                alert = {
                    "time": timestamp_str,
                    "ip": ip,
                    "user": username,
                    "type": "CRITICAL: ACCOUNT TAKEOVER DETECTED",
                    "details": f"Attacker at {ip} ({recon['country']} - {recon['isp']}) had {len(recent_fails)} failures before a SUCCESSFUL login for '{username}'! Password was likely cracked.",
                    "severity": "CRITICAL",
                    "recon": recon,
                    "firewall_cmd": f'New-NetFirewallRule -DisplayName "Block_{ip}" -RemoteAddress {ip} -Action Block',
                }
                self.alerts.insert(0, alert)
                event["alert"] = alert["type"]
                return event

            if not success:
                history.append(now)
                self.targeted_users[ip].add(username)

                while history and (now - history[0] > SLIDING_WINDOW_SECONDS):
                    history.popleft()

                fail_count = len(history)

                # Check Threshold
                if fail_count >= MAX_FAILED_ATTEMPTS:
                    self.blocked_ips[ip] = now + BLOCK_DURATION_SECONDS
                    attack_type = (
                        "PASSWORD SPRAYING ATTACK"
                        if len(self.targeted_users[ip]) >= 3
                        else "BRUTE-FORCE ATTACK"
                    )

                    alert = {
                        "time": timestamp_str,
                        "ip": ip,
                        "user": ", ".join(list(self.targeted_users[ip])[:4]),
                        "type": f"HIGH: {attack_type} DETECTED",
                        "details": f"{fail_count} failed logins in {SLIDING_WINDOW_SECONDS}s. Origin: {recon['country']} ({recon['isp']}). IP quarantined for {BLOCK_DURATION_SECONDS}s.",
                        "severity": "HIGH",
                        "recon": recon,
                        "firewall_cmd": f'New-NetFirewallRule -DisplayName "Block_{ip}" -RemoteAddress {ip} -Action Block',
                    }
                    self.alerts.insert(0, alert)
                    event["alert"] = alert["type"]

            return event

    def get_dashboard_state(self) -> dict[str, Any]:
        """Return snapshot for the live frontend SOC radar."""
        with self.lock:
            now = time.time()
            active_blocks = {}
            for ip, exp in self.blocked_ips.items():
                if exp > now:
                    recon = fetch_geoip_recon(ip)
                    active_blocks[ip] = {
                        "remaining": int(exp - now),
                        "country": recon["country"],
                        "isp": recon["isp"],
                        "applied": ip in self.firewall_applied_ips,
                    }

            return {
                "max_attempts": MAX_FAILED_ATTEMPTS,
                "window": SLIDING_WINDOW_SECONDS,
                "block_duration": BLOCK_DURATION_SECONDS,
                "events": self.recent_events[:15],
                "alerts": self.alerts[:10],
                "blocked_ips": active_blocks,
                "total_failed": sum(len(h) for h in self.failed_history.values()),
                "total_alerts": len(self.alerts),
            }


SECURITY = SecurityEngine()


class SecurityAppHandler(http.server.BaseHTTPRequestHandler):
    """Handles HTTP requests for Login Portal, SOC Dashboard, and API."""

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.serve_login_page()
        elif path == "/soc":
            self.serve_soc_dashboard()
        elif path == "/api/state":
            self.serve_api_state()
        elif path == "/api/simulate":
            self.handle_simulation()
        elif path == "/api/simulate-takeover":
            self.handle_takeover_simulation()
        elif path == "/api/unblock":
            self.handle_unblock(parsed.query)
        elif path == "/api/firewall-block":
            self.handle_firewall_block(parsed.query)
        else:
            self.send_error(404, "Page Not Found")

    def do_POST(self) -> None:
        if self.path == "/login":
            self.handle_login_submission()
        else:
            self.send_error(404, "Endpoint Not Found")

    def get_client_ip(self) -> str:
        return self.client_address[0]

    def serve_login_page(self, message: str = "", is_error: bool = False) -> None:
        client_ip = self.get_client_ip()
        blocked, remaining = SECURITY.is_blocked(client_ip)

        notice_html = ""
        if blocked:
            notice_html = f"""
            <div class="alert danger">
                <strong>🚫 ACCESS BLOCKED BY SOC DEFENDER</strong><br>
                Too many failed login attempts detected. Your IP (<code>{client_ip}</code>) is quarantined for <strong>{remaining}s</strong>.
            </div>
            """
        elif message:
            cls = "danger" if is_error else "success"
            icon = "❌" if is_error else "✅"
            notice_html = f'<div class="alert {cls}">{icon} {html.escape(message)}</div>'

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Corporate Portal - Secure Login</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{ background: #0f172a; color: #f8fafc; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
    .nav-bar {{ position: absolute; top: 20px; right: 20px; }}
    .soc-link {{ background: #38bdf8; color: #0f172a; text-decoration: none; padding: 10px 18px; border-radius: 8px; font-weight: 700; font-size: 14px; box-shadow: 0 4px 12px rgba(56, 189, 248, 0.3); transition: 0.2s; }}
    .soc-link:hover {{ background: #7dd3fc; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 35px 30px; width: 100%; max-width: 440px; box-shadow: 0 10px 25px rgba(0,0,0,0.4); }}
    .card h1 {{ font-size: 22px; text-align: center; margin-bottom: 6px; color: #f8fafc; }}
    .card p.sub {{ font-size: 13px; color: #94a3b8; text-align: center; margin-bottom: 25px; }}
    .alert {{ padding: 14px; border-radius: 8px; font-size: 13px; margin-bottom: 20px; line-height: 1.5; }}
    .alert.danger {{ background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }}
    .alert.success {{ background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #86efac; }}
    .form-group {{ margin-bottom: 18px; }}
    label {{ display: block; font-size: 12px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
    input[type="text"], input[type="password"] {{ width: 100%; background: #0f172a; border: 1px solid #475569; border-radius: 8px; padding: 12px 14px; font-size: 14px; color: #f8fafc; outline: none; transition: 0.2s; }}
    input:focus {{ border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2); }}
    input:disabled {{ opacity: 0.5; cursor: not-allowed; }}
    button.btn-primary {{ width: 100%; background: #2563eb; color: #fff; border: none; border-radius: 8px; padding: 12px; font-size: 15px; font-weight: 700; cursor: pointer; transition: 0.2s; margin-top: 5px; }}
    button.btn-primary:hover:not(:disabled) {{ background: #1d4ed8; }}
    button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
    .simulator-box {{ margin-top: 25px; padding-top: 20px; border-top: 1px solid #334155; text-align: center; }}
    .btn-sim {{ background: #dc2626; color: #fff; border: none; border-radius: 6px; padding: 8px 12px; font-size: 12px; font-weight: 700; cursor: pointer; transition: 0.2s; margin: 4px; }}
    .btn-sim.purple {{ background: #9333ea; }}
    .btn-sim:hover {{ opacity: 0.9; }}
    .hint {{ font-size: 11px; color: #64748b; margin-top: 12px; line-height: 1.4; }}
    code {{ color: #38bdf8; }}
</style>
</head>
<body>
<div class="nav-bar">
    <a href="/soc" target="_blank" class="soc-link">🛡️ Open SOC Live Radar ↗</a>
</div>

<div class="card">
    <h1>🔐 CyberCorp Employee Portal</h1>
    <p class="sub">Protected by Automated SOC Threat Prevention</p>

    {notice_html}

    <form method="POST" action="/login">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" placeholder="e.g. admin or rahul" required {'disabled' if blocked else ''}>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" placeholder="Enter password" required {'disabled' if blocked else ''}>
        </div>
        <button type="submit" class="btn-primary" {'disabled' if blocked else ''}>
            {'Account Blocked' if blocked else 'Sign In'}
        </button>
    </form>

    <div class="simulator-box">
        <div style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 8px;">
            ⚡ Quick Interview Attack Simulators
        </div>
        <button class="btn-sim" onclick="runSimulator()">🔴 Sim: 5 Fast Brute-Force Fails</button>
        <button class="btn-sim purple" onclick="runTakeoverSim()">🟣 Sim: Account Takeover</button>
        <p class="hint">
            Valid: <code>admin</code> / <code>SecurePass2026!</code><br>
            Policy: 5 failed attempts in 60s locks out IP for 45 seconds.
        </p>
    </div>
</div>

<script>
function runSimulator() {{
    fetch('/api/simulate')
        .then(res => res.json())
        .then(data => {{
            alert(data.message);
            window.location.reload();
        }});
}}
function runTakeoverSim() {{
    fetch('/api/simulate-takeover')
        .then(res => res.json())
        .then(data => {{
            alert(data.message);
            window.location.reload();
        }});
}}
</script>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def handle_login_submission(self) -> None:
        client_ip = self.get_client_ip()
        blocked, remaining = SECURITY.is_blocked(client_ip)
        if blocked:
            self.serve_login_page(f"Access Denied! IP is quarantined for {remaining} seconds.", is_error=True)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        params = urllib.parse.parse_qs(post_data)

        username = params.get("username", [""])[0].strip()
        password = params.get("password", [""])[0].strip()

        is_valid = (username in DEMO_USERS) and (DEMO_USERS[username] == password)
        event = SECURITY.record_attempt(client_ip, username, success=is_valid)

        if is_valid:
            self.serve_login_page(f"Authentication Successful! Welcome, {username}.", is_error=False)
        else:
            if "alert" in event:
                self.serve_login_page(f"Invalid Password! {event['alert']}", is_error=True)
            else:
                self.serve_login_page("Invalid Username or Password. Attempt logged.", is_error=True)

    def serve_soc_dashboard(self) -> None:
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Defender - Live Authentication Attack Radar</title>
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #0b1120; color: #e2e8f0; padding: 25px; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; border-bottom: 1px solid #1e293b; padding-bottom: 15px; }
    .title h1 { font-size: 24px; color: #38bdf8; display: flex; align-items: center; gap: 10px; }
    .live-badge { background: #22c55e; color: #0f172a; font-size: 11px; font-weight: 800; padding: 4px 8px; border-radius: 20px; animation: pulse 2s infinite; }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 25px; }
    .stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; }
    .stat-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-val { font-size: 28px; font-weight: 800; color: #f8fafc; margin-top: 6px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 25px; }
    .card h2 { font-size: 16px; color: #38bdf8; margin-bottom: 15px; text-transform: uppercase; letter-spacing: 0.5px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 10px; border-bottom: 1px solid #334155; color: #94a3b8; font-weight: 600; }
    td { padding: 10px; border-bottom: 1px solid #1e293b; vertical-align: middle; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
    .badge.reject { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .badge.accept { background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid #22c55e; }
    .alert-box { background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 6px; margin-bottom: 12px; font-size: 13px; }
    .alert-critical { background: rgba(147, 51, 234, 0.2); border-left: 4px solid #a855f7; }
    .btn-unblock { background: #475569; color: #fff; border: none; border-radius: 4px; padding: 5px 10px; font-size: 11px; cursor: pointer; font-weight: 600; }
    .btn-unblock:hover { background: #64748b; }
    .btn-firewall { background: #dc2626; color: #fff; border: none; border-radius: 4px; padding: 5px 10px; font-size: 11px; cursor: pointer; font-weight: 700; margin-right: 6px; }
    .btn-firewall:hover { background: #b91c1c; }
    .btn-firewall.active { background: #16a34a; cursor: default; }
    code { background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="title">
            <h1>🛡️ SOC Defender <span class="live-badge">● LIVE RADAR</span></h1>
        </div>
        <div>
            <a href="/" target="_blank" style="color: #38bdf8; text-decoration: none; font-size: 13px; font-weight: 600;">Open Employee Login Page ↗</a>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total Failed Logins</div>
            <div class="stat-val" id="stat-failed">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Security Incidents / Alarms</div>
            <div class="stat-val" style="color: #f87171;" id="stat-alerts">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Currently Blacklisted IPs</div>
            <div class="stat-val" style="color: #fb923c;" id="stat-blocked">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Lockout Policy</div>
            <div class="stat-val" style="font-size: 20px; color: #a5f3fc;" id="stat-policy">5 fails / 60s</div>
        </div>
    </div>

    <!-- Active Blacklist Section with Feature 4: Active Defense -->
    <div class="card" id="card-blacklist" style="display: none; border-color: #ef4444;">
        <h2 style="color: #ef4444;">🚫 Quarantined & Blocked Attacker IPs (Active Defense)</h2>
        <table id="tbl-blocked">
            <thead>
                <tr>
                    <th>Attacker IP</th>
                    <th>Jasoosi / Origin (GeoIP)</th>
                    <th>Quarantine Timer</th>
                    <th>Active Defense (Firewall Action)</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>

    <!-- Security Incidents with Feature 2: Account Takeover Highlight -->
    <div class="card">
        <h2>🚨 Security Incident Alerts & Threat Intelligence</h2>
        <div id="alerts-container">
            <p style="color: #64748b; font-size: 13px;">No security attacks detected yet. System running smoothly.</p>
        </div>
    </div>

    <!-- Live Event Feed with Feature 1: Live GeoIP Recon -->
    <div class="card">
        <h2>📡 Live Authentication Event Stream (With Threat Recon)</h2>
        <table>
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Source IP</th>
                    <th>Origin / ISP (Jasoosi)</th>
                    <th>Target Account</th>
                    <th>Status</th>
                    <th>Security Flag</th>
                </tr>
            </thead>
            <tbody id="tbl-events">
                <tr><td colspan="6" style="color: #64748b;">Waiting for incoming login attempts...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
function refreshDashboard() {
    fetch('/api/state')
        .then(res => res.json())
        .then(data => {
            document.getElementById('stat-failed').textContent = data.total_failed;
            document.getElementById('stat-alerts').textContent = data.total_alerts;
            document.getElementById('stat-policy').textContent = `${data.max_attempts} fails / ${data.window}s`;

            // Blocked IPs
            const blockedKeys = Object.keys(data.blocked_ips);
            document.getElementById('stat-blocked').textContent = blockedKeys.length;
            const blkCard = document.getElementById('card-blacklist');
            const blkTbody = document.querySelector('#tbl-blocked tbody');

            if (blockedKeys.length > 0) {
                blkCard.style.display = 'block';
                blkTbody.innerHTML = blockedKeys.map(ip => {
                    const info = data.blocked_ips[ip];
                    const fwBtn = info.applied 
                        ? `<button class="btn-firewall active">✅ Windows Firewall Active</button>`
                        : `<button class="btn-firewall" onclick="blockFirewall('${ip}')">⚡ Apply Windows Firewall Rule</button>`;
                    return `
                    <tr>
                        <td><code>${ip}</code></td>
                        <td><strong>${info.country}</strong><br><small style="color: #94a3b8;">${info.isp}</small></td>
                        <td style="color: #fb923c; font-weight: 700;">${info.remaining}s remaining</td>
                        <td>
                            ${fwBtn}
                            <button class="btn-unblock" onclick="unblock('${ip}')">Unblock</button>
                        </td>
                    </tr>
                    `;
                }).join('');
            } else {
                blkCard.style.display = 'none';
            }

            // Alerts
            const alertsDiv = document.getElementById('alerts-container');
            if (data.alerts.length > 0) {
                alertsDiv.innerHTML = data.alerts.map(a => `
                    <div class="alert-box ${a.severity === 'CRITICAL' ? 'alert-critical' : ''}">
                        <strong>[${a.time}] ${a.type}</strong><br>
                        ${a.details}
                    </div>
                `).join('');
            }

            // Events
            const evTbody = document.getElementById('tbl-events');
            if (data.events.length > 0) {
                evTbody.innerHTML = data.events.map(e => `
                    <tr>
                        <td>${e.time}</td>
                        <td><code>${e.ip}</code></td>
                        <td><small>${e.country || 'Local'}</small></td>
                        <td><strong>${e.username}</strong></td>
                        <td><span class="badge ${e.success ? 'accept' : 'reject'}">${e.action}</span></td>
                        <td style="color: #f87171; font-weight: 600;">${e.alert || '-'}</td>
                    </tr>
                `).join('');
            }
        });
}

function unblock(ip) {
    fetch(`/api/unblock?ip=${encodeURIComponent(ip)}`)
        .then(() => refreshDashboard());
}

function blockFirewall(ip) {
    fetch(`/api/firewall-block?ip=${encodeURIComponent(ip)}`)
        .then(res => res.json())
        .then(data => {
            alert(data.message);
            refreshDashboard();
        });
}

setInterval(refreshDashboard, 1500);
refreshDashboard();
</script>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def serve_api_state(self) -> None:
        state = SECURITY.get_dashboard_state()
        data = json.dumps(state).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def handle_unblock(self, query: str) -> None:
        params = urllib.parse.parse_qs(query)
        ip = params.get("ip", [""])[0]
        if ip:
            SECURITY.unblock_ip(ip)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def handle_firewall_block(self, query: str) -> None:
        params = urllib.parse.parse_qs(query)
        ip = params.get("ip", [""])[0]
        success, msg = SECURITY.apply_real_firewall_block(ip)
        res = json.dumps({"status": "ok" if success else "error", "message": msg}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(res)

    def handle_simulation(self) -> None:
        """Feature 3: Simulate 5 rapid attacks from a Tor Exit Node IP."""
        sim_ip = "185.220.101.5"  # Russian / European Tor Exit Node
        targets = ["admin", "admin", "admin", "admin", "admin"]
        for u in targets:
            SECURITY.record_attempt(sim_ip, u, success=False)
            time.sleep(0.02)

        data = json.dumps(
            {
                "status": "ok",
                "message": f"Simulated 5 rapid brute-force attacks from Tor Exit Node {sim_ip}! Check SOC Dashboard for live GeoIP recon.",
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def handle_takeover_simulation(self) -> None:
        """Feature 2: Simulate Account Takeover (4 fails + 1 CRACKED login)."""
        sim_ip = "45.33.32.156"
        for _ in range(4):
            SECURITY.record_attempt(sim_ip, "admin", success=False)
            time.sleep(0.02)
        # 5th attempt: PASSWORD CRACKED!
        SECURITY.record_attempt(sim_ip, "admin", success=True)

        data = json.dumps(
            {
                "status": "ok",
                "message": f"Simulated Account Takeover on user 'admin' from {sim_ip}! 4 fails followed by SUCCESSFUL crack. Check purple CRITICAL alarm on SOC Radar.",
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


def start_server(port: int = 8080) -> None:
    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server_address = ("", port)
    httpd = ThreadedServer(server_address, SecurityAppHandler)

    print("\n" + "=" * 65)
    print("🛡️  FAILED LOGIN DETECTOR & SOC DEFENDER LIVE DEMO")
    print("=" * 65)
    print(f"  • Employee Login Portal : http://localhost:{port}")
    print(f"  • SOC Live Radar        : http://localhost:{port}/soc")
    print("  • Detection Threshold   : 5 failed attempts / 60s")
    print("  • Auto-Block Quarantine : 45 seconds")
    print("=" * 65)
    print("Press Ctrl+C to stop the server.\n")

    webbrowser.open(f"http://localhost:{port}")
    time.sleep(0.5)
    webbrowser.open(f"http://localhost:{port}/soc")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server. Goodbye!")
        httpd.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Failed Login Detector & SOC Web Portal Demo.")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Web server port (default: 8080)")
    args = parser.parse_args()
    start_server(args.port)


if __name__ == "__main__":
    main()
