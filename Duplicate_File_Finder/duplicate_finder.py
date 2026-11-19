"""Forensic Duplicate File Finder & Malware Disguise Detector.

(Level 1 - Security Fundamentals & Digital Forensics Investigation).

Combined 3-in-1 Architecture:
1. Category & Storage Breakdown Cards (Documents, Images, Videos, Suspicious Executables)
2. Clean ASCII Forensic Grid Table (Zero terminal clutter, compact overview)
3. Interactive Command Console (Expand specific ID paths on-demand, 1-click quarantine, HTML report)
4. Anti-Forensic Disguise Detection (Same SHA-256 hash, completely different names)
5. Zero external dependencies (pure Python standard library).
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import html
import json
import os
import shutil
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

CHUNK_SIZE = 65536         # 64 KB streaming chunks
PARTIAL_HASH_SIZE = 4096   # 4 KB initial check for large files

DEFAULT_IGNORED_DIRS = {
    ".venv", "venv", "node_modules", "__pycache__", ".git", ".idea", ".vscode", "site-packages",
}

# Extension categories
EXT_CATEGORIES = {
    "📄 Documents": {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".txt", ".csv"},
    "🖼️ Images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico"},
    "🎬 Videos & Audio": {".mp4", ".mkv", ".avi", ".mov", ".mp3", ".wav", ".flac"},
    "📦 Archives & ISOs": {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"},
    "🚨 Suspicious / Executables": {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".scr", ".jar", ".py"},
}

STAGING_DIRECTORIES = {"temp", "tmp", "public", "downloads", "appdata"}


def format_bytes(size: int) -> str:
    """Format bytes into clean human-readable units."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def get_partial_hash(file_path: Path) -> str:
    """Read first 4KB to quickly eliminate non-matching large files."""
    hasher = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            chunk = f.read(PARTIAL_HASH_SIZE)
            hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return ""


def get_full_hash(file_path: Path) -> str:
    """Compute full cryptographic SHA-256 hash using 64KB streaming blocks."""
    hasher = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return ""


def is_ignored_path(path: Path) -> bool:
    """Check if any directory segment matches the ignore list."""
    parts = set(path.parts)
    return bool(parts & DEFAULT_IGNORED_DIRS)


def categorize_extension(ext: str) -> str:
    """Map a file extension to a readable forensic category."""
    ext_lower = ext.lower()
    for cat_name, ext_set in EXT_CATEGORIES.items():
        if ext_lower in ext_set:
            return cat_name
    return "📁 Other Files"


def scan_for_duplicates(target_dir: Path, include_system: bool = False) -> dict[str, Any]:
    """Execute 3-stage forensic duplicate detection pipeline across target directory."""
    start_time = time.time()
    resolved_dir = target_dir.resolve()

    if not resolved_dir.is_dir():
        raise NotADirectoryError(f"Directory not found: {resolved_dir}")

    total_files_scanned = 0
    total_bytes_scanned = 0
    size_map: dict[int, list[Path]] = collections.defaultdict(list)

    for root, dirs, files in os.walk(resolved_dir):
        if not include_system:
            dirs[:] = [d for d in dirs if d.lower() not in DEFAULT_IGNORED_DIRS]

        for fname in files:
            fpath = Path(root) / fname
            try:
                if fpath.is_file():
                    if not include_system and is_ignored_path(fpath):
                        continue
                    sz = fpath.stat().st_size
                    total_files_scanned += 1
                    total_bytes_scanned += sz
                    if sz > 0:
                        size_map[sz].append(fpath)
            except OSError:
                continue

    candidate_sizes = {sz: paths for sz, paths in size_map.items() if len(paths) > 1}

    # Partial Hash Check (4 KB)
    partial_map: dict[tuple[int, str], list[Path]] = collections.defaultdict(list)
    for sz, paths in candidate_sizes.items():
        for p in paths:
            phash = get_partial_hash(p)
            if phash:
                partial_map[(sz, phash)].append(p)

    candidate_partials = {k: paths for k, paths in partial_map.items() if len(paths) > 1}

    # Full SHA-256 Hash Matching
    full_hash_map: dict[str, list[Path]] = collections.defaultdict(list)
    for _, paths in candidate_partials.items():
        for p in paths:
            fhash = get_full_hash(p)
            if fhash:
                full_hash_map[fhash].append(p)

    duplicate_groups: list[dict[str, Any]] = []
    total_wasted_bytes = 0
    disguised_file_count = 0

    category_stats: dict[str, dict[str, int]] = collections.defaultdict(lambda: {"count": 0, "wasted": 0})

    for fhash, paths in full_hash_map.items():
        if len(paths) > 1:
            file_size = paths[0].stat().st_size
            wasted_bytes = (len(paths) - 1) * file_size
            total_wasted_bytes += wasted_bytes

            distinct_names = {p.name for p in paths}
            distinct_exts = {p.suffix.lower() for p in paths}
            is_disguised = len(distinct_names) > 1 or len(distinct_exts) > 1

            if is_disguised:
                disguised_file_count += len(paths)

            # Categorize
            cat = categorize_extension(paths[0].suffix)
            category_stats[cat]["count"] += len(paths) - 1
            category_stats[cat]["wasted"] += wasted_bytes

            has_suspicious_loc = any(
                any(staging in p.as_posix().lower() for staging in STAGING_DIRECTORIES)
                and p.suffix.lower() in EXT_CATEGORIES["🚨 Suspicious / Executables"]
                for p in paths
            )

            duplicate_groups.append(
                {
                    "sha256": fhash,
                    "primary_name": paths[0].name,
                    "file_size": file_size,
                    "file_size_formatted": format_bytes(file_size),
                    "duplicate_count": len(paths),
                    "wasted_bytes": wasted_bytes,
                    "wasted_formatted": format_bytes(wasted_bytes),
                    "is_disguised": is_disguised,
                    "suspicious_location": has_suspicious_loc,
                    "distinct_names": list(distinct_names),
                    "paths": [str(p) for p in paths],
                }
            )

    # Sort groups by threat severity first, then wasted space
    duplicate_groups.sort(key=lambda x: (x["suspicious_location"], x["is_disguised"], x["wasted_bytes"]), reverse=True)

    duration = time.time() - start_time

    return {
        "target_directory": str(resolved_dir),
        "total_files_scanned": total_files_scanned,
        "total_bytes_scanned": total_bytes_scanned,
        "total_bytes_formatted": format_bytes(total_bytes_scanned),
        "duplicate_sets_found": len(duplicate_groups),
        "disguised_files_found": disguised_file_count,
        "total_wasted_bytes": total_wasted_bytes,
        "total_wasted_formatted": format_bytes(total_wasted_bytes),
        "scan_duration_seconds": round(duration, 2),
        "category_stats": {k: {"count": v["count"], "wasted": format_bytes(v["wasted"])} for k, v in category_stats.items()},
        "duplicate_groups": duplicate_groups,
    }


def display_combined_dashboard(data: dict[str, Any]) -> None:
    """Renders the combined 3-in-1 terminal view (Categories + Grid Table)."""
    print("\n" + "╔" + "═" * 78 + "╗")
    print("║   🔍 FORENSIC DUPLICATE FILE AUDITOR & MALWARE DISGUISE RADAR               ║")
    print("╚" + "═" * 78 + "╝")
    print(f" Target: {data['target_directory']}")
    print(f" Scanned: {data['total_files_scanned']:,} files ({data['total_bytes_formatted']}) | Wasted: {data['total_wasted_formatted']} | Time: {data['scan_duration_seconds']}s")
    print("─" * 80)

    # Section 1: Category & Storage Breakdown Cards
    print("\n ── [1] CATEGORY & STORAGE BREAKDOWN ──────────────────────────────────────────")
    if data["category_stats"]:
        for cat_name, stats in data["category_stats"].items():
            print(f"   {cat_name:<28} : {stats['count']:>3} Duplicate Copies  ({stats['wasted']} Wasted)")
    else:
        print("   No duplicate files found in any category.")

    # Section 2: Clean Forensic Grid Table
    print("\n ── [2] FORENSIC DUPLICATE GRID TABLE ─────────────────────────────────────────")
    if not data["duplicate_groups"]:
        print("   ✅ Clean! No duplicate files or disguised copies detected.")
        print("═" * 80 + "\n")
        return

    print(f"  {'ID':<4} {'PRIMARY FILE NAME':<26} {'SIZE':<10} {'COPIES':<8} {'WASTED':<10} {'SECURITY STATUS'}")
    print("  " + "─" * 76)

    for idx, grp in enumerate(data["duplicate_groups"][:15], start=1):
        status = "📄 EXACT DUPLICATE"
        if grp["suspicious_location"]:
            status = "🚨 SUSPICIOUS STAGING"
        elif grp["is_disguised"]:
            status = "⚠️ DISGUISED NAMES"

        fname = grp["primary_name"][:24]
        print(f"  {idx:<4} {fname:<26} {grp['file_size_formatted']:<10} {grp['duplicate_count']:<8} {grp['wasted_formatted']:<10} {status}")

    if len(data["duplicate_groups"]) > 15:
        print(f"  ... and {len(data['duplicate_groups']) - 15} more sets (accessible via ID).")

    print("  " + "═" * 76)


def interactive_console(data: dict[str, Any]) -> None:
    """Section 3: Interactive command console for analyst actions."""
    if not data["duplicate_groups"]:
        return

    print("\n ── [3] INTERACTIVE ACTION CONSOLE ────────────────────────────────────────────")
    print("  • Type an ID number (e.g. '1') to inspect full file paths & SHA-256 hash")
    print("  • Type 'q <ID>' (e.g. 'q 1') to quarantine/isolate duplicates of that set")
    print("  • Type 'q all' to quarantine all duplicate copies safely")
    print("  • Type 'html' to open visual browser dashboard")
    print("  • Type 'exit' to quit")
    print("─" * 80)

    groups = data["duplicate_groups"]

    while True:
        try:
            cmd = input("\n[Forensics-Console] Enter action > ").strip().lower()
            if not cmd:
                continue
            if cmd in ("exit", "quit", "q"):
                print("Exiting console. Stay safe!")
                break

            if cmd == "html":
                html_file = Path("duplicate_audit_report.html").resolve()
                generate_html_report(data, html_file)
                print(f"[+] Opening HTML Dashboard: {html_file}")
                webbrowser.open(html_file.as_uri())

            elif cmd.isdigit():
                idx = int(cmd)
                if 1 <= idx <= len(groups):
                    grp = groups[idx - 1]
                    print(f"\n[SET #{idx} DETAILS]")
                    print(f"  • SHA-256 Hash : {grp['sha256']}")
                    print(f"  • File Size    : {grp['file_size_formatted']} (Wasted: {grp['wasted_formatted']})")
                    print(f"  • Is Disguised : {'YES ⚠️ (Different names)' if grp['is_disguised'] else 'No (Same names)'}")
                    print("  • File Locations on Disk:")
                    for p in grp["paths"]:
                        print(f"    └── {p}")
                else:
                    print(f"Invalid ID. Range is 1 to {len(groups)}.")

            elif cmd.startswith("q "):
                arg = cmd.split(" ", 1)[1].strip()
                q_dir = Path("forensic_quarantine")
                if arg == "all":
                    count = quarantine_all(data, q_dir)
                    print(f"[+] Quarantined {count} duplicate copies to '{q_dir.resolve()}'.")
                elif arg.isdigit():
                    idx = int(arg)
                    if 1 <= idx <= len(groups):
                        grp = groups[idx - 1]
                        count = quarantine_single_group(grp, q_dir)
                        print(f"[+] Quarantined {count} files from Set #{idx} to '{q_dir.resolve()}'.")
                    else:
                        print(f"Invalid ID: {arg}")
                else:
                    print("Usage: 'q <ID>' or 'q all'")

            else:
                print("Unknown command. Type an ID number (e.g. '1'), 'q 1', 'html', or 'exit'.")

        except KeyboardInterrupt:
            print("\n[!] Console closed.")
            break


def quarantine_single_group(grp: dict[str, Any], quarantine_dir: Path) -> int:
    """Quarantine duplicates of a single set, keeping the original first file safe."""
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    paths = [Path(p) for p in grp["paths"]]
    moved = 0
    for p in paths[1:]:
        try:
            dest = quarantine_dir / f"quarantine_{p.name}_{grp['sha256'][:8]}"
            shutil.move(str(p), str(dest))
            moved += 1
            print(f"  [MOVED] {p.name} -> forensic_quarantine/")
        except OSError as exc:
            print(f"  [ERROR] Could not move {p}: {exc}")
    return moved


def quarantine_all(data: dict[str, Any], quarantine_dir: Path) -> int:
    """Quarantine all duplicate copies across all sets."""
    total = 0
    for grp in data["duplicate_groups"]:
        total += quarantine_single_group(grp, quarantine_dir)
    return total


def generate_html_report(data: dict[str, Any], output_path: Path) -> Path:
    """Generate an interactive HTML dashboard report."""
    rows_html = []
    for idx, grp in enumerate(data["duplicate_groups"], start=1):
        badge = (
            '<span class="badge danger">⚠️ Disguised File</span>'
            if grp["is_disguised"]
            else '<span class="badge normal">Duplicate</span>'
        )
        paths_list = "".join(f"<li><code>{html.escape(p)}</code></li>" for p in grp["paths"])

        rows_html.append(
            f"""
            <tr>
                <td><strong>Set #{idx}</strong><br>{badge}</td>
                <td><code>{grp['sha256'][:16]}...</code></td>
                <td>{grp['file_size_formatted']}</td>
                <td style="color: #f59e0b; font-weight: 700;">{grp['wasted_formatted']}</td>
                <td><ul class="file-list">{paths_list}</ul></td>
            </tr>
            """
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Duplicate File & Forensics Audit</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{ background: #0f172a; color: #e2e8f0; padding: 30px 20px; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .header {{ background: #1e293b; padding: 25px; border-radius: 12px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
    .stat-card {{ background: #1e293b; padding: 18px; border-radius: 10px; border: 1px solid #334155; }}
    .stat-val {{ font-size: 24px; font-weight: 800; color: #38bdf8; margin-top: 5px; }}
    .card {{ background: #1e293b; padding: 25px; border-radius: 12px; border: 1px solid #334155; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ text-align: left; padding: 12px; color: #94a3b8; border-bottom: 1px solid #334155; }}
    td {{ padding: 14px 12px; border-bottom: 1px solid #334155; vertical-align: top; }}
    code {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; color: #38bdf8; font-size: 12px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
    .badge.danger {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
    .badge.normal {{ background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid #38bdf8; }}
    .file-list {{ margin-left: 15px; line-height: 1.6; word-break: break-all; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>🔍 Forensic Duplicate File Audit</h1>
            <p style="color: #94a3b8; margin-top: 4px;">Target: <strong>{html.escape(data['target_directory'])}</strong></p>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 20px; font-weight: 800; color: #f59e0b;">{data['total_wasted_formatted']} Wasted</div>
            <small style="color: #94a3b8;">Scanned in {data['scan_duration_seconds']}s</small>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Total Files Scanned</div>
            <div class="stat-val">{data['total_files_scanned']:,}</div>
        </div>
        <div class="stat-card">
            <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Duplicate Sets Found</div>
            <div class="stat-val">{data['duplicate_sets_found']}</div>
        </div>
        <div class="stat-card">
            <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Disguised File Threats</div>
            <div class="stat-val" style="color: #ef4444;">{data['disguised_files_found']}</div>
        </div>
        <div class="stat-card">
            <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Space Recoverable</div>
            <div class="stat-val" style="color: #f59e0b;">{data['total_wasted_formatted']}</div>
        </div>
    </div>

    <div class="card">
        <h2 style="margin-bottom: 15px; font-size: 16px; color: #38bdf8;">Forensic Duplicate Evidence Registry</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Set & Threat</th>
                    <th style="width: 20%;">SHA-256 Hash</th>
                    <th style="width: 10%;">File Size</th>
                    <th style="width: 10%;">Wasted</th>
                    <th style="width: 45%;">Identical File Paths</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>
    </div>
</div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Forensic Duplicate File Finder & Malware Disguise Detector (3-in-1 View)."
    )
    parser.add_argument("path", nargs="?", default=None, help="Directory to scan")
    parser.add_argument("--include-system", action="store_true", help="Include .venv, node_modules, etc.")
    parser.add_argument("--json", action="store_true", help="Output audit report as raw JSON")
    args = parser.parse_args(argv)

    target_path = args.path
    if target_path is None:
        print("\n" + "╔" + "═" * 78 + "╗")
        print("║   🔍 FORENSIC DUPLICATE FILE AUDITOR & MALWARE DISGUISE RADAR               ║")
        print("╚" + "═" * 78 + "╝")
        user_input = input("\n[?] Enter directory path to scan [press Enter for current directory '.']: ").strip()
        target_path = user_input if user_input else "."

    try:
        report = scan_for_duplicates(Path(target_path), include_system=args.include_system)

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            display_combined_dashboard(report)
            interactive_console(report)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
