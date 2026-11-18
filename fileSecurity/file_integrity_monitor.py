"""File Integrity Monitor (FIM) for detecting unauthorized file tampering.

Supports creating a cryptographic hash baseline (SHA-256 / SHA-512),
performing one-time integrity checks, and continuous real-time monitoring.

Run with:
    py file_integrity_monitor.py                 # Interactive menu
    py file_integrity_monitor.py init <path>     # Create baseline
    py file_integrity_monitor.py check <path>    # Verify against baseline
    py file_integrity_monitor.py monitor <path>  # Continuous monitoring
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_BASELINE_FILE = "fim_baseline.json"
DEFAULT_LOG_FILE = "fim_alerts.log"
DEFAULT_EXCLUDES = ("*.log", "fim_baseline.json", "__pycache__", ".git", ".venv", "venv")
SUPPORTED_ALGORITHMS = ("sha256", "sha512")
CHUNK_SIZE = 65536


def setup_logger(log_file: Path | None = None) -> logging.Logger:
    """Configure logger for console and optional alert log file."""
    logger = logging.getLogger("fim")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute the cryptographic hex digest of a file in chunks."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    hasher = hashlib.new(algorithm)
    with file_path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def is_excluded(path: Path, root: Path, exclude_patterns: tuple[str, ...]) -> bool:
    """Return True if any path component or relative path matches an exclude pattern."""
    try:
        rel_path = path.relative_to(root)
    except ValueError:
        rel_path = path

    parts = rel_path.parts
    rel_str = rel_path.as_posix()
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(rel_str, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


def collect_files(target: Path, exclude_patterns: tuple[str, ...]) -> list[Path]:
    """Collect all regular files under target (or target itself if it is a file)."""
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    if target.is_file():
        return [target.resolve()]

    files: list[Path] = []
    root = target.resolve()
    for item in sorted(root.rglob("*")):
        if item.is_file() and not is_excluded(item, root, exclude_patterns):
            files.append(item)
    return files


def scan_target(
    target: Path,
    algorithm: str = "sha256",
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDES,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Scan target and return (file_records, read_errors)."""
    root = target.resolve()
    records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    for file_path in collect_files(root, exclude_patterns):
        key = file_path.name if root.is_file() else file_path.relative_to(root).as_posix()
        try:
            stat = file_path.stat()
            records[key] = {
                "hash": compute_file_hash(file_path, algorithm),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            }
        except OSError as exc:
            errors.append(f"{key}: {exc}")

    return records, errors


def create_baseline(
    target: Path,
    baseline_path: Path,
    algorithm: str = "sha256",
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDES,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Create and save a baseline JSON snapshot of the target path."""
    log = logger or setup_logger()
    extra_excludes = exclude_patterns + (baseline_path.name,)
    records, errors = scan_target(target, algorithm=algorithm, exclude_patterns=extra_excludes)

    baseline = {
        "metadata": {
            "target": str(target.resolve()),
            "algorithm": algorithm,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "file_count": len(records),
        },
        "files": records,
    }

    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    log.info("Baseline created: %s (%d files indexed, %s)", baseline_path, len(records), algorithm.upper())
    for err in errors:
        log.warning("Could not read file during baseline scan: %s", err)

    return baseline


def load_baseline(baseline_path: Path) -> dict[str, Any]:
    """Load and validate an existing baseline JSON file."""
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    if "metadata" not in data or "files" not in data:
        raise ValueError(f"Invalid baseline format in {baseline_path}")
    return data


def compare_against_baseline(
    baseline: dict[str, Any],
    target: Path | None = None,
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDES,
) -> dict[str, list[Any]]:
    """Compare current filesystem state against a loaded baseline."""
    meta = baseline["metadata"]
    scan_root = (target or Path(meta["target"])).resolve()
    algorithm = meta.get("algorithm", "sha256")
    expected_files: dict[str, dict[str, Any]] = baseline["files"]

    current_files, read_errors = scan_target(
        scan_root,
        algorithm=algorithm,
        exclude_patterns=exclude_patterns,
    )

    expected_keys = set(expected_files.keys())
    current_keys = set(current_files.keys())

    added = sorted(current_keys - expected_keys)
    deleted = sorted(expected_keys - current_keys)
    modified: list[dict[str, Any]] = []

    for key in sorted(expected_keys & current_keys):
        old_info = expected_files[key]
        new_info = current_files[key]
        if old_info["hash"] != new_info["hash"]:
            modified.append(
                {
                    "path": key,
                    "old_hash": old_info["hash"],
                    "new_hash": new_info["hash"],
                    "old_size": old_info["size"],
                    "new_size": new_info["size"],
                }
            )

    return {
        "modified": modified,
        "added": added,
        "deleted": deleted,
        "errors": read_errors,
    }


def report_findings(findings: dict[str, list[Any]], logger: logging.Logger) -> bool:
    """Log integrity findings. Return True if any tampering or error was detected."""
    modified = findings["modified"]
    added = findings["added"]
    deleted = findings["deleted"]
    errors = findings["errors"]

    tampered = bool(modified or added or deleted or errors)
    if not tampered:
        logger.info("Integrity check PASSED: no tampering detected.")
        return False

    for item in modified:
        logger.warning(
            "[TAMPERED / MODIFIED] %s | size: %d -> %d | hash: %s... -> %s...",
            item["path"],
            item["old_size"],
            item["new_size"],
            item["old_hash"][:12],
            item["new_hash"][:12],
        )
    for path in added:
        logger.warning("[ADDED / UNAUTHORIZED] %s", path)
    for path in deleted:
        logger.warning("[DELETED / MISSING] %s", path)
    for err in errors:
        logger.error("[READ ERROR] %s", err)

    return True


def monitor_target(
    baseline_path: Path,
    target: Path | None = None,
    interval: float = 5.0,
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDES,
    logger: logging.Logger | None = None,
) -> None:
    """Continuously monitor target against baseline until interrupted."""
    log = logger or setup_logger(Path(DEFAULT_LOG_FILE))
    baseline = load_baseline(baseline_path)
    scan_root = (target or Path(baseline["metadata"]["target"])).resolve()
    extra_excludes = exclude_patterns + (baseline_path.name,)

    log.info("Starting File Integrity Monitor on %s (interval: %.1fs). Press Ctrl+C to stop.", scan_root, interval)
    last_snapshot: tuple[Any, ...] | None = None

    try:
        while True:
            findings = compare_against_baseline(
                baseline,
                target=scan_root,
                exclude_patterns=extra_excludes,
            )
            snapshot = (
                tuple((m["path"], m["new_hash"]) for m in findings["modified"]),
                tuple(findings["added"]),
                tuple(findings["deleted"]),
                tuple(findings["errors"]),
            )

            # Alert only when the tampering state changes to avoid log flooding
            if snapshot != last_snapshot:
                has_issues = report_findings(findings, log)
                if not has_issues and last_snapshot is not None:
                    log.info("All monitored files match the baseline again.")
                last_snapshot = snapshot

            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("Monitoring stopped by user.")


def interactive_menu() -> int:
    """Run an interactive CLI menu when no subcommand is provided."""
    print("=== File Integrity Monitor (FIM) ===")
    print("1. Create / Update Baseline")
    print("2. Run One-Time Integrity Check")
    print("3. Start Real-Time Monitoring")
    print("4. Exit")

    choice = input("Enter your choice (1-4): ").strip()
    if choice == "4":
        return 0

    if choice not in {"1", "2", "3"}:
        print("Invalid choice.")
        return 1

    target_input = input("Enter file or directory path to monitor [.]: ").strip() or "."
    baseline_input = input(f"Enter baseline file path [{DEFAULT_BASELINE_FILE}]: ").strip() or DEFAULT_BASELINE_FILE
    target = Path(target_input)
    baseline_path = Path(baseline_input)

    if choice == "1":
        algo = input("Hash algorithm (sha256/sha512) [sha256]: ").strip().lower() or "sha256"
        logger = setup_logger()
        create_baseline(target, baseline_path, algorithm=algo, logger=logger)
        return 0

    if choice == "2":
        logger = setup_logger(Path(DEFAULT_LOG_FILE))
        baseline = load_baseline(baseline_path)
        findings = compare_against_baseline(
            baseline,
            target=target,
            exclude_patterns=DEFAULT_EXCLUDES + (baseline_path.name,),
        )
        tampered = report_findings(findings, logger)
        return 1 if tampered else 0

    interval_raw = input("Polling interval in seconds [5]: ").strip() or "5"
    interval = max(0.5, float(interval_raw))
    logger = setup_logger(Path(DEFAULT_LOG_FILE))
    monitor_target(baseline_path, target=target, interval=interval, logger=logger)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor (FIM) - Detect unauthorized file tampering."
    )
    subparsers = parser.add_subparsers(dest="command")

    init_cmd = subparsers.add_parser("init", help="Create a new integrity baseline.")
    init_cmd.add_argument("target", type=Path, help="File or directory to baseline.")
    init_cmd.add_argument("-b", "--baseline", type=Path, default=Path(DEFAULT_BASELINE_FILE), help="Baseline JSON path.")
    init_cmd.add_argument("-a", "--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256", help="Hash algorithm.")
    init_cmd.add_argument("-e", "--exclude", nargs="*", default=[], help="Additional glob patterns to exclude.")

    check_cmd = subparsers.add_parser("check", help="Check target integrity against a baseline.")
    check_cmd.add_argument("target", nargs="?", type=Path, default=None, help="Optional target path override.")
    check_cmd.add_argument("-b", "--baseline", type=Path, default=Path(DEFAULT_BASELINE_FILE), help="Baseline JSON path.")
    check_cmd.add_argument("-l", "--log", type=Path, default=Path(DEFAULT_LOG_FILE), help="Alert log file path.")
    check_cmd.add_argument("-e", "--exclude", nargs="*", default=[], help="Additional glob patterns to exclude.")

    mon_cmd = subparsers.add_parser("monitor", help="Continuously monitor target for tampering.")
    mon_cmd.add_argument("target", nargs="?", type=Path, default=None, help="Optional target path override.")
    mon_cmd.add_argument("-b", "--baseline", type=Path, default=Path(DEFAULT_BASELINE_FILE), help="Baseline JSON path.")
    mon_cmd.add_argument("-l", "--log", type=Path, default=Path(DEFAULT_LOG_FILE), help="Alert log file path.")
    mon_cmd.add_argument("-i", "--interval", type=float, default=5.0, help="Polling interval in seconds.")
    mon_cmd.add_argument("-e", "--exclude", nargs="*", default=[], help="Additional glob patterns to exclude.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the File Integrity Monitor."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        return interactive_menu()

    excludes = DEFAULT_EXCLUDES + tuple(args.exclude) + (args.baseline.name,)

    try:
        if args.command == "init":
            logger = setup_logger()
            create_baseline(
                args.target,
                args.baseline,
                algorithm=args.algorithm,
                exclude_patterns=excludes,
                logger=logger,
            )
            return 0

        if args.command == "check":
            logger = setup_logger(args.log)
            excludes = excludes + (args.log.name,)
            baseline = load_baseline(args.baseline)
            findings = compare_against_baseline(baseline, target=args.target, exclude_patterns=excludes)
            return 1 if report_findings(findings, logger) else 0

        if args.command == "monitor":
            logger = setup_logger(args.log)
            excludes = excludes + (args.log.name,)
            monitor_target(
                args.baseline,
                target=args.target,
                interval=max(0.5, args.interval),
                exclude_patterns=excludes,
                logger=logger,
            )
            return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

