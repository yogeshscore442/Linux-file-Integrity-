"""
Security scan report generation module.
Generates human-readable Markdown reports, terminal ASCII summaries,
and machine-readable JSON exports formatted for SOC triage.
"""

from __future__ import annotations

import datetime
import json
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class ReportGenerator:
    """
    Renders structured comparison results into polished security reports
    suitable for incident response documentation and portfolio presentation.
    """

    def __init__(self, reports_dir: Union[str, Path] = "reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_markdown(
        self,
        comparison_results: Dict[str, Any],
        scan_stats: Dict[str, Any],
        baseline_meta: Optional[Dict[str, Any]] = None,
        save_file: bool = True,
        custom_filename: Optional[str] = None,
    ) -> Tuple[str, Optional[Path]]:
        """
        Generate a comprehensive, executive-ready Markdown investigation report.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
        file_ts = now.strftime("%Y%m%d_%H%M%S")

        status = comparison_results.get("status", "UNKNOWN")
        counts = comparison_results.get("counts", {})
        anomalies: List[Dict[str, Any]] = comparison_results.get("anomalies", [])

        is_clean = status == "CLEAN"
        critical_count = counts.get("critical_violations", 0)

        # Status Banner
        if is_clean:
            status_badge = "🟢 **STATUS: SECURE / CLEAN (NO INTEGRITY VIOLATIONS DETECTED)**"
        elif critical_count > 0:
            status_badge = f"🔴 **STATUS: CRITICAL ALERT ({critical_count} HIGH-RISK VIOLATION{'S' if critical_count > 1 else ''} DETECTED)**"
        else:
            status_badge = f"🟡 **STATUS: WARNING ({counts.get('total_anomalies', 0)} ANOMALIES DETECTED)**"

        md_lines = [
            "# Linux File Integrity Monitoring (FIM) - Security Scan Report",
            "",
            f"> Generated: `{timestamp_str}` | Host: `{socket.gethostname()}`",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            status_badge,
            "",
            "This report details the findings of an automated host-based cryptographic file integrity verification scan. "
            "All targeted file system objects were evaluated against an authorized SHA-256 cryptographic baseline.",
            "",
            "### Summary Metrics",
            "",
            "| Metric | Count | Description |",
            "| :--- | :--- | :--- |",
            f"| **Baseline File Count** | `{counts.get('total_baseline', 0)}` | Authorized files cataloged in active baseline |",
            f"| **Current Files Scanned** | `{counts.get('total_current', 0)}` | Files inspected during active scan cycle |",
            f"| **Modified Files** | `{counts.get('modified', 0)}` | Files with cryptographic hash discrepancies |",
            f"| **Added Files** | `{counts.get('added', 0)}` | Uncataloged newly created files discovered |",
            f"| **Deleted Files** | `{counts.get('deleted', 0)}` | Baseline files missing from disk |",
            f"| **Metadata Alterations** | `{counts.get('metadata_changed', 0)}` | Permissions, size, or ownership altered |",
            f"| **Unchanged Files** | `{counts.get('unchanged', 0)}` | Cryptographically validated unaltered files |",
            f"| **Critical Alerts** | `{counts.get('critical_violations', 0)}` | High-priority security file violations |",
            f"| **Scan Duration** | `{scan_stats.get('duration_seconds', 0.0):.4f}s` | Total file traversal & hashing duration |",
            "",
        ]

        # 2. Detailed Findings Section
        md_lines.append("## 2. Detected Discrepancies & Anomaly Log")
        md_lines.append("")

        if not anomalies:
            md_lines.append("✅ **No discrepancies detected.** All files match baseline signatures.")
            md_lines.append("")
        else:
            md_lines.append("| Severity | Type | Target Path | Baseline Hash / Details | Current Hash / Mode |")
            md_lines.append("| :--- | :--- | :--- | :--- | :--- |")

            for item in anomalies:
                sev = item.get("severity", "INFO")
                sev_icon = {
                    "CRITICAL": "🔴 CRITICAL",
                    "HIGH": "🟠 HIGH",
                    "MEDIUM": "🟡 MEDIUM",
                    "LOW": "🔵 LOW",
                    "INFO": "⚪ INFO",
                }.get(sev, sev)

                ch_type = item.get("change_type", "UNKNOWN")
                path = f"`{item.get('path')}`"

                base_hash = item.get("baseline_sha256")
                curr_hash = item.get("current_sha256")

                base_repr = f"`{base_hash[:16]}...`" if base_hash else "*None (New)*"
                curr_repr = f"`{curr_hash[:16]}...`" if curr_hash else "*Deleted*"

                if ch_type == "METADATA_CHANGED":
                    base_repr = f"Mode: `{item.get('baseline_mode')}`"
                    curr_repr = f"Mode: `{item.get('current_mode')}`"

                md_lines.append(f"| **{sev_icon}** | `{ch_type}` | {path} | {base_repr} | {curr_repr} |")

            md_lines.append("")
            md_lines.append("### Detailed Findings Breakdown")
            md_lines.append("")
            for idx, item in enumerate(anomalies, 1):
                md_lines.append(f"#### Finding #{idx}: `{item.get('path')}` ({item.get('change_type')})")
                md_lines.append(f"- **Severity**: `{item.get('severity')}`")
                md_lines.append(f"- **Finding Summary**: {item.get('details')}")
                if item.get("baseline_sha256"):
                    md_lines.append(f"- **Baseline SHA-256**: `{item.get('baseline_sha256')}`")
                if item.get("current_sha256"):
                    md_lines.append(f"- **Current SHA-256**: `{item.get('current_sha256')}`")
                if item.get("baseline_size") is not None and item.get("current_size") is not None:
                    md_lines.append(
                        f"- **Size Comparison**: {item.get('baseline_size')} bytes -> {item.get('current_size')} bytes"
                    )
                if item.get("current_mtime"):
                    md_lines.append(f"- **Last Modified Timestamp**: `{item.get('current_mtime')}`")
                md_lines.append("")

        # 3. MITRE ATT&CK Mapping
        md_lines.extend([
            "## 3. Threat Context & MITRE ATT&CK® Mapping",
            "",
            "File integrity anomalies typically correspond to core adversary tactics during Linux host intrusion:",
            "",
            "| Technique ID | Technique Name | Tactic | Context in FIM Findings |",
            "| :--- | :--- | :--- | :--- |",
            "| **T1565.001** | Stored Data Manipulation | Impact | Unauthorized modification of system binaries, web roots, or configs |",
            "| **T1098** | Account Manipulation | Persistence | Tampering with `/etc/passwd` or `/etc/shadow` to inject rogue UID 0 accounts |",
            "| **T1053.003** | Cron Persistence | Persistence / Privilege Escalation | Creation of malicious scheduled jobs in `/etc/cron.*` |",
            "| **T1070** | Indicator Removal | Defense Evasion | Unauthorized deletion of audit logs (`/var/log/auth.log`) to wipe footprints |",
            "| **T1543.002** | Systemd Service Dropper | Persistence | New backdoor service unit created in `/etc/systemd/system/` |",
            "",
            "## 4. SOC Analyst Incident Response Playbook",
            "",
            "If unexpected modifications or deletions are detected:",
            "1. **Isolate & Preserve**: Disconnect host network interface if critical binaries (`/bin/login`, `sshd`) are altered.",
            "2. **Forensic Evidence Collection**: Preserve volatile RAM and inspect bash history, process trees (`ps auxf`), and active sockets (`ss -tulpn`).",
            "3. **Differential Analysis**: Compare modified files against known-good package repository checksums (`dpkg -V` on Debian/Ubuntu, `rpm -V` on RHEL/CentOS).",
            "4. **Remediation**: Restore verified copies from clean immutable backups or reinstall official vendor packages.",
            "5. **Authorized Baseline Refresh**: Once verified legitimate, execute `python main.py update` to update the baseline.",
            "",
            "---",
            "*Report generated by Linux File Integrity Monitor Utility*",
        ])

        report_content = "\n".join(md_lines)
        saved_path = None

        if save_file:
            fname = custom_filename or f"scan_report_{file_ts}.md"
            saved_path = self.reports_dir / fname
            saved_path.write_text(report_content, encoding="utf-8")

        return report_content, saved_path

    def generate_json(
        self,
        comparison_results: Dict[str, Any],
        scan_stats: Dict[str, Any],
        save_file: bool = True,
        custom_filename: Optional[str] = None,
    ) -> Tuple[str, Optional[Path]]:
        """Export comprehensive machine-readable JSON report."""
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "report_timestamp": now.isoformat(),
            "host": socket.gethostname(),
            "scan_stats": scan_stats,
            "comparison": comparison_results,
        }

        json_str = json.dumps(payload, indent=2)
        saved_path = None

        if save_file:
            file_ts = now.strftime("%Y%m%d_%H%M%S")
            fname = custom_filename or f"scan_report_{file_ts}.json"
            saved_path = self.reports_dir / fname
            saved_path.write_text(json_str, encoding="utf-8")

        return json_str, saved_path

    def generate_text_summary(self, comparison_results: Dict[str, Any], scan_stats: Dict[str, Any]) -> str:
        """Render a clean, high-impact terminal banner and summary table."""
        counts = comparison_results.get("counts", {})
        status = comparison_results.get("status", "UNKNOWN")
        anomalies: List[Dict[str, Any]] = comparison_results.get("anomalies", [])

        border = "=" * 70
        divider = "-" * 70

        lines = [
            border,
            "           LINUX FILE INTEGRITY MONITOR - SCAN REPORT SUMMARY",
            border,
            f" Status:               {status}",
            f" Baseline Files:       {counts.get('total_baseline', 0)}",
            f" Current Files:        {counts.get('total_current', 0)}",
            f" Modified Files:       {counts.get('modified', 0)}",
            f" Added Files:          {counts.get('added', 0)}",
            f" Deleted Files:        {counts.get('deleted', 0)}",
            f" Metadata Changes:     {counts.get('metadata_changed', 0)}",
            f" Unchanged (Verified): {counts.get('unchanged', 0)}",
            f" Critical Alerts:      {counts.get('critical_violations', 0)}",
            f" Scan Duration:        {scan_stats.get('duration_seconds', 0.0):.4f} seconds",
            divider,
        ]

        if anomalies:
            lines.append(" DETECTED ANOMALIES:")
            for a in anomalies:
                lines.append(f"   [{a['severity']}] {a['change_type']}: {a['path']}")
                lines.append(f"          Details: {a['details']}")
        else:
            lines.append("  All monitored files match authorized cryptographic signatures.")

        lines.append(border)
        return "\n".join(lines)
