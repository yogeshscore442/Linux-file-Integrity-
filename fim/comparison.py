"""
Integrity comparison and differential analysis engine.
Compares baseline state with active filesystem state, isolates cryptographic
and metadata discrepancies, and assigns threat-informed severity ratings.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional


class IntegrityComparator:
    """
    Evaluates baseline records against current scan records to detect
    additions, deletions, content modifications, and metadata tampering.
    """

    def __init__(self, critical_patterns: Optional[List[str]] = None):
        """
        Args:
            critical_patterns: Glob patterns identifying high-criticality assets
                               (e.g., *passwd*, *shadow*, *sudoers*, */bin/*).
        """
        self.critical_patterns = critical_patterns or [
            "*passwd*",
            "*shadow*",
            "*sudoers*",
            "*sshd_config*",
            "*/bin/*",
            "*/sbin/*",
            "*/boot/*",
            "*/cron*",
        ]

    def is_critical_path(self, path: str) -> bool:
        """Evaluate if path matches any high-criticality system file patterns."""
        normalized = path.replace("\\", "/").strip()
        leading_slash_path = "/" + normalized.lstrip("/")

        for pattern in self.critical_patterns:
            if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(leading_slash_path, pattern):
                return True
            # Also check matching if pattern doesn't have leading asterisk
            alt_pattern = f"*{pattern}" if not pattern.startswith("*") else pattern
            if fnmatch.fnmatch(normalized, alt_pattern) or fnmatch.fnmatch(leading_slash_path, alt_pattern):
                return True
            if any(fnmatch.fnmatch(part, pattern.strip("/*")) for part in normalized.split("/")):
                return True
        return False

    def assign_severity(self, change_type: str, path: str, mode_changed: bool = False) -> str:
        """
        Derive SOC-aligned alert severity level based on change type and path criticality.

        Returns:
            One of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'.
        """
        is_critical = self.is_critical_path(path)

        if change_type == "MODIFIED":
            return "CRITICAL" if is_critical else "HIGH"

        if change_type == "DELETED":
            return "CRITICAL" if is_critical else "HIGH"

        if change_type == "ADDED":
            return "CRITICAL" if is_critical else "MEDIUM"

        if change_type == "METADATA_CHANGED":
            if mode_changed:
                return "CRITICAL" if is_critical else "HIGH"
            return "HIGH" if is_critical else "LOW"

        return "INFO"

    def compare(
        self,
        baseline_files: Dict[str, Dict[str, Any]],
        current_files: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Perform a full differential comparison between baseline and current state.

        Args:
            baseline_files: Dict of file records from baseline database.
            current_files: Dict of file records from active scan.

        Returns:
            Dictionary containing structured comparison results, anomaly details,
            and aggregate metrics.
        """
        baseline_keys = set(baseline_files.keys())
        current_keys = set(current_files.keys())

        added_keys = current_keys - baseline_keys
        deleted_keys = baseline_keys - current_keys
        common_keys = baseline_keys & current_keys

        anomalies: List[Dict[str, Any]] = []
        unchanged_count = 0
        critical_count = 0

        # 1. Process Modified and Metadata-Changed files
        for key in sorted(common_keys):
            base_rec = baseline_files[key]
            curr_rec = current_files[key]

            hash_match = base_rec.get("sha256") == curr_rec.get("sha256")
            size_match = base_rec.get("size_bytes") == curr_rec.get("size_bytes")
            mode_match = base_rec.get("mode_octal") == curr_rec.get("mode_octal")
            owner_match = (
                base_rec.get("owner") == curr_rec.get("owner")
                and base_rec.get("group") == curr_rec.get("group")
            )

            if not hash_match:
                # Content has been modified!
                severity = self.assign_severity("MODIFIED", key)
                if severity == "CRITICAL":
                    critical_count += 1

                details = (
                    f"Cryptographic hash mismatch. Content modified! "
                    f"Baseline: {base_rec.get('sha256')[:12]}... -> Current: {curr_rec.get('sha256')[:12]}..."
                )
                if not size_match:
                    details += f" (Size delta: {curr_rec.get('size_bytes', 0) - base_rec.get('size_bytes', 0):+} bytes)"

                anomalies.append({
                    "path": key,
                    "change_type": "MODIFIED",
                    "severity": severity,
                    "baseline_sha256": base_rec.get("sha256"),
                    "current_sha256": curr_rec.get("sha256"),
                    "baseline_size": base_rec.get("size_bytes"),
                    "current_size": curr_rec.get("size_bytes"),
                    "baseline_mode": base_rec.get("mode_octal"),
                    "current_mode": curr_rec.get("mode_octal"),
                    "baseline_mtime": base_rec.get("mtime_iso"),
                    "current_mtime": curr_rec.get("mtime_iso"),
                    "details": details,
                })

            elif not (size_match and mode_match and owner_match):
                # Hash is unchanged, but file permissions, size, or owner changed
                mode_changed = not mode_match
                severity = self.assign_severity("METADATA_CHANGED", key, mode_changed=mode_changed)
                if severity == "CRITICAL":
                    critical_count += 1

                changes = []
                if not mode_match:
                    changes.append(f"mode: {base_rec.get('mode_octal')} -> {curr_rec.get('mode_octal')}")
                if not owner_match:
                    changes.append(
                        f"owner: {base_rec.get('owner')}:{base_rec.get('group')} -> "
                        f"{curr_rec.get('owner')}:{curr_rec.get('group')}"
                    )
                if not size_match:
                    changes.append(f"size: {base_rec.get('size_bytes')} -> {curr_rec.get('size_bytes')}")

                anomalies.append({
                    "path": key,
                    "change_type": "METADATA_CHANGED",
                    "severity": severity,
                    "baseline_sha256": base_rec.get("sha256"),
                    "current_sha256": curr_rec.get("sha256"),
                    "baseline_size": base_rec.get("size_bytes"),
                    "current_size": curr_rec.get("size_bytes"),
                    "baseline_mode": base_rec.get("mode_octal"),
                    "current_mode": curr_rec.get("mode_octal"),
                    "baseline_mtime": base_rec.get("mtime_iso"),
                    "current_mtime": curr_rec.get("mtime_iso"),
                    "details": f"File metadata altered ({', '.join(changes)}) with identical hash.",
                })

            else:
                unchanged_count += 1

        # 2. Process Newly Added files
        for key in sorted(added_keys):
            curr_rec = current_files[key]
            severity = self.assign_severity("ADDED", key)
            if severity == "CRITICAL":
                critical_count += 1

            anomalies.append({
                "path": key,
                "change_type": "ADDED",
                "severity": severity,
                "baseline_sha256": None,
                "current_sha256": curr_rec.get("sha256"),
                "baseline_size": None,
                "current_size": curr_rec.get("size_bytes"),
                "baseline_mode": None,
                "current_mode": curr_rec.get("mode_octal"),
                "baseline_mtime": None,
                "current_mtime": curr_rec.get("mtime_iso"),
                "details": f"New file discovered. Not present in established baseline.",
            })

        # 3. Process Deleted files
        for key in sorted(deleted_keys):
            base_rec = baseline_files[key]
            severity = self.assign_severity("DELETED", key)
            if severity == "CRITICAL":
                critical_count += 1

            anomalies.append({
                "path": key,
                "change_type": "DELETED",
                "severity": severity,
                "baseline_sha256": base_rec.get("sha256"),
                "current_sha256": None,
                "baseline_size": base_rec.get("size_bytes"),
                "current_size": None,
                "baseline_mode": base_rec.get("mode_octal"),
                "current_mode": None,
                "baseline_mtime": base_rec.get("mtime_iso"),
                "current_mtime": None,
                "details": f"File recorded in baseline is missing from the active filesystem.",
            })

        # Sort anomalies by severity: CRITICAL first, then HIGH, MEDIUM, LOW
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        anomalies.sort(key=lambda x: (severity_order.get(x["severity"], 99), x["path"]))

        has_violations = len(anomalies) > 0
        status_label = "VIOLATIONS_DETECTED" if has_violations else "CLEAN"

        counts = {
            "total_baseline": len(baseline_keys),
            "total_current": len(current_keys),
            "modified": sum(1 for a in anomalies if a["change_type"] == "MODIFIED"),
            "added": sum(1 for a in anomalies if a["change_type"] == "ADDED"),
            "deleted": sum(1 for a in anomalies if a["change_type"] == "DELETED"),
            "metadata_changed": sum(1 for a in anomalies if a["change_type"] == "METADATA_CHANGED"),
            "unchanged": unchanged_count,
            "total_anomalies": len(anomalies),
            "critical_violations": critical_count,
        }

        return {
            "status": status_label,
            "counts": counts,
            "anomalies": anomalies,
        }
