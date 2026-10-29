"""
Baseline database lifecycle management module.
Handles creation, atomic persistence, schema validation, and explicit updates
of cryptographic file system baselines.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import socket
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

BASELINE_SCHEMA_VERSION = "1.0.0"


def get_system_context() -> Dict[str, str]:
    """Capture host identification and environment context for the baseline header."""
    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
    }


def compute_catalog_checksum(files_dict: Dict[str, Dict[str, Any]]) -> str:
    """
    Calculate an integrity checksum over the entire catalog of file records.
    Sorts keys deterministically to produce a stable cryptographic signature.
    """
    canonical_json = json.dumps(files_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class BaselineManager:
    """
    Manages baseline JSON storage, atomic write safety, and explicit updates.
    """

    def __init__(self, baseline_path: Union[str, Path] = "baseline.json"):
        self.baseline_path = Path(baseline_path)

    def exists(self) -> bool:
        """Check if baseline file exists on disk."""
        return self.baseline_path.is_file()

    def create(
        self,
        file_records: Dict[str, Dict[str, Any]],
        monitored_paths: List[Union[str, Path]],
        hash_algorithm: str = "sha256",
    ) -> Dict[str, Any]:
        """
        Assemble and persist a new baseline document.

        Args:
            file_records: Dict of path -> file metadata records.
            monitored_paths: Target paths included in this baseline.
            hash_algorithm: Cryptographic algorithm identifier.

        Returns:
            The complete baseline dictionary.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        catalog_checksum = compute_catalog_checksum(file_records)

        baseline_data: Dict[str, Any] = {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "created_at": now_iso,
            "updated_at": now_iso,
            "hash_algorithm": hash_algorithm,
            "host_context": get_system_context(),
            "monitored_paths": [str(Path(p).as_posix()) for p in monitored_paths],
            "total_files": len(file_records),
            "catalog_checksum": catalog_checksum,
            "files": file_records,
        }

        self._save_atomic(baseline_data)
        return baseline_data

    def load(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Read and validate baseline file from disk.

        Returns:
            Tuple of (baseline_dict, error_message).
        """
        if not self.exists():
            return None, f"Baseline file not found at '{self.baseline_path}'. Run 'init' to establish one."

        try:
            with self.baseline_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            # Validate basic schema presence
            required_keys = {"schema_version", "created_at", "files"}
            missing = required_keys - set(data.keys())
            if missing:
                return None, f"Corrupted baseline: missing required keys {missing}"

            # Verify catalog integrity checksum if present
            if "catalog_checksum" in data and "files" in data:
                expected = compute_catalog_checksum(data["files"])
                if expected != data["catalog_checksum"]:
                    return data, (
                        "Warning: Baseline catalog checksum mismatch! "
                        "The baseline file itself may have been tampered with or edited manually."
                    )

            return data, None

        except json.JSONDecodeError as err:
            return None, f"Baseline JSON syntax is corrupted or unreadable: {err}"
        except PermissionError:
            return None, f"Permission denied reading baseline file: {self.baseline_path}"
        except OSError as err:
            return None, f"OS error loading baseline: {err}"

    def update_explicit(
        self,
        current_records: Dict[str, Dict[str, Any]],
        monitored_paths: Optional[List[Union[str, Path]]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Explicitly overwrite or update baseline with new state.
        Never runs automatically; requires intentional invocation by user.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        old_data, err = self.load()

        created_at = old_data.get("created_at", now_iso) if old_data else now_iso
        resolved_monitored = (
            [str(Path(p).as_posix()) for p in monitored_paths]
            if monitored_paths
            else (old_data.get("monitored_paths", []) if old_data else [])
        )

        catalog_checksum = compute_catalog_checksum(current_records)
        updated_data: Dict[str, Any] = {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "created_at": created_at,
            "updated_at": now_iso,
            "hash_algorithm": "sha256",
            "host_context": get_system_context(),
            "monitored_paths": resolved_monitored,
            "total_files": len(current_records),
            "catalog_checksum": catalog_checksum,
            "files": current_records,
        }

        # Backup old baseline if it existed
        if self.exists():
            backup_path = self.baseline_path.with_suffix(".json.bak")
            try:
                self.baseline_path.replace(backup_path)
            except OSError:
                pass  # Non-fatal if backup replace fails

        self._save_atomic(updated_data)
        return updated_data, None

    def _save_atomic(self, data: Dict[str, Any]) -> None:
        """
        Write serialized JSON to a temporary file on the same filesystem
        and atomically rename it into place to avoid partial writes.
        """
        parent_dir = self.baseline_path.resolve().parent
        parent_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent_dir,
            delete=False,
            suffix=".tmp"
        ) as tmp:
            json.dump(data, tmp, indent=2, sort_keys=True)
            tmp_path = Path(tmp.name)

        # Atomic replace (standard on POSIX and Windows in modern Python)
        tmp_path.replace(self.baseline_path)
