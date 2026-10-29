"""
File system traversal and state collection engine.
Performs recursive directory scanning, filters exclusion patterns,
and safely collects cryptographic and metadata fingerprints.
"""

from __future__ import annotations

import fnmatch
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .hashing import inspect_file, DEFAULT_CHUNK_SIZE


class FileScanner:
    """
    Traverses target file systems, normalizes paths, filters exclusions,
    and constructs a dictionary of file state records.
    """

    def __init__(
        self,
        monitored_paths: List[Union[str, Path]],
        exclude_patterns: Optional[List[str]] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        follow_symlinks: bool = False,
    ):
        """
        Initialize the scanner with targets and filtering rules.

        Args:
            monitored_paths: List of directories or files to monitor.
            exclude_patterns: Glob patterns of paths or filenames to ignore.
            chunk_size: Hashing buffer size in bytes.
            follow_symlinks: Whether to traverse directory symlinks.
        """
        self.monitored_paths = [Path(p) for p in monitored_paths]
        self.exclude_patterns = exclude_patterns or []
        self.chunk_size = chunk_size
        self.follow_symlinks = follow_symlinks

    def is_excluded(self, path: Path) -> bool:
        """
        Check if a given path matches any configured exclusion patterns.
        Checks both the filename and the full normalized POSIX path string.
        """
        posix_path = path.as_posix()
        name = path.name

        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(posix_path, pattern):
                return True
            # Also check matching against segments
            if any(fnmatch.fnmatch(part, pattern) for part in path.parts):
                return True
        return False

    def scan(self) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, str]], Dict[str, Any]]:
        """
        Execute scan over all monitored targets.

        Returns:
            Tuple of:
                - records: Dict[normalized_path_string, file_record]
                - errors: List of error dictionaries [{'path': ..., 'error': ...}]
                - stats: Summary statistics dictionary
        """
        start_time = time.time()
        records: Dict[str, Dict[str, Any]] = {}
        errors: List[Dict[str, str]] = []
        total_bytes = 0
        visited_inodes: Set[Tuple[int, int]] = set()  # (device, inode) for cycle detection

        for target in self.monitored_paths:
            if not target.exists():
                errors.append({
                    "path": str(target.as_posix()),
                    "error": "Target path does not exist on filesystem"
                })
                continue

            if target.is_file():
                if not self.is_excluded(target):
                    rec, err = inspect_file(target, chunk_size=self.chunk_size)
                    if err:
                        errors.append({"path": str(target.as_posix()), "error": err})
                    elif rec:
                        key = str(target.as_posix())
                        records[key] = rec
                        total_bytes += rec.get("size_bytes", 0)
                continue

            if target.is_dir():
                for root, dirs, files in os.walk(
                    target,
                    topdown=True,
                    followlinks=self.follow_symlinks
                ):
                    root_path = Path(root)

                    # Cycle detection for symlinked directories on POSIX
                    if self.follow_symlinks:
                        try:
                            stat_res = root_path.stat()
                            dev_ino = (stat_res.st_dev, stat_res.st_ino)
                            if dev_ino in visited_inodes:
                                dirs[:] = []  # Do not recurse further
                                continue
                            visited_inodes.add(dev_ino)
                        except (OSError, PermissionError):
                            pass

                    # Filter excluded directories in-place to prevent unnecessary traversal
                    dirs[:] = [
                        d for d in dirs
                        if not self.is_excluded(root_path / d)
                    ]

                    for filename in files:
                        file_path = root_path / filename

                        if self.is_excluded(file_path):
                            continue

                        # Check for symlink policy
                        if not self.follow_symlinks and file_path.is_symlink():
                            # Record metadata without following target content
                            pass

                        rec, err = inspect_file(file_path, chunk_size=self.chunk_size)
                        if err:
                            errors.append({"path": str(file_path.as_posix()), "error": err})
                        elif rec:
                            key = str(file_path.as_posix())
                            records[key] = rec
                            total_bytes += rec.get("size_bytes", 0)

        duration = round(time.time() - start_time, 4)
        stats = {
            "total_files": len(records),
            "total_bytes": total_bytes,
            "error_count": len(errors),
            "duration_seconds": duration,
        }

        return records, errors, stats
