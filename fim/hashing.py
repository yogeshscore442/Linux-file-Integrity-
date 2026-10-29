"""
Cryptographic hashing and file metadata extraction module.
Provides secure SHA-256 chunked calculation and POSIX-compatible
metadata capture with cross-platform resilience.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

# Attempt to import UNIX-specific user/group resolution modules
try:
    import pwd
    import grp
    POSIX_AVAILABLE = True
except ImportError:
    POSIX_AVAILABLE = False


DEFAULT_CHUNK_SIZE = 65536  # 64 KB chunks for memory-efficient hashing


def calculate_sha256(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Tuple[Optional[str], Optional[str]]:
    """
    Compute the SHA-256 cryptographic digest of a file using buffered chunking.

    Args:
        file_path: Path to the target file.
        chunk_size: Size of data chunks read into memory per iteration (default 64KB).

    Returns:
        A tuple of (sha256_hex_string, error_message). If successful,
        error_message is None; if an error occurs, sha256 is None.
    """
    path = Path(file_path)
    if not path.is_file():
        return None, f"Target is not a regular file or does not exist: {path}"

    hasher = hashlib.sha256()

    try:
        with path.open("rb") as stream:
            while chunk := stream.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest(), None
    except PermissionError:
        return None, f"Permission denied while reading file: {path}"
    except FileNotFoundError:
        return None, f"File disappeared during read: {path}"
    except OSError as err:
        return None, f"OS error occurred while hashing {path}: {err}"


def get_file_metadata(file_path: Union[str, Path]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Retrieve comprehensive file system attributes and permissions.

    Extracts:
        - File size in bytes
        - Last modification time (epoch and ISO 8601)
        - POSIX file mode (octal notation, e.g., '0644')
        - File owner and group (resolving usernames on POSIX, fallback on Windows)
        - Inode number (POSIX)

    Args:
        file_path: Path to the target file.

    Returns:
        A tuple of (metadata_dict, error_message).
    """
    path = Path(file_path)
    try:
        st = path.stat(follow_symlinks=False)
        is_symlink = path.is_symlink()

        # Format modification timestamp in RFC 3339 / ISO 8601 format
        mtime_dt = datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)
        mtime_iso = mtime_dt.isoformat()

        # Format POSIX file permissions (e.g. '0644')
        octal_mode = oct(stat.S_IMODE(st.st_mode))

        # Resolve owner and group names if running on POSIX systems
        owner = str(st.st_uid)
        group = str(st.st_gid)

        if POSIX_AVAILABLE and hasattr(os, "getuid"):
            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except (KeyError, OverflowError):
                owner = str(st.st_uid)

            try:
                group = grp.getgrgid(st.st_gid).gr_name
            except (KeyError, OverflowError):
                group = str(st.st_gid)
        else:
            owner = f"uid:{st.st_uid}"
            group = f"gid:{st.st_gid}"

        metadata: Dict[str, Any] = {
            "size_bytes": st.st_size,
            "mtime_epoch": st.st_mtime,
            "mtime_iso": mtime_iso,
            "mode_octal": octal_mode,
            "owner": owner,
            "group": group,
            "is_symlink": is_symlink,
            "inode": getattr(st, "st_ino", None),
        }
        return metadata, None

    except PermissionError:
        return None, f"Permission denied accessing metadata for: {path}"
    except FileNotFoundError:
        return None, f"File not found during metadata extraction: {path}"
    except OSError as err:
        return None, f"OS error retrieving metadata for {path}: {err}"


def inspect_file(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Combined helper to extract both SHA-256 digest and file system metadata.

    Returns:
        Tuple of (file_record_dict, error_message).
    """
    path = Path(file_path)
    sha256_hash, hash_err = calculate_sha256(path, chunk_size=chunk_size)
    if hash_err:
        return None, hash_err

    metadata, meta_err = get_file_metadata(path)
    if meta_err:
        return None, meta_err

    record = {
        "path": str(path.as_posix()),
        "sha256": sha256_hash,
        **metadata,
    }
    return record, None
