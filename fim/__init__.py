"""
Linux File Integrity Monitoring (FIM) Utility
A host-based security tool for establishing cryptographic file baselines,
detecting unauthorized file tampering, and recording structured audit trails.

Author: Yogesh
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Yogesh"
__all__ = [
    "calculate_sha256",
    "get_file_metadata",
    "BaselineManager",
    "FileScanner",
    "IntegrityComparator",
    "AuditLogger",
    "ReportGenerator",
]

from .hashing import calculate_sha256, get_file_metadata
from .baseline import BaselineManager
from .scanner import FileScanner
from .comparison import IntegrityComparator
from .audit_logger import AuditLogger
from .report_generator import ReportGenerator
