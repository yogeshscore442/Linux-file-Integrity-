"""
Unit tests for baseline management and persistence.
"""

import json
import tempfile
import unittest
from pathlib import Path

from fim.baseline import BaselineManager, compute_catalog_checksum


class TestBaselineManager(unittest.TestCase):
    """Test suite for baseline creation, atomic writing, and validation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        self.baseline_path = self.test_dir / "test_baseline.json"
        self.manager = BaselineManager(self.baseline_path)

        self.mock_records = {
            "sample/file1.txt": {
                "path": "sample/file1.txt",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size_bytes": 100,
                "mtime_iso": "2026-10-29T10:00:00Z",
                "mode_octal": "0644",
                "owner": "root",
                "group": "root",
            },
            "sample/file2.txt": {
                "path": "sample/file2.txt",
                "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "size_bytes": 200,
                "mtime_iso": "2026-10-29T10:05:00Z",
                "mode_octal": "0755",
                "owner": "root",
                "group": "root",
            },
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_baseline_creation(self):
        """Verify baseline writes valid JSON and creates schema."""
        self.assertFalse(self.manager.exists())
        data = self.manager.create(
            file_records=self.mock_records,
            monitored_paths=["sample"],
            hash_algorithm="sha256"
        )
        self.assertTrue(self.manager.exists())
        self.assertEqual(data["total_files"], 2)
        self.assertEqual(data["hash_algorithm"], "sha256")
        self.assertIn("catalog_checksum", data)

    def test_baseline_load_and_catalog_checksum(self):
        """Verify baseline loads correctly and detects checksum consistency."""
        self.manager.create(self.mock_records, monitored_paths=["sample"])
        loaded, err = self.manager.load()
        self.assertIsNone(err)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["total_files"], 2)
        self.assertIn("sample/file1.txt", loaded["files"])

    def test_baseline_detects_manual_tampering(self):
        """Verify modifying baseline JSON directly triggers catalog checksum mismatch."""
        self.manager.create(self.mock_records, monitored_paths=["sample"])

        # Manually alter the baseline JSON file
        with self.baseline_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)

        raw["files"]["sample/file1.txt"]["sha256"] = "tampered_hash_12345"

        with self.baseline_path.open("w", encoding="utf-8") as f:
            json.dump(raw, f)

        # Loading should notify of tampering
        loaded, err = self.manager.load()
        self.assertIsNotNone(loaded)
        self.assertIsNotNone(err)
        self.assertIn("catalog checksum mismatch", err)

    def test_explicit_update(self):
        """Verify explicit update refreshes catalog and creates backup."""
        self.manager.create(self.mock_records, monitored_paths=["sample"])

        # New records with a 3rd file added
        new_records = dict(self.mock_records)
        new_records["sample/file3.txt"] = {
            "path": "sample/file3.txt",
            "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "size_bytes": 300,
            "mtime_iso": "2026-10-29T10:10:00Z",
            "mode_octal": "0600",
            "owner": "root",
            "group": "root",
        }

        updated, err = self.manager.update_explicit(new_records)
        self.assertIsNone(err)
        self.assertEqual(updated["total_files"], 3)

        # Check backup was created
        backup_path = self.baseline_path.with_suffix(".json.bak")
        self.assertTrue(backup_path.exists())


if __name__ == "__main__":
    unittest.main()
