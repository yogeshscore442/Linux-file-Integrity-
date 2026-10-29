"""
Unit tests for cryptographic hashing and metadata extraction.
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from fim.hashing import calculate_sha256, get_file_metadata, inspect_file


class TestHashingModule(unittest.TestCase):
    """Test suite for SHA-256 calculation and metadata handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        # Create sample files
        self.empty_file = self.test_dir / "empty.txt"
        self.empty_file.write_bytes(b"")

        self.sample_file = self.test_dir / "sample.txt"
        self.sample_content = b"The quick brown fox jumps over the lazy dog"
        self.sample_file.write_bytes(self.sample_content)

        # Known SHA-256 digests
        self.empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.sample_sha256 = hashlib.sha256(self.sample_content).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_file_hash(self):
        """Verify empty file yields standard empty SHA-256 digest."""
        digest, err = calculate_sha256(self.empty_file)
        self.assertIsNone(err)
        self.assertEqual(digest, self.empty_sha256)

    def test_sample_file_hash(self):
        """Verify file content produces exact standard SHA-256 digest."""
        digest, err = calculate_sha256(self.sample_file)
        self.assertIsNone(err)
        self.assertEqual(digest, self.sample_sha256)

    def test_chunked_hashing(self):
        """Verify chunked streaming hashing produces identical hash with tiny buffer."""
        # Use tiny 4-byte chunk buffer to stress chunking logic
        digest, err = calculate_sha256(self.sample_file, chunk_size=4)
        self.assertIsNone(err)
        self.assertEqual(digest, self.sample_sha256)

    def test_non_existent_file(self):
        """Verify graceful error reporting when file does not exist."""
        ghost = self.test_dir / "does_not_exist.bin"
        digest, err = calculate_sha256(ghost)
        self.assertIsNone(digest)
        self.assertIsNotNone(err)
        self.assertIn("not a regular file", err)

    def test_directory_passed_as_file(self):
        """Verify passing a directory to calculate_sha256 safely fails."""
        digest, err = calculate_sha256(self.test_dir)
        self.assertIsNone(digest)
        self.assertIsNotNone(err)

    def test_metadata_extraction(self):
        """Verify file metadata attributes are captured accurately."""
        meta, err = get_file_metadata(self.sample_file)
        self.assertIsNone(err)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["size_bytes"], len(self.sample_content))
        self.assertIn("mtime_iso", meta)
        self.assertIn("mode_octal", meta)
        self.assertIn("owner", meta)
        self.assertIn("group", meta)

    def test_inspect_file_combined(self):
        """Verify inspect_file aggregates hash and metadata in single call."""
        rec, err = inspect_file(self.sample_file)
        self.assertIsNone(err)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["sha256"], self.sample_sha256)
        self.assertEqual(rec["size_bytes"], len(self.sample_content))
        self.assertIn("mode_octal", rec)


if __name__ == "__main__":
    unittest.main()
