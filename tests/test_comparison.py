"""
Unit tests for differential integrity comparison and anomaly classification.
"""

import unittest
from fim.comparison import IntegrityComparator


class TestIntegrityComparator(unittest.TestCase):
    """Test suite for detecting modifications, additions, deletions, and metadata changes."""

    def setUp(self):
        self.comparator = IntegrityComparator(
            critical_patterns=["*passwd*", "*shadow*", "*/bin/*"]
        )

        self.baseline = {
            "etc/passwd": {
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "size_bytes": 1000,
                "mode_octal": "0644",
                "owner": "root",
                "group": "root",
                "mtime_iso": "2026-10-29T00:00:00Z",
            },
            "etc/hosts": {
                "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
                "size_bytes": 200,
                "mode_octal": "0644",
                "owner": "root",
                "group": "root",
                "mtime_iso": "2026-10-29T00:00:00Z",
            },
            "var/log/auth.log": {
                "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
                "size_bytes": 5000,
                "mode_octal": "0640",
                "owner": "root",
                "group": "adm",
                "mtime_iso": "2026-10-29T00:00:00Z",
            },
        }

    def test_clean_state_comparison(self):
        """Verify identical current files produce CLEAN status and zero anomalies."""
        current = dict(self.baseline)
        results = self.comparator.compare(self.baseline, current)

        self.assertEqual(results["status"], "CLEAN")
        self.assertEqual(results["counts"]["total_anomalies"], 0)
        self.assertEqual(results["counts"]["unchanged"], 3)
        self.assertEqual(results["counts"]["modified"], 0)
        self.assertEqual(len(results["anomalies"]), 0)

    def test_detect_modified_file_and_critical_severity(self):
        """Verify hash mismatch on critical file triggers CRITICAL severity MODIFIED anomaly."""
        current = {
            k: dict(v) for k, v in self.baseline.items()
        }
        # Tamper with etc/passwd
        current["etc/passwd"]["sha256"] = "9999999999999999999999999999999999999999999999999999999999999999"
        current["etc/passwd"]["size_bytes"] = 1050

        results = self.comparator.compare(self.baseline, current)

        self.assertEqual(results["status"], "VIOLATIONS_DETECTED")
        self.assertEqual(results["counts"]["modified"], 1)
        self.assertEqual(results["counts"]["critical_violations"], 1)

        anomaly = results["anomalies"][0]
        self.assertEqual(anomaly["path"], "etc/passwd")
        self.assertEqual(anomaly["change_type"], "MODIFIED")
        self.assertEqual(anomaly["severity"], "CRITICAL")
        self.assertIn("Cryptographic hash mismatch", anomaly["details"])

    def test_detect_added_file(self):
        """Verify untracked file is detected as ADDED."""
        current = dict(self.baseline)
        current["bin/backdoor.sh"] = {
            "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
            "size_bytes": 128,
            "mode_octal": "0755",
            "owner": "root",
            "group": "root",
            "mtime_iso": "2026-10-29T01:00:00Z",
        }

        results = self.comparator.compare(self.baseline, current)
        self.assertEqual(results["status"], "VIOLATIONS_DETECTED")
        self.assertEqual(results["counts"]["added"], 1)

        anomaly = [a for a in results["anomalies"] if a["change_type"] == "ADDED"][0]
        self.assertEqual(anomaly["path"], "bin/backdoor.sh")
        self.assertEqual(anomaly["severity"], "CRITICAL")  # Matches bin pattern

    def test_detect_deleted_file(self):
        """Verify deleted baseline file is detected as DELETED."""
        current = {
            k: v for k, v in self.baseline.items() if k != "var/log/auth.log"
        }

        results = self.comparator.compare(self.baseline, current)
        self.assertEqual(results["status"], "VIOLATIONS_DETECTED")
        self.assertEqual(results["counts"]["deleted"], 1)

        anomaly = [a for a in results["anomalies"] if a["change_type"] == "DELETED"][0]
        self.assertEqual(anomaly["path"], "var/log/auth.log")
        self.assertEqual(anomaly["change_type"], "DELETED")

    def test_detect_metadata_change(self):
        """Verify permission change with identical hash triggers METADATA_CHANGED."""
        current = {
            k: dict(v) for k, v in self.baseline.items()
        }
        # Change file mode from 0644 to 0777 (dangerous permissions change)
        current["etc/hosts"]["mode_octal"] = "0777"

        results = self.comparator.compare(self.baseline, current)
        self.assertEqual(results["status"], "VIOLATIONS_DETECTED")
        self.assertEqual(results["counts"]["metadata_changed"], 1)

        anomaly = results["anomalies"][0]
        self.assertEqual(anomaly["change_type"], "METADATA_CHANGED")
        self.assertIn("mode: 0644 -> 0777", anomaly["details"])


if __name__ == "__main__":
    unittest.main()
