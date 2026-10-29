"""
End-to-end integration tests simulating real-world file tampering and FIM lifecycle.
"""

import tempfile
import unittest
from pathlib import Path

from fim.baseline import BaselineManager
from fim.comparison import IntegrityComparator
from fim.scanner import FileScanner


class TestFileChangesLifecycle(unittest.TestCase):
    """Integration test suite executing the complete FIM workflow on a real filesystem."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Setup mock file hierarchy
        self.etc_dir = self.root / "etc"
        self.bin_dir = self.root / "bin"
        self.etc_dir.mkdir(parents=True)
        self.bin_dir.mkdir(parents=True)

        self.passwd_file = self.etc_dir / "passwd"
        self.passwd_file.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")

        self.login_file = self.bin_dir / "login"
        self.login_file.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

        self.baseline_file = self.root / "baseline.json"
        self.manager = BaselineManager(self.baseline_file)
        self.comparator = IntegrityComparator()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_complete_fim_lifecycle(self):
        """
        Verify:
        1. Initial baseline creation
        2. First scan is clean
        3. Adversary tampers with files (modify, add, delete)
        4. FIM scan accurately catches all 3 anomalies
        5. Explicit update establishes new baseline
        6. Subsequent scan is clean again
        """
        monitored_paths = [self.etc_dir, self.bin_dir]

        # Phase 1: Establish baseline
        scanner1 = FileScanner(monitored_paths)
        records1, errs1, stats1 = scanner1.scan()
        self.assertEqual(len(errs1), 0)
        self.assertEqual(len(records1), 2)

        base_data = self.manager.create(records1, monitored_paths)
        self.assertTrue(self.baseline_file.exists())

        # Phase 2: Immediate scan should be 100% clean
        scanner2 = FileScanner(monitored_paths)
        records2, _, _ = scanner2.scan()
        results2 = self.comparator.compare(base_data["files"], records2)
        self.assertEqual(results2["status"], "CLEAN")
        self.assertEqual(results2["counts"]["unchanged"], 2)

        # Phase 3: Adversary attacks
        # Action A: Modify etc/passwd (append backdoor user)
        with self.passwd_file.open("a", encoding="utf-8") as f:
            f.write("backdoor:x:0:0:backdoor:/root:/bin/bash\n")

        # Action B: Create rogue binary bin/trojan
        trojan_file = self.bin_dir / "trojan"
        trojan_file.write_text("malicious payload", encoding="utf-8")

        # Action C: Delete bin/login
        self.login_file.unlink()

        # Phase 4: FIM Scan detects all anomalies
        scanner3 = FileScanner(monitored_paths)
        records3, _, stats3 = scanner3.scan()
        results3 = self.comparator.compare(base_data["files"], records3)

        self.assertEqual(results3["status"], "VIOLATIONS_DETECTED")
        self.assertEqual(results3["counts"]["modified"], 1)
        self.assertEqual(results3["counts"]["added"], 1)
        self.assertEqual(results3["counts"]["deleted"], 1)
        self.assertEqual(results3["counts"]["unchanged"], 0)

        # Phase 5: Explicit baseline update
        updated_data, up_err = self.manager.update_explicit(records3, monitored_paths)
        self.assertIsNone(up_err)
        self.assertEqual(updated_data["total_files"], 2)  # modified passwd + added trojan

        # Phase 6: Scan against new baseline is clean
        scanner4 = FileScanner(monitored_paths)
        records4, _, _ = scanner4.scan()
        results4 = self.comparator.compare(updated_data["files"], records4)
        self.assertEqual(results4["status"], "CLEAN")
        self.assertEqual(results4["counts"]["unchanged"], 2)


if __name__ == "__main__":
    unittest.main()
