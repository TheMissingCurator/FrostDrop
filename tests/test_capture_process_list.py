import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProcessListTest(unittest.TestCase):
    def test_host_proc_metadata_and_disappearing_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            (proc / "stat").write_text("btime 1000000000\n")
            (proc / "12").mkdir()
            (proc / "13").mkdir()  # raced/disappearing process without stat
            fields = ["S", "10"] + ["0"] * 17 + [str(os.sysconf("SC_CLK_TCK"))]
            (proc / "12/stat").write_text("12 (thedivision.exe) " + " ".join(fields))
            result = subprocess.run([sys.executable, str(ROOT / "tools/capture-process-list.py")],
                                    env=dict(os.environ, ISAC_HOST_PROC=str(proc)),
                                    capture_output=True, text=True, check=True)
            parts = result.stdout.strip().split()
            self.assertEqual(parts[:2], ["12", "10"])
            self.assertEqual(parts[-1], "thedivision.exe")
            self.assertEqual(len(result.stdout.splitlines()), 1)
