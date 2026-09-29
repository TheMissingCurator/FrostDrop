#!/usr/bin/env python3
"""Tests for the TCTD certificate completion branch analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-branch-probe.py"))


class AnalyzeTctdBranchProbeTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_parses_status_and_callers(self) -> None:
        path = self.write_log(
            "TCTD_BRANCH_PROBE_READY tick_ms=1 process=2 thread=3 detail=ready\n"
            "TCTD_BRANCH_CHECKPOINT tick_ms=2 process=2 thread=3 "
            "detail=sequence=1,checkpoint=tls-status,result=nonzero,"
            "value-low16=0x002a,caller-count=2,caller-rvas=0xbb537,0xbbba7,"
            "mutation=disabled,payloads=disabled\n"
        )
        checkpoints, events, errors = ANALYZER["parse_log"](path)
        self.assertEqual(events["TCTD_BRANCH_PROBE_READY"], 1)
        self.assertEqual(errors, [])
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0].name, "tls-status")
        self.assertEqual(checkpoints[0].value, 0x2A)
        self.assertEqual(checkpoints[0].callers, (0xBB537, 0xBBBA7))

    def test_rejects_caller_count_mismatch(self) -> None:
        path = self.write_log(
            "TCTD_BRANCH_CHECKPOINT tick_ms=2 process=2 thread=3 "
            "detail=sequence=1,checkpoint=operation-ready,result=zero,"
            "value-low16=0x0000,caller-count=2,caller-rvas=0xbb537,"
            "mutation=disabled,payloads=disabled\n"
        )
        with self.assertRaisesRegex(ValueError, "caller-count mismatch"):
            ANALYZER["parse_log"](path)


if __name__ == "__main__":
    unittest.main()
