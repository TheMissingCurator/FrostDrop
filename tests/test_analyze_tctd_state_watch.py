#!/usr/bin/env python3
"""Tests for the TCTD validation-state write analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-state-watch.py"))


class AnalyzeTctdStateWatchTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_parses_state_writes(self) -> None:
        path = self.write_log(
            "TCTD_STATE_WATCH_READY tick_ms=1 process=2 thread=3 detail=ready\n"
            "TCTD_STATE_WATCH_TARGET tick_ms=2 process=2 thread=3 detail=target\n"
            "TCTD_STATE_WRITE tick_ms=3 process=2 thread=3 "
            "detail=sequence=1,value-after=nonzero,resume-rva=set,"
            "resume=0xf12b4,caller-count=2,caller-rvas=0xf1324,0xbb537,"
            "mutation=disabled,payloads=disabled\n"
        )
        writes, events, errors = ANALYZER["parse_log"](path)
        self.assertEqual(errors, [])
        self.assertEqual(events["TCTD_STATE_WATCH_TARGET"], 1)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].value, "nonzero")
        self.assertEqual(writes[0].resume, 0xF12B4)
        self.assertEqual(writes[0].callers, (0xF1324, 0xBB537))

    def test_rejects_caller_count_mismatch(self) -> None:
        path = self.write_log(
            "TCTD_STATE_WRITE tick_ms=3 process=2 thread=3 "
            "detail=sequence=1,value-after=zero,resume-rva=set,"
            "resume=0x1234,caller-count=2,caller-rvas=0x2000,"
            "mutation=disabled,payloads=disabled\n"
        )
        with self.assertRaisesRegex(ValueError, "caller-count mismatch"):
            ANALYZER["parse_log"](path)


if __name__ == "__main__":
    unittest.main()
