#!/usr/bin/env python3
"""Tests for the TCTD decision-owner lifecycle analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-owner-watch.py"))


class AnalyzeTctdOwnerWatchTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_parses_field_and_state_writes(self) -> None:
        path = self.write_log(
            "TCTD_OWNER_WATCH_READY tick_ms=1 process=2 thread=3 detail=ready\n"
            "TCTD_OWNER_DECISION tick_ms=2 process=2 thread=3 detail=decision\n"
            "TCTD_OWNER_FIELD_WRITE tick_ms=3 process=2 thread=3 "
            "detail=sequence=1,state=replaced,state-byte=zero,resume-rva=set,"
            "resume=0x1234,caller-count=1,caller-rvas=0x2000,"
            "mutation=disabled,payloads=disabled\n"
            "TCTD_OWNER_STATE_WRITE tick_ms=4 process=2 thread=3 "
            "detail=sequence=1,value-after=nonzero,resume-rva=outside-game,"
            "caller-count=0,caller-rvas=none,"
            "mutation=disabled,payloads=disabled\n"
        )
        writes, events, errors = ANALYZER["parse_log"](path)
        self.assertEqual(errors, [])
        self.assertEqual(events["TCTD_OWNER_DECISION"], 1)
        self.assertEqual([item.kind for item in writes], ["field", "state"])
        self.assertEqual(writes[0].resume, 0x1234)
        self.assertIsNone(writes[1].resume)

    def test_rejects_caller_count_mismatch(self) -> None:
        path = self.write_log(
            "TCTD_OWNER_FIELD_WRITE tick_ms=3 process=2 thread=3 "
            "detail=sequence=1,state=replaced,state-byte=zero,resume-rva=set,"
            "resume=0x1234,caller-count=2,caller-rvas=0x2000,"
            "mutation=disabled,payloads=disabled\n"
        )
        with self.assertRaisesRegex(ValueError, "caller-count mismatch"):
            ANALYZER["parse_log"](path)


if __name__ == "__main__":
    unittest.main()
