#!/usr/bin/env python3
"""Tests for the certificate-read probe analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-cert-probe.py"))


class AnalyzeTctdCertProbeTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_parses_in_game_and_runtime_reads(self) -> None:
        path = self.write_log(
            "TCTD_CERT_PROBE_READY tick_ms=1 process=2 thread=3 detail=ready\n"
            "TCTD_CERT_WATCH_ARMED tick_ms=2 process=2 thread=3 detail=armed\n"
            "TCTD_CERT_READ tick_ms=3 process=2 thread=3 "
            "detail=sequence=1,instruction-rva=set,instruction=0x1234,"
            "caller-count=2,caller-rvas=0x2000,0x3000,payloads=disabled\n"
            "TCTD_CERT_READ tick_ms=4 process=2 thread=3 "
            "detail=sequence=2,instruction-rva=outside-game,caller-count=1,"
            "caller-rvas=0x4000,payloads=disabled\n"
        )
        reads, events, errors = ANALYZER["parse_log"](path)
        self.assertEqual(len(reads), 2)
        self.assertEqual(reads[0].instruction, 0x1234)
        self.assertEqual(reads[0].callers, (0x2000, 0x3000))
        self.assertIsNone(reads[1].instruction)
        self.assertEqual(events["TCTD_CERT_WATCH_ARMED"], 1)
        self.assertEqual(errors, [])

    def test_rejects_caller_count_mismatch(self) -> None:
        path = self.write_log(
            "TCTD_CERT_READ tick_ms=3 process=2 thread=3 "
            "detail=sequence=1,instruction-rva=set,instruction=0x1234,"
            "caller-count=2,caller-rvas=0x2000,payloads=disabled\n"
        )
        with self.assertRaisesRegex(ValueError, "caller-count mismatch"):
            ANALYZER["parse_log"](path)


if __name__ == "__main__":
    unittest.main()
