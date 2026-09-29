#!/usr/bin/env python3
"""Tests for the dynamically selected TLS parser-code analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-parser-code.py"))


class AnalyzeTctdParserCodeTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_reconstructs_contiguous_function(self) -> None:
        stack = self.write_log(
            "TCTD_PARSER_CODE_CAPTURED tick_ms=1 process=2 thread=3 "
            "detail=target-rva=0x1001,begin-rva=0x1000,end-rva=0x1006,"
            "length=6,windows=2,mutation=disabled,payloads=disabled\n"
        )
        code = self.write_log(
            "CODE tick_ms=1 process=2 thread=3 label=tctd-parser-body-00 "
            "target_rva=0x1000 start_rva=0x1000 length=4 bytes=01020304\n"
            "CODE tick_ms=1 process=2 thread=3 label=tctd-parser-body-01 "
            "target_rva=0x1004 start_rva=0x1004 length=2 bytes=0506\n"
        )
        capture = ANALYZER["parse_capture"](stack, code)
        self.assertEqual(capture.target, 0x1001)
        self.assertEqual(capture.begin, 0x1000)
        self.assertEqual(capture.end, 0x1006)
        self.assertEqual(capture.body, b"\x01\x02\x03\x04\x05\x06")

    def test_rejects_target_outside_function(self) -> None:
        stack = self.write_log(
            "TCTD_PARSER_CODE_CAPTURED tick_ms=1 process=2 thread=3 "
            "detail=target-rva=0x2000,begin-rva=0x1000,end-rva=0x1002,"
            "length=2,windows=1,mutation=disabled,payloads=disabled\n"
        )
        code = self.write_log(
            "CODE tick_ms=1 process=2 thread=3 label=tctd-parser-body-00 "
            "target_rva=0x1000 start_rva=0x1000 length=2 bytes=0102\n"
        )
        with self.assertRaisesRegex(ValueError, "outside captured function"):
            ANALYZER["parse_capture"](stack, code)


if __name__ == "__main__":
    unittest.main()
