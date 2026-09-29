#!/usr/bin/env python3
"""Tests for the early-control path analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-control-probe.py"))


class ControlAnalyzerTests(unittest.TestCase):
    def test_parses_path_and_code(self) -> None:
        log = "\n".join(
            (
                "CONTROL_PROBE_READY tick_ms=1 process=2 thread=3 "
                "detail=target-types=0x0002,0x0006",
                "CONTROL_PATH sequence=1 tick_ms=2 process=2 thread=3 "
                "type_id=0x0002 frame_length=156 absolute_cursor=10 "
                "local_cursor=4 reader_method_rva=0x6c0f0 frame_count=2 "
                "rvas=0x6c139,0x123456",
                "CONTROL_CODE tick_ms=2 process=2 thread=3 type_id=0x0002 "
                "caller_rva=0x6c139 function_rva=0x6c0f0 "
                "function_end_rva=0x6c0f3 length=3 exact_range=1 "
                "truncated=0 bytes=31c0c3",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            paths, code, counts, errors = ANALYZER["parse_log"](path)

        self.assertEqual(paths[0].type_id, 2)
        self.assertEqual(paths[0].rvas, (0x6C139, 0x123456))
        self.assertEqual(code[0x6C0F0].data, bytes.fromhex("31c0c3"))
        self.assertEqual(counts["CONTROL_PROBE_READY"], 1)
        self.assertEqual(errors, [])

    def test_rejects_unexpected_type(self) -> None:
        log = (
            "CONTROL_PATH sequence=1 tick_ms=2 process=2 thread=3 "
            "type_id=0x0007 frame_length=4 absolute_cursor=10 "
            "local_cursor=4 reader_method_rva=0x6c0f0 frame_count=0 rvas=\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected control type"):
                ANALYZER["parse_log"](path)

    def test_accepts_bootstrap_type_0003(self) -> None:
        log = (
            "CONTROL_PATH sequence=1 tick_ms=2 process=2 thread=3 "
            "type_id=0x0003 frame_length=835 absolute_cursor=4 "
            "local_cursor=4 reader_method_rva=0x6c0f0 frame_count=1 "
            "rvas=0x6c12c\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            paths, _, _, _ = ANALYZER["parse_log"](path)

        self.assertEqual(paths[0].type_id, 3)
        self.assertEqual(paths[0].frame_length, 835)


if __name__ == "__main__":
    unittest.main()
