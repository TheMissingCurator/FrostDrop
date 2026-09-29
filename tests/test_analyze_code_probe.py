#!/usr/bin/env python3
"""Focused tests for code-probe call-site analysis."""

from __future__ import annotations

import runpy
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-code-probe.py"))


class CodeAnalyzerTests(unittest.TestCase):
    def test_infers_direct_call_before_return_address(self) -> None:
        record = ANALYZER["CodeRecord"](
            tick=1,
            process=2,
            thread=3,
            label="send-frame",
            target_rva=0x1010,
            start_rva=0x1000,
            data=b"\x90" * 11 + b"\xe8\xf0\x0f\x00\x00" + b"\xc3",
        )
        self.assertEqual(
            ANALYZER["infer_preceding_direct_call"](record),
            0x2000,
        )

    def test_rejects_non_call_predecessor(self) -> None:
        record = ANALYZER["CodeRecord"](
            tick=1,
            process=2,
            thread=3,
            label="send-frame",
            target_rva=0x1005,
            start_rva=0x1000,
            data=b"\x90" * 6,
        )
        self.assertIsNone(ANALYZER["infer_preceding_direct_call"](record))


if __name__ == "__main__":
    unittest.main()
