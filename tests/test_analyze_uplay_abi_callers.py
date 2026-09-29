#!/usr/bin/env python3
"""Tests for the bounded Uplay caller-code analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(
    str(PROJECT_DIR / "tools/analyze-uplay-abi-callers.py")
)


class UplayAbiCallerAnalyzerTests(unittest.TestCase):
    def parse(self, code: bytes, return_rva: int = 0x1006):
        line = (
            "UPLAY_ABI_CODE tick_ms=1 process=2 thread=3 "
            "function=UPLAY_USER_IsOwned return_rva="
            f"{return_rva:#x} function_start_rva=0x1000 start_rva=0x1000 "
            f"exact_start=yes length={len(code)} bytes={code.hex()}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "abi.log"
            path.write_text(line, encoding="utf-8")
            return ANALYZER["parse_log"](path)[0]

    def test_parses_rip_indirect_call(self) -> None:
        record = self.parse(bytes.fromhex("ff1534120000c3"))
        self.assertEqual(record.function, "UPLAY_USER_IsOwned")
        self.assertEqual(
            ANALYZER["preceding_call"](record),
            "rip-indirect slot=0x223a",
        )

    def test_parses_direct_call(self) -> None:
        record = self.parse(bytes.fromhex("e8fb0f0000c3"), 0x1005)
        self.assertEqual(ANALYZER["preceding_call"](record), "direct 0x2000")

    def test_rejects_byte_count_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "abi.log"
            path.write_text(
                "UPLAY_ABI_CODE tick_ms=1 process=2 thread=3 function=F "
                "return_rva=0x1001 function_start_rva=0x1000 "
                "start_rva=0x1000 exact_start=yes length=2 bytes=90\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "byte-count mismatch"):
                ANALYZER["parse_log"](path)


if __name__ == "__main__":
    unittest.main()
