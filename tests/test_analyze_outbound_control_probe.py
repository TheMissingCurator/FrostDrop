#!/usr/bin/env python3
"""Tests for the code-only outbound bootstrap path analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(
    str(PROJECT_DIR / "tools/analyze-outbound-control-probe.py")
)


class OutboundControlAnalyzerTests(unittest.TestCase):
    def test_parses_path_and_code(self) -> None:
        log = "\n".join(
            (
                "OUTBOUND_CONTROL_PROBE_READY tick_ms=1 process=2 thread=3 "
                "detail=target-types=0x0002,0x0005",
                "OUTBOUND_CONTROL_PATH sequence=1 tick_ms=2 process=2 thread=3 "
                "type_id=0x0005 envelope_length=12 marker=0x03 channel=0x0a "
                "boundary_function_rva=0xd6b60 "
                "boundary_function_end_rva=0xd6c00 frame_count=2 "
                "rvas=0xd6c10,0x123456",
                "OUTBOUND_CONTROL_CODE tick_ms=2 process=2 thread=3 "
                "type_id=0x0005 caller_rva=0xd6c10 function_rva=0xd6c00 "
                "function_end_rva=0xd6c03 length=3 exact_range=1 "
                "truncated=0 bytes=31c0c3",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            paths, code, counts, errors = ANALYZER["parse_log"](path)

        self.assertEqual(paths[0].type_id, 5)
        self.assertEqual(paths[0].channel, 10)
        self.assertEqual(paths[0].rvas, (0xD6C10, 0x123456))
        self.assertEqual(code[0xD6C00].data, bytes.fromhex("31c0c3"))
        self.assertEqual(counts["OUTBOUND_CONTROL_PROBE_READY"], 1)
        self.assertEqual(errors, [])

    def test_rejects_unexpected_type(self) -> None:
        log = (
            "OUTBOUND_CONTROL_PATH sequence=1 tick_ms=2 process=2 thread=3 "
            "type_id=0x0006 envelope_length=4 marker=0x03 channel=0x01 "
            "boundary_function_rva=0xd6b60 "
            "boundary_function_end_rva=0xd6c00 frame_count=0 rvas=\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected outbound"):
                ANALYZER["parse_log"](path)

    def test_parses_correlation_candidates(self) -> None:
        log = "\n".join(
            (
                "CONTROL_CORRELATION sequence=1 tick_ms=10 process=2 thread=3 "
                "direction=outbound stream_id=4 type_id=0x0005 "
                "frame_length=7 marker=0x03 channel=0x0a first_uvar=42 "
                "encoded_bytes=1",
                "CONTROL_CORRELATION sequence=2 tick_ms=12 process=2 thread=5 "
                "direction=inbound stream_id=6 type_id=0x0006 "
                "frame_length=8 marker=- channel=- first_uvar=42 "
                "encoded_bytes=1",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            records = ANALYZER["parse_correlations"](path)

        self.assertEqual([record.first_uvar for record in records], [42, 42])
        self.assertEqual(records[1].direction, "inbound")
        self.assertEqual(records[1].type_id, 6)


if __name__ == "__main__":
    unittest.main()
