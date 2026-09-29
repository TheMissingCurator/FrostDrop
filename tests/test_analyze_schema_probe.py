#!/usr/bin/env python3
"""Focused tests for schema-probe log parsing."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-schema-probe.py"))


class SchemaAnalyzerTests(unittest.TestCase):
    def test_parses_schema_records(self) -> None:
        log = "\n".join(
            (
                "SCHEMA_EVENT sequence=1 tick_ms=2 process=3 thread=4 "
                "type_id=0x014d vtable_rva=0x100 "
                "deserialize_rva=0x200 slot08_rva=0x300 slot28_rva=0x400 "
                "has_cursor=1 absolute_cursor=50 local_cursor=10 buffer_length=1000",
                "SCHEMA_TARGET tick_ms=2 process=3 thread=4 type_id=0x014d "
                "vtable_rva=0x100 deserialize_rva=0x200 "
                "slot08_rva=0x300 slot28_rva=0x400",
                "SCHEMA_CODE tick_ms=2 process=3 thread=4 type_id=0x014d "
                "target_rva=0x200 function_rva=0x200 function_end_rva=0x203 "
                "length=3 truncated=0 bytes=31c0c3",
                "SCHEMA_RESOLUTION tick_ms=2 process=3 thread=4 "
                "type_id=0x014d target_rva=0x200 resolved_rva=0x180 "
                "object_adjustment=32 steps=1",
                "SCHEMA_HELPER_CODE tick_ms=2 process=3 thread=4 "
                "target_rva=0x223dac0 function_rva=0x223dac0 "
                "function_end_rva=0x223dac3 length=3 truncated=0 bytes=31c0c3",
                "SCHEMA_HELPER_CODE tick_ms=2 process=3 thread=4 "
                "target_rva=0x223d6a0 resolved_rva=0x2237290 "
                "object_adjustment=0 steps=1 function_rva=0x2237290 "
                "function_end_rva=0x2237293 length=3 truncated=0 bytes=31c0c3",
                "SCHEMA_NESTED_CODE tick_ms=2 process=3 thread=4 "
                "root_rva=0xc47de0 depth=0 target_rva=0xc47de0 "
                "function_rva=0xc47de0 function_end_rva=0xc47de3 "
                "length=3 truncated=0 bytes=31c0c3",
                "SCHEMA_NESTED_FORWARD_CODE tick_ms=2 process=3 thread=4 "
                "root_rva=0xc47de0 window_start_rva=0xc47de0 "
                "window_end_rva=0xc47de3 length=3 bytes=31c0c3",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            events, targets, code, counts, errors = ANALYZER["parse_log"](path)
            resolutions, helpers, nested, nested_forward = ANALYZER[
                "parse_extended_log"
            ](path)

        self.assertEqual(events[0].type_id, 0x14D)
        self.assertEqual(events[0].local_cursor, 10)
        self.assertIn((0x14D, 0x200), targets)
        self.assertEqual(code[(0x14D, 0x200)].data, bytes.fromhex("31c0c3"))
        self.assertEqual(counts["SCHEMA_EVENT"], 1)
        self.assertEqual(errors, [])
        self.assertEqual(resolutions[(0x14D, 0x200)].resolved_rva, 0x180)
        self.assertEqual(resolutions[(0x14D, 0x200)].object_adjustment, 32)
        self.assertEqual(helpers[0x223DAC0].data, bytes.fromhex("31c0c3"))
        self.assertIsNone(helpers[0x223DAC0].resolved_rva)
        self.assertEqual(helpers[0x223D6A0].resolved_rva, 0x2237290)
        self.assertEqual(
            nested[(0xC47DE0, 0, 0xC47DE0)].data,
            bytes.fromhex("31c0c3"),
        )
        self.assertEqual(
            nested_forward[0xC47DE0].data,
            bytes.fromhex("31c0c3"),
        )

    def test_rejects_nested_forward_range_mismatch(self) -> None:
        log = (
            "SCHEMA_NESTED_FORWARD_CODE tick_ms=2 process=3 thread=4 "
            "root_rva=0xc47de0 window_start_rva=0xc47de0 "
            "window_end_rva=0xc47de4 length=3 bytes=31c0c3\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "forward range mismatch"):
                ANALYZER["parse_extended_log"](path)

    def test_rejects_code_length_mismatch(self) -> None:
        log = (
            "SCHEMA_CODE tick_ms=2 process=3 thread=4 type_id=0x014d "
            "target_rva=0x200 function_rva=0x200 function_end_rva=0x203 "
            "length=4 truncated=0 bytes=31c0c3\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "byte-count mismatch"):
                ANALYZER["parse_log"](path)


if __name__ == "__main__":
    unittest.main()
