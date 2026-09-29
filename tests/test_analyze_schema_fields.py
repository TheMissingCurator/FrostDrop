#!/usr/bin/env python3
"""Focused tests for schema-field log parsing."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-schema-fields.py"))


class SchemaFieldAnalyzerTests(unittest.TestCase):
    def test_parses_exact_field_record(self) -> None:
        log = (
            "SCHEMA_FIELD sequence=1 tick_ms=2 process=3 thread=4 "
            "type_id=0x0012 deserializer_rva=0x100 helper_rva=0x223dac0 "
            "return_rva=0x1234 "
            "destination_offset=32 argument_r8=0x2 argument_r9=0x0 "
            "before_absolute=50 after_absolute=52 consumed=2 "
            "return_value=0x1 wire_captured=4 wire=aabbccdd "
            "before=0001 after=aabb\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            records, counts, errors = ANALYZER["parse_log"](path)

        self.assertEqual(counts["SCHEMA_FIELD"], 1)
        self.assertEqual(errors, [])
        self.assertEqual(records[0].type_id, 0x12)
        self.assertEqual(records[0].return_rva, 0x1234)
        self.assertEqual(records[0].exact_wire, bytes.fromhex("aabb"))
        self.assertEqual(records[0].changed_offsets, (0, 1))

    def test_marks_wire_as_truncated(self) -> None:
        log = (
            "SCHEMA_FIELD sequence=1 tick_ms=2 process=3 thread=4 "
            "type_id=0x0012 deserializer_rva=0x100 helper_rva=0x223dac0 "
            "destination_offset=-1 argument_r8=0x0 argument_r9=0x0 "
            "before_absolute=50 after_absolute=90 consumed=40 "
            "return_value=0x1 wire_captured=2 wire=aabb before= after=\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            records, _, _ = ANALYZER["parse_log"](path)

        self.assertIsNone(records[0].exact_wire)
        self.assertIsNone(records[0].return_rva)


if __name__ == "__main__":
    unittest.main()
