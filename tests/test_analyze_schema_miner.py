#!/usr/bin/env python3
"""Tests for schema-miner message/field correlation."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
MINER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-schema-miner.py"))
FIELDS = runpy.run_path(str(PROJECT_DIR / "tools/analyze-schema-fields.py"))


class SchemaMinerTests(unittest.TestCase):
    def test_correlates_fields_and_calculates_exact_coverage(self) -> None:
        log = "\n".join(
            (
                "SCHEMA_MESSAGE sequence=1 message_sequence=10 tick_ms=20 "
                "process=3 thread=4 type_id=0x0088 deserializer_rva=0x100 "
                "start_absolute=100 end_absolute=103 length=3 captured=3 "
                "complete=1 bytes=000102",
                "SCHEMA_FIELD sequence=1 message_sequence=10 tick_ms=19 "
                "process=3 thread=4 type_id=0x0088 deserializer_rva=0x100 "
                "helper_rva=0x223d6a0 return_rva=0x101 "
                "destination_offset=0 argument_r8=0x0 argument_r9=0x0 "
                "before_absolute=100 after_absolute=101 consumed=1 "
                "return_value=0x1 wire_captured=3 wire=000102 before= after=",
                "SCHEMA_FIELD sequence=2 message_sequence=10 tick_ms=19 "
                "process=3 thread=4 type_id=0x0088 deserializer_rva=0x100 "
                "helper_rva=0x223daf0 return_rva=0x102 "
                "destination_offset=1 argument_r8=0x0 argument_r9=0x0 "
                "before_absolute=101 after_absolute=103 consumed=2 "
                "return_value=0x1 wire_captured=2 wire=0102 before= after=",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            messages, counts, errors = MINER["parse_message_log"](path)
            fields, _, field_errors = FIELDS["parse_log"](path)
            coverage, uncorrelated = MINER["correlate"](messages, fields)
            summaries = MINER["summarize_types"](coverage)

        self.assertEqual(counts["SCHEMA_MESSAGE"], 1)
        self.assertEqual(errors + field_errors, [])
        self.assertEqual(uncorrelated, [])
        self.assertEqual(coverage[0].ranges, ((0, 3),))
        self.assertEqual(coverage[0].covered_bytes, 3)
        self.assertTrue(coverage[0].fully_accounted)
        self.assertEqual(summaries[0].fully_accounted_count, 1)

    def test_rejects_complete_body_with_short_capture(self) -> None:
        log = (
            "SCHEMA_MESSAGE sequence=1 message_sequence=10 tick_ms=20 "
            "process=3 thread=4 type_id=0x000f deserializer_rva=0x100 "
            "start_absolute=100 end_absolute=103 length=3 captured=2 "
            "complete=1 bytes=0001\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "complete message is truncated"):
                MINER["parse_message_log"](path)


if __name__ == "__main__":
    unittest.main()
