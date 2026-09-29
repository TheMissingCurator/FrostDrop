#!/usr/bin/env python3
"""Focused tests for bounded plaintext-probe log parsing."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-plaintext-probe.py"))


class PlaintextAnalyzerTests(unittest.TestCase):
    def test_parses_bounded_outbound_record(self) -> None:
        log = "\n".join(
            (
                "PLAINTEXT_PROBE_READY tick_ms=1 process=2 thread=3 "
                "detail=direction=outbound,max-records=512,max-bytes=1000",
                "PLAINTEXT_OUT sequence=1 tick_ms=2 process=2 thread=3 "
                "length=4 bytes=0012aaff",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plaintext.log"
            path.write_text(log, encoding="utf-8")
            records, events, errors = ANALYZER["parse_log"](path)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].direction, "outbound")
        self.assertEqual(records[0].sequence, 1)
        self.assertEqual(records[0].data, bytes.fromhex("0012aaff"))
        self.assertEqual(events["PLAINTEXT_PROBE_READY"], 1)
        self.assertEqual(errors, [])

    def test_parses_inbound_candidate_record(self) -> None:
        log = (
            "PLAINTEXT_IN sequence=1 tick_ms=2 process=2 thread=3 "
            "length=4 bytes=03000100\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plaintext.log"
            path.write_text(log, encoding="utf-8")
            records, events, errors = ANALYZER["parse_log"](path)

        self.assertEqual(records[0].direction, "inbound")
        self.assertEqual(events["PLAINTEXT_IN"], 1)
        self.assertEqual(errors, [])

    def test_rejects_length_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plaintext.log"
            path.write_text(
                "PLAINTEXT_OUT sequence=1 tick_ms=2 process=2 thread=3 "
                "length=3 bytes=0012\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "byte-count mismatch"):
                ANALYZER["parse_log"](path)

    def test_decodes_observed_record_envelope(self) -> None:
        envelope = ANALYZER["decode_envelope"](
            bytes.fromhex("0300478a010f") + bytes(68)
        )

        self.assertIsNotNone(envelope)
        self.assertEqual(envelope.marker, 0x03)
        self.assertEqual(envelope.channel, 0x00)
        self.assertEqual(envelope.body_length, 0x47)
        self.assertEqual(len(envelope.frames), 1)
        self.assertEqual(len(envelope.frames[0].data), 69)
        self.assertEqual(envelope.frames[0].leading_value, 0x0F)

    def test_decodes_inbound_length_prefixed_frame(self) -> None:
        frame = ANALYZER["decode_frame"](
            bytes.fromhex("2acd0201") + bytes(18)
        )

        self.assertIsNotNone(frame)
        self.assertEqual(len(frame.data), 21)
        self.assertEqual(frame.leading_value, 0x14D)

    def test_rejects_inconsistent_inbound_frame_length(self) -> None:
        self.assertIsNone(ANALYZER["decode_frame"](bytes.fromhex("2acd02")))

    def test_decodes_multibyte_body_length(self) -> None:
        data = (
            bytes.fromhex("0302c702ca0304")
            + bytes(228)
            + bytes.fromhex("bc0105")
            + bytes(93)
        )
        envelope = ANALYZER["decode_envelope"](data)

        self.assertIsNotNone(envelope)
        self.assertEqual(envelope.body_length, 327)
        self.assertEqual([len(frame.data) for frame in envelope.frames], [229, 94])
        self.assertEqual(
            [frame.leading_value for frame in envelope.frames],
            [0x04, 0x05],
        )

    def test_rejects_inconsistent_envelope_length(self) -> None:
        self.assertIsNone(
            ANALYZER["decode_envelope"](bytes.fromhex("0300478a01"))
        )


if __name__ == "__main__":
    unittest.main()
