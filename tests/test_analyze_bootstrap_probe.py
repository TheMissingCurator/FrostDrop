#!/usr/bin/env python3
"""Tests for the redacted bootstrap-probe analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-bootstrap-probe.py"))


class BootstrapAnalyzerTests(unittest.TestCase):
    def test_parses_records_without_payload_bytes(self) -> None:
        log = "\n".join(
            (
                "BOOTSTRAP_PROBE_READY tick_ms=1 process=2 thread=3 "
                "detail=phase=startup,payloads=redacted",
                "BOOTSTRAP_SOCKET sequence=1 tick_ms=2 process=2 thread=3 "
                "direction=send socket_id=1 peer_port=55000",
                "BOOTSTRAP_RECORD sequence=1 tick_ms=3 process=2 thread=3 "
                "direction=outbound stream_id=1 length=20 framing=envelope "
                "marker=0x03 channel=0x00 frame_count=2 listed_frames=2 "
                "frame_types=0x0012,0x0088 frame_lengths=4,12",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plaintext.log"
            path.write_text(log, encoding="utf-8")
            records, sockets, events, errors = ANALYZER["parse_log"](path)

        self.assertEqual(records[0].frame_types, (0x12, 0x88))
        self.assertEqual(records[0].frame_lengths, (4, 12))
        self.assertEqual(records[0].channel, 0)
        self.assertEqual(sockets[0].socket_id, 1)
        self.assertEqual(events["BOOTSTRAP_PROBE_READY"], 1)
        self.assertEqual(errors, [])

    def test_parses_unrecognized_record(self) -> None:
        log = (
            "BOOTSTRAP_RECORD sequence=1 tick_ms=3 process=2 thread=3 "
            "direction=inbound stream_id=2 length=9 framing=unrecognized "
            "marker=- channel=- frame_count=0 listed_frames=0 "
            "frame_types=- frame_lengths=-\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plaintext.log"
            path.write_text(log, encoding="utf-8")
            records, _, _, _ = ANALYZER["parse_log"](path)

        self.assertEqual(records[0].framing, "unrecognized")
        self.assertEqual(records[0].frame_types, ())
        self.assertIsNone(records[0].marker)

    def test_rejects_list_count_mismatch(self) -> None:
        log = (
            "BOOTSTRAP_RECORD sequence=1 tick_ms=3 process=2 thread=3 "
            "direction=inbound stream_id=2 length=9 framing=frame "
            "marker=- channel=- frame_count=1 listed_frames=1 "
            "frame_types=0x002a frame_lengths=-\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plaintext.log"
            path.write_text(log, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "listed-frame mismatch"):
                ANALYZER["parse_log"](path)


if __name__ == "__main__":
    unittest.main()
