#!/usr/bin/env python3

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_backend import BRIDGE_REPLAY_HEADER, WorldReplay  # noqa: E402
from isac_protocol import MessageFrame, encode_length_prefixed_frame  # noqa: E402


def capture_bytes(*, gate: bool = True) -> bytes:
    frames = encode_length_prefixed_frame(MessageFrame(0x0002, b"sync"))
    if gate:
        frames += encode_length_prefixed_frame(MessageFrame(0x0012, b"gate"))
    split = 4
    wire = struct.pack("<8sIIQII", b"ISACWBS1", 1, 32, 99, 1, 0)
    wire += struct.pack("<QII", 10, split, 0x07) + frames[:split]
    wire += struct.pack("<QII", 20, len(frames) - split, 0x0E) + frames[split:]
    return wire


class WorldReplayTests(unittest.TestCase):
    def test_valid_capture_loads(self) -> None:
        replay = WorldReplay.from_bytes(capture_bytes())
        self.assertEqual(replay.duration_ms, 20)
        self.assertEqual(replay.frame_count, 2)
        self.assertEqual(replay.first_gate_frame, 2)
        self.assertEqual(len(BRIDGE_REPLAY_HEADER), 16)
        self.assertEqual(BRIDGE_REPLAY_HEADER[:8], b"ISACRPL1")

    def test_gate_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "no type 0x0012"):
            WorldReplay.from_bytes(capture_bytes(gate=False))

    def test_timestamps_must_be_monotonic(self) -> None:
        wire = bytearray(capture_bytes())
        second_record = 32 + 16 + 4
        struct.pack_into("<Q", wire, second_record, 5)
        with self.assertRaisesRegex(ValueError, "not monotonic"):
            WorldReplay.from_bytes(bytes(wire))


if __name__ == "__main__":
    unittest.main()
