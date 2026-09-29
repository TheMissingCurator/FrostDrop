#!/usr/bin/env python3
"""Tests for simple message codecs promoted from broad-miner schemas."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    CompactReference,
    ReferenceTable,
    Type0020,
    Type0024,
    Type002D,
    Type0067,
    Type019D,
    WireFloat32,
    decode_type0020,
    decode_type0024,
    decode_type002d,
    decode_type0067,
    decode_type019d,
    encode_type0020,
    encode_type0024,
    encode_type002d,
    encode_type0067,
    encode_type019d,
)


def reference(index: int = 7) -> CompactReference:
    return CompactReference(value=None, token=index << 1)


class SimpleMessageCodecTests(unittest.TestCase):
    def round_trip(self, message: object, encoder: object, decoder: object) -> None:
        encoded = encoder(message, ReferenceTable(assume_existing=True))
        decoded = decoder(encoded, ReferenceTable(assume_existing=True))
        reencoded = encoder(decoded, ReferenceTable(assume_existing=True))
        self.assertEqual(decoded, message)
        self.assertEqual(reencoded, encoded)

    def test_type0024(self) -> None:
        self.round_trip(
            Type0024(reference(), b"Ready\x00\xff", 3, 0),
            encode_type0024,
            decode_type0024,
        )

    def test_type0067(self) -> None:
        self.round_trip(
            Type0067(
                reference(),
                (
                    WireFloat32(0x3F800000),
                    WireFloat32(0x80000000),
                    WireFloat32(0x7FC01234),
                ),
                WireFloat32(0xBF000000),
            ),
            encode_type0067,
            decode_type0067,
        )

    def test_type019d(self) -> None:
        self.round_trip(
            Type019D(-2147483648, reference()),
            encode_type019d,
            decode_type019d,
        )

    def test_type0020(self) -> None:
        self.round_trip(
            Type0020(reference(), 255),
            encode_type0020,
            decode_type0020,
        )

    def test_type002d(self) -> None:
        self.round_trip(
            Type002D(reference(), -42, WireFloat32(0x7F800000)),
            encode_type002d,
            decode_type002d,
        )


if __name__ == "__main__":
    unittest.main()
