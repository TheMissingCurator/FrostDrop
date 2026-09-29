#!/usr/bin/env python3
"""Tests for the branch-aware type 0x002a codec."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    CompactReference,
    DecodeError,
    ReferenceTable,
    Type002A,
    Type002ATail,
    decode_type002a,
    encode_type002a,
)


def reference(token: int) -> CompactReference:
    return CompactReference(value=None, token=token)


class Type002ACodecTests(unittest.TestCase):
    def test_captured_core_form_round_trips(self) -> None:
        wire = bytes.fromhex("f82d0a00000a00d4de0100")
        message = decode_type002a(wire, ReferenceTable(assume_existing=True))

        self.assertEqual(message.reference_0.token, 5880)
        self.assertEqual(message.reference_1.token, 10)
        self.assertEqual(
            (
                message.signed_0,
                message.signed_1,
                message.signed_2,
                message.signed_3,
                message.signed_4,
                message.signed_5,
            ),
            (0, 0, 5, 0, 14250, 0),
        )
        self.assertIsNone(message.tail)
        self.assertEqual(
            encode_type002a(message, ReferenceTable(assume_existing=True)), wire
        )

    def test_captured_conditional_tail_round_trips(self) -> None:
        wire = bytes.fromhex("8a06b2305cb689021400b8850602020000001a0001b230")
        message = decode_type002a(wire, ReferenceTable(assume_existing=True))

        self.assertEqual(message.signed_5, 1)
        self.assertEqual(
            message.tail,
            Type002ATail(
                fixed_u32_0=2,
                signed_6=13,
                signed_7=0,
                fixed_u8_0=1,
                reference_2=reference(6194),
            ),
        )
        self.assertEqual(
            encode_type002a(message, ReferenceTable(assume_existing=True)), wire
        )

    def test_nonzero_selector_requires_tail(self) -> None:
        message = Type002A(
            reference_0=reference(2),
            reference_1=reference(4),
            signed_0=0,
            signed_1=0,
            signed_2=0,
            signed_3=0,
            signed_4=0,
            signed_5=1,
        )
        with self.assertRaisesRegex(ValueError, "requires"):
            encode_type002a(message, ReferenceTable(assume_existing=True))

    def test_zero_selector_forbids_tail(self) -> None:
        tail = Type002ATail(0, 0, 0, 0, reference(6))
        message = Type002A(
            reference_0=reference(2),
            reference_1=reference(4),
            signed_0=0,
            signed_1=0,
            signed_2=0,
            signed_3=0,
            signed_4=0,
            signed_5=1,
            tail=tail,
        )
        with self.assertRaisesRegex(ValueError, "forbids"):
            encode_type002a(
                replace(message, signed_5=0),
                ReferenceTable(assume_existing=True),
            )

    def test_nonzero_selector_with_truncated_tail_is_rejected(self) -> None:
        core_with_selector = bytes.fromhex("0204000000000002")
        with self.assertRaises(DecodeError):
            decode_type002a(
                core_with_selector,
                ReferenceTable(assume_existing=True),
            )


if __name__ == "__main__":
    unittest.main()
