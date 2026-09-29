#!/usr/bin/env python3
"""Tests for the branch-aware type 0x0023 codec."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    CompactReference,
    ReferenceTable,
    Type0023,
    Type0023Tail,
    WireFloat32,
    decode_type0023,
    encode_type0023,
)


def reference(token: int) -> CompactReference:
    return CompactReference(value=None, token=token)


class Type0023CodecTests(unittest.TestCase):
    def assert_wire_round_trip(self, hexadecimal: str) -> Type0023:
        wire = bytes.fromhex(hexadecimal)
        decoded = decode_type0023(wire, ReferenceTable(assume_existing=True))
        encoded = encode_type0023(decoded, ReferenceTable(assume_existing=True))
        self.assertEqual(encoded, wire)
        return decoded

    def test_stop_variant(self) -> None:
        message = self.assert_wire_round_trip("c02f0000")
        self.assertEqual((message.byte_0, message.discriminator), (0, 0))
        self.assertIsNone(message.tail)

    def test_reference_variant_with_metadata(self) -> None:
        message = self.assert_wire_round_trip(
            "c02f00018a0601e807000096420000704200000040"
        )
        self.assertEqual(message.reference_1, reference(778))
        self.assertEqual(message.tail.boolean_0, True)
        self.assertEqual(message.tail.signed_0, 500)

    def test_vector_variant_with_metadata(self) -> None:
        message = self.assert_wire_round_trip(
            "c02f00024f236ac474c2953fd000e64301e807000096420000704200000040"
        )
        self.assertIsNotNone(message.vector_0)
        self.assertEqual(message.tail.signed_0, 500)

    def test_nonzero_byte_omits_metadata(self) -> None:
        message = self.assert_wire_round_trip(
            "b03001018a06000070420000704200000000"
        )
        self.assertEqual(message.byte_0, 1)
        self.assertIsNone(message.tail.boolean_0)
        self.assertIsNone(message.tail.signed_0)

    def test_other_discriminator_has_only_common_tail(self) -> None:
        message = Type0023(
            reference_0=reference(2),
            byte_0=1,
            discriminator=3,
            tail=Type0023Tail(
                boolean_0=None,
                signed_0=None,
                float_0=WireFloat32(0),
                float_1=WireFloat32(0x80000000),
                float_2=WireFloat32(0x7FC01234),
            ),
        )
        wire = encode_type0023(message, ReferenceTable(assume_existing=True))
        self.assertEqual(
            decode_type0023(wire, ReferenceTable(assume_existing=True)), message
        )

    def test_signed64_minimum_round_trips(self) -> None:
        message = Type0023(
            reference_0=reference(2),
            byte_0=0,
            discriminator=3,
            tail=Type0023Tail(
                boolean_0=False,
                signed_0=-(1 << 63),
                float_0=WireFloat32(0),
                float_1=WireFloat32(0),
                float_2=WireFloat32(0),
            ),
        )
        wire = encode_type0023(message, ReferenceTable(assume_existing=True))
        self.assertEqual(
            decode_type0023(wire, ReferenceTable(assume_existing=True)), message
        )

    def test_rejects_missing_reference_variant(self) -> None:
        message = Type0023(
            reference_0=reference(2),
            byte_0=1,
            discriminator=1,
            tail=Type0023Tail(
                None,
                None,
                WireFloat32(0),
                WireFloat32(0),
                WireFloat32(0),
            ),
        )
        with self.assertRaisesRegex(ValueError, "requires only reference_1"):
            encode_type0023(message, ReferenceTable(assume_existing=True))


if __name__ == "__main__":
    unittest.main()
