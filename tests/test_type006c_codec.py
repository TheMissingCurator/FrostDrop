#!/usr/bin/env python3
"""Tests for the observed type 0x006c presence-mask subset."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    CompactReference,
    DecodeError,
    ReferenceTable,
    Type006C,
    Type006CIdentifier,
    WireFloat32,
    decode_type006c,
    encode_type006c,
)


def reference(token: int) -> CompactReference:
    return CompactReference(value=None, token=token)


def triple(start: int) -> tuple[WireFloat32, WireFloat32, WireFloat32]:
    return (
        WireFloat32(start),
        WireFloat32(start + 1),
        WireFloat32(start + 2),
    )


class Type006CCodecTests(unittest.TestCase):
    def test_all_observed_fields_round_trip_in_wire_order(self) -> None:
        message = Type006C(
            identifier=Type006CIdentifier(2, b"synthetic-id"),
            vector_bit_2=triple(0x3F000000),
            references_bit_12=(reference(10), reference(12)),
            uint16_bit_16=0xFFFF,
            uint8_bit_17=0xFF,
            reference_bit_18=reference(16),
            reference_bit_26=reference(14),
            floats_bit_28=triple(0x40000000),
            floats_bit_29=triple(0x40400000),
            boolean_bit_32=False,
            boolean_bit_35=True,
        )
        writer_table = ReferenceTable(assume_existing=True)
        wire = encode_type006c(message, writer_table)
        decoded = decode_type006c(wire, ReferenceTable(assume_existing=True))

        self.assertEqual(decoded, message)
        self.assertEqual(
            encode_type006c(decoded, ReferenceTable(assume_existing=True)), wire
        )

    def test_present_empty_reference_list_is_distinct_from_absent(self) -> None:
        message = Type006C(
            identifier=Type006CIdentifier(0, b""),
            references_bit_12=(),
        )
        wire = encode_type006c(message, ReferenceTable(assume_existing=True))
        decoded = decode_type006c(wire, ReferenceTable(assume_existing=True))
        self.assertEqual(decoded.references_bit_12, ())
        self.assertEqual(decoded.presence_mask, 1 << 12)

    def test_rejects_unobserved_presence_bit(self) -> None:
        wire = b"\x01\x00\x00"
        with self.assertRaisesRegex(DecodeError, "presence bits 0x1"):
            decode_type006c(wire, ReferenceTable(assume_existing=True))

    def test_rejects_identifier_longer_than_uint8(self) -> None:
        message = Type006C(Type006CIdentifier(0, bytes(256)))
        with self.assertRaisesRegex(ValueError, "unsigned 8-bit"):
            encode_type006c(message, ReferenceTable(assume_existing=True))


if __name__ == "__main__":
    unittest.main()
