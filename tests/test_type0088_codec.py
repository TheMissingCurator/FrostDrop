#!/usr/bin/env python3
"""Tests for the structural type 0x0088 codec."""

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
    Type0088,
    Type0088Child,
    Type0088Item,
    Type0088ReferenceFloatByte,
    WireFloat32,
    decode_type0088,
    encode_type0088,
)
from isac_protocol.codec import (  # noqa: E402
    Cursor,
    decode_reference,
    encode_reference,
    encode_svarint32,
    encode_u8_varint,
)


def token_reference(index: int) -> CompactReference:
    return CompactReference(value=None, token=index << 1)


def triple(index: int, bits: int, byte: int) -> Type0088ReferenceFloatByte:
    return Type0088ReferenceFloatByte(
        reference=token_reference(index),
        float_0=WireFloat32(bits),
        byte_0=byte,
    )


def child(index: int) -> Type0088Child:
    return Type0088Child(
        reference_0=token_reference(index),
        reference_1=token_reference(index + 1),
        signed_0=-123456,
        byte_0=2,
        byte_1=4,
        signed_1=-10,
        signed_2=20,
        signed_3=-30,
        signed_4=40,
        signed_5=-50,
        signed_6=60,
        byte_2=7,
        signed_7=-70,
        signed_8=80,
        signed_9=-90,
        reference_2=token_reference(index + 2),
        subitems=(triple(index + 3, 0x7FC01234, 9),),
        byte_3=11,
        flags=0x1B,
    )


def message() -> Type0088:
    return Type0088(
        signed_0=-1,
        equipped=1,
        owner_reference=token_reference(200),
        item=Type0088Item(
            reference_0=token_reference(201),
            reference_1=token_reference(202),
            signed_0=0x1234567,
            byte_0=2,
            byte_1=4,
            signed_1=9,
            signed_2=4,
            signed_3=-1,
            signed_4=17,
            signed_5=0,
            signed_6=4,
            byte_2=0,
            signed_7=-1,
            signed_8=1,
            signed_9=0,
            reference_2=token_reference(5),
            reference_3=token_reference(5),
            flags=0x15,
            children=(child(210), child(220)),
            auxiliary=(
                triple(230, 0x3F800000, 1),
                triple(231, 0x80000000, 255),
            ),
            trailing_byte=3,
            trailing_signed=-2147483648,
        ),
    )


class Type0088CodecTests(unittest.TestCase):
    def test_round_trips_both_lists_and_nested_sublist(self) -> None:
        original = message()
        encoded = encode_type0088(
            original,
            ReferenceTable(assume_existing=True),
        )
        decoded = decode_type0088(
            encoded,
            ReferenceTable(assume_existing=True),
        )
        reencoded = encode_type0088(
            decoded,
            ReferenceTable(assume_existing=True),
        )

        self.assertEqual(decoded, original)
        self.assertEqual(reencoded, encoded)
        self.assertEqual(decoded.item.auxiliary[1].float_0.bits, 0x80000000)
        self.assertEqual(decoded.item.children[0].subitems[0].float_0.bits, 0x7FC01234)

    def test_stateful_reference_table_add_and_reuse(self) -> None:
        value = bytes(range(16))
        writer_table = ReferenceTable()
        first = encode_reference(CompactReference(value=value), writer_table)
        second = encode_reference(CompactReference(value=value), writer_table)

        self.assertEqual(first, b"\x00" + value)
        self.assertEqual(second, b"\x00")

        reader_table = ReferenceTable()
        first_decoded = decode_reference(Cursor(first), reader_table)
        second_decoded = decode_reference(Cursor(second), reader_table)
        self.assertEqual(first_decoded.value, value)
        self.assertEqual(second_decoded.value, value)
        self.assertEqual(reader_table.entries, [value])

    def test_existing_odd_reference_token_preserves_side_value(self) -> None:
        side_value = bytes(reversed(range(16)))
        wire = b"\x07" + side_value
        table = ReferenceTable(assume_existing=True)
        decoded = decode_reference(Cursor(wire), table)

        self.assertEqual(decoded.index, 3)
        self.assertTrue(decoded.has_side_value)
        self.assertEqual(decoded.side_value, side_value)
        self.assertEqual(encode_reference(decoded, table), wire)

    def test_rejects_negative_collection_count(self) -> None:
        original = message()
        minimal = replace(
            original,
            item=replace(original.item, children=(), auxiliary=()),
        )
        encoded = encode_type0088(
            minimal,
            ReferenceTable(assume_existing=True),
        )
        suffix = (
            encode_svarint32(0)
            + encode_svarint32(0)
            + encode_u8_varint(minimal.item.trailing_byte)
            + encode_svarint32(minimal.item.trailing_signed)
        )
        self.assertTrue(encoded.endswith(suffix))
        negative_child_count = (
            encoded[: -len(suffix)]
            + encode_svarint32(-1)
            + suffix[1:]
        )

        with self.assertRaisesRegex(DecodeError, "child count is negative"):
            decode_type0088(
                negative_child_count,
                ReferenceTable(assume_existing=True),
            )


if __name__ == "__main__":
    unittest.main()
