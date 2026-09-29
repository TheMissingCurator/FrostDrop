"""Structural codec for inbound message type 0x002a."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .codec import (
    CompactReference,
    Cursor,
    DecodeError,
    ReferenceTable,
    decode_reference,
    encode_reference,
    encode_svarint32,
)


@dataclass(frozen=True)
class Type002ATail:
    """Conditional tail present when ``Type002A.signed_5`` is nonzero.

    The client reads the four-byte and one-byte fields directly rather than
    through one of the instrumented primitive helpers. Their wire widths and
    byte order are established; their semantic types remain deliberately
    neutral.
    """

    fixed_u32_0: int
    signed_6: int
    signed_7: int
    fixed_u8_0: int
    reference_2: CompactReference


@dataclass(frozen=True)
class Type002A:
    reference_0: CompactReference
    reference_1: CompactReference
    signed_0: int
    signed_1: int
    signed_2: int
    signed_3: int
    signed_4: int
    signed_5: int
    tail: Type002ATail | None = None


def _read_fixed_u32(cursor: Cursor) -> int:
    return struct.unpack("<I", cursor.read(4))[0]


def _encode_fixed_u32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("fixed u32 value must fit in 32 bits")
    return struct.pack("<I", value)


def _read_fixed_u8(cursor: Cursor) -> int:
    return cursor.read(1)[0]


def _encode_fixed_u8(value: int) -> bytes:
    if value < 0 or value > 0xFF:
        raise ValueError("fixed u8 value must fit in 8 bits")
    return bytes((value,))


def decode_type002a(data: bytes, table: ReferenceTable | None) -> Type002A:
    cursor = Cursor(data)
    reference_0 = decode_reference(cursor, table)
    reference_1 = decode_reference(cursor, table)
    signed_values = tuple(cursor.read_svarint32() for _ in range(6))

    tail = None
    if signed_values[5] != 0:
        tail = Type002ATail(
            fixed_u32_0=_read_fixed_u32(cursor),
            signed_6=cursor.read_svarint32(),
            signed_7=cursor.read_svarint32(),
            fixed_u8_0=_read_fixed_u8(cursor),
            reference_2=decode_reference(cursor, table),
        )

    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x002a")

    return Type002A(
        reference_0=reference_0,
        reference_1=reference_1,
        signed_0=signed_values[0],
        signed_1=signed_values[1],
        signed_2=signed_values[2],
        signed_3=signed_values[3],
        signed_4=signed_values[4],
        signed_5=signed_values[5],
        tail=tail,
    )


def encode_type002a(message: Type002A, table: ReferenceTable | None) -> bytes:
    expects_tail = message.signed_5 != 0
    if expects_tail != (message.tail is not None):
        requirement = "requires" if expects_tail else "forbids"
        raise ValueError(f"signed_5={message.signed_5} {requirement} a type 0x002a tail")

    encoded = bytearray()
    encoded.extend(encode_reference(message.reference_0, table))
    encoded.extend(encode_reference(message.reference_1, table))
    for value in (
        message.signed_0,
        message.signed_1,
        message.signed_2,
        message.signed_3,
        message.signed_4,
        message.signed_5,
    ):
        encoded.extend(encode_svarint32(value))

    if message.tail is not None:
        encoded.extend(_encode_fixed_u32(message.tail.fixed_u32_0))
        encoded.extend(encode_svarint32(message.tail.signed_6))
        encoded.extend(encode_svarint32(message.tail.signed_7))
        encoded.extend(_encode_fixed_u8(message.tail.fixed_u8_0))
        encoded.extend(encode_reference(message.tail.reference_2, table))

    return bytes(encoded)
