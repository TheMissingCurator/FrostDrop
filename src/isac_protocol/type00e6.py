"""Structural codec for observed inbound world message 0x00e6.

Names describe wire order and client memory offsets, not mission semantics.
The reader follows the analyzed-build deserializers at 0x178f2c0,
0x178cd80 and 0x1795e20. Only bounded, canonical observed shapes are
accepted; this codec is not a complete client-acceptance model.
"""

from __future__ import annotations

from dataclasses import dataclass

from .codec import (
    CompactReference, Cursor, DecodeError, ReferenceTable, WireFloat32,
    decode_reference, encode_bool, encode_reference, encode_svarint32,
    encode_u8_varint, encode_uvarint, encode_vec3f,
)


Vec3f = tuple[WireFloat32, WireFloat32, WireFloat32]
MAX_ROWS = 128
MAX_NESTED_ROWS = 128
MAX_TAIL_ROWS = 128


@dataclass(frozen=True)
class Type00E6SubRow:
    reference_0: CompactReference
    vector_0: Vec3f
    signed_0: int
    boolean_0: bool


@dataclass(frozen=True)
class Type00E6Row:
    signed_0_2: tuple[int, int, int]
    booleans_0_1: tuple[bool, bool]
    float_0: WireFloat32
    boolean_2: bool
    float_1: WireFloat32
    reference_0: CompactReference
    subrows: tuple[Type00E6SubRow, ...]
    signed8_40: int


@dataclass(frozen=True)
class Type00E6Group:
    reference_0: CompactReference
    children: tuple[tuple[CompactReference, int], ...]


@dataclass(frozen=True)
class Type00E6:
    reference_0: CompactReference
    reference_1: CompactReference
    signed_54_58_5c: tuple[int, int, int]
    boolean_60: bool
    packed_61_63: int
    byte_64: int
    rows_20: tuple[Type00E6Row, ...]
    unsigned64_40_48: tuple[int, int]
    float_50: WireFloat32
    vector_30: Vec3f
    unsigned32_68: int
    unsigned32_6c_7c: tuple[int, int, int, int, int]
    unsigned32_80: int
    unsigned16_84: int
    byte_86: int
    reference_signed_88: tuple[tuple[CompactReference, int], ...]
    groups_98: tuple[Type00E6Group, ...]
    boolean_a8: bool
    byte_a9: int
    boolean_aa: bool
    boolean_ab: bool
    reference_b0: CompactReference


def _bool8(cursor: Cursor) -> bool:
    value = cursor.read_u8_varint()
    if value not in (0, 1):
        raise DecodeError('noncanonical type 0x00e6 boolean')
    return bool(value)


def _count(cursor: Cursor, maximum: int) -> int:
    value = cursor.read_svarint32()
    if not 0 <= value <= maximum:
        raise DecodeError('type 0x00e6 collection count outside observed bound')
    return value


def _count8(cursor: Cursor, maximum: int) -> int:
    value = cursor.read_u8_varint()
    if value > maximum:
        raise DecodeError('type 0x00e6 collection count outside observed bound')
    return value


def _signed8(cursor: Cursor) -> int:
    value = cursor.read_uvarint(maximum_bits=8)
    return (value >> 1) ^ -(value & 1)


def _encode_signed8(value: int) -> bytes:
    if not -128 <= value <= 127:
        raise ValueError('type 0x00e6 signed8 outside range')
    return encode_u8_varint((value << 1) ^ (value >> 7))


def _decode(data: bytes, table: ReferenceTable | None) -> Type00E6:
    cursor = Cursor(data)
    reference_0 = decode_reference(cursor, table)
    reference_1 = decode_reference(cursor, table)
    signed = tuple(cursor.read_svarint32() for _ in range(3))
    boolean_60 = _bool8(cursor)
    packed = cursor.read_u8_varint()
    byte_64 = cursor.read_u8_varint()
    rows = []
    for _ in range(_count(cursor, MAX_ROWS)):
        row_signed = tuple(cursor.read_svarint32() for _ in range(3))
        row_booleans = (_bool8(cursor), _bool8(cursor))
        float_0 = cursor.read_float32()
        boolean_2 = _bool8(cursor)
        float_1 = cursor.read_float32()
        row_ref = decode_reference(cursor, table)
        subrows = []
        for _ in range(_count(cursor, MAX_NESTED_ROWS)):
            subrows.append(Type00E6SubRow(
                decode_reference(cursor, table), cursor.read_vec3f(),
                cursor.read_svarint32(), _bool8(cursor)))
        rows.append(Type00E6Row(row_signed, row_booleans, float_0,
                                boolean_2, float_1, row_ref,
                                tuple(subrows), _signed8(cursor)))
    unsigned64 = (cursor.read_uvarint(maximum_bits=64),
                  cursor.read_uvarint(maximum_bits=64))
    float_50 = cursor.read_float32()
    vector_30 = cursor.read_vec3f()
    unsigned32_68 = cursor.read_uvarint(maximum_bits=32)
    unsigned32_6c_7c = tuple(cursor.read_uvarint(maximum_bits=32)
                                for _ in range(5))
    unsigned32_80 = cursor.read_uvarint(maximum_bits=32)
    unsigned16_84 = cursor.read_uvarint(maximum_bits=16)
    byte_86 = cursor.read_u8_varint()
    reference_signed = tuple(
        (decode_reference(cursor, table), cursor.read_svarint32())
        for _ in range(_count8(cursor, MAX_TAIL_ROWS))
    )
    groups = []
    for _ in range(_count8(cursor, MAX_TAIL_ROWS)):
        group_ref = decode_reference(cursor, table)
        children = tuple((decode_reference(cursor, table), cursor.read_svarint32())
                         for _ in range(_count8(cursor, MAX_TAIL_ROWS)))
        groups.append(Type00E6Group(group_ref, children))
    result = Type00E6(
        reference_0, reference_1, signed, boolean_60, packed, byte_64,
        tuple(rows), unsigned64, float_50, vector_30, unsigned32_68,
        unsigned32_6c_7c, unsigned32_80, unsigned16_84, byte_86,
        reference_signed, tuple(groups), _bool8(cursor),
        cursor.read_u8_varint(), _bool8(cursor), _bool8(cursor),
        decode_reference(cursor, table))
    if cursor.remaining:
        raise DecodeError(f'{cursor.remaining} trailing bytes after type 0x00e6')
    return result


def decode_type00e6(data: bytes, table: ReferenceTable | None) -> Type00E6:
    if len(data) > 65536:
        raise DecodeError('type 0x00e6 body exceeds safety bound')
    working = table.clone() if table is not None else None
    value = _decode(data, working)
    # Reject noncanonical varints/booleans without changing caller dictionary.
    if _encode(value, table.clone() if table is not None else None) != data:
        raise DecodeError('noncanonical type 0x00e6 body')
    if table is not None:
        table.entries[:] = working.entries
    return value


def _encode(value: Type00E6, table: ReferenceTable | None) -> bytes:
    if len(value.rows_20) > MAX_ROWS or len(value.reference_signed_88) > MAX_TAIL_ROWS \
            or len(value.groups_98) > MAX_TAIL_ROWS:
        raise ValueError('type 0x00e6 collection exceeds bound')
    body = bytearray()
    body += encode_reference(value.reference_0, table)
    body += encode_reference(value.reference_1, table)
    for number in value.signed_54_58_5c:
        body += encode_svarint32(number)
    body += encode_bool(value.boolean_60)
    body += encode_u8_varint(value.packed_61_63)
    body += encode_u8_varint(value.byte_64)
    body += encode_svarint32(len(value.rows_20))
    for row in value.rows_20:
        if len(row.subrows) > MAX_NESTED_ROWS:
            raise ValueError('type 0x00e6 nested collection exceeds bound')
        for number in row.signed_0_2:
            body += encode_svarint32(number)
        for flag in row.booleans_0_1:
            body += encode_bool(flag)
        body += row.float_0.encode()
        body += encode_bool(row.boolean_2)
        body += row.float_1.encode()
        body += encode_reference(row.reference_0, table)
        body += encode_svarint32(len(row.subrows))
        for subrow in row.subrows:
            body += encode_reference(subrow.reference_0, table)
            body += encode_vec3f(subrow.vector_0)
            body += encode_svarint32(subrow.signed_0)
            body += encode_bool(subrow.boolean_0)
        body += _encode_signed8(row.signed8_40)
    for number in value.unsigned64_40_48:
        body += encode_uvarint(number, maximum_bits=64)
    body += value.float_50.encode()
    body += encode_vec3f(value.vector_30)
    body += encode_uvarint(value.unsigned32_68, maximum_bits=32)
    for number in value.unsigned32_6c_7c:
        body += encode_uvarint(number, maximum_bits=32)
    body += encode_uvarint(value.unsigned32_80, maximum_bits=32)
    body += encode_uvarint(value.unsigned16_84, maximum_bits=16)
    body += encode_u8_varint(value.byte_86)
    body += encode_u8_varint(len(value.reference_signed_88))
    for ref, number in value.reference_signed_88:
        body += encode_reference(ref, table)
        body += encode_svarint32(number)
    body += encode_u8_varint(len(value.groups_98))
    for group in value.groups_98:
        if len(group.children) > MAX_TAIL_ROWS:
            raise ValueError('type 0x00e6 group exceeds bound')
        body += encode_reference(group.reference_0, table)
        body += encode_u8_varint(len(group.children))
        for ref, number in group.children:
            body += encode_reference(ref, table)
            body += encode_svarint32(number)
    body += encode_bool(value.boolean_a8)
    body += encode_u8_varint(value.byte_a9)
    body += encode_bool(value.boolean_aa)
    body += encode_bool(value.boolean_ab)
    body += encode_reference(value.reference_b0, table)
    return bytes(body)


def encode_type00e6(value: Type00E6, table: ReferenceTable | None) -> bytes:
    working = table.clone() if table is not None else None
    body = _encode(value, working)
    if len(body) > 65536:
        raise ValueError('type 0x00e6 body exceeds safety bound')
    if table is not None:
        table.entries[:] = working.entries
    return body
