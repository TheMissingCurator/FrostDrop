"""Structural codec for inbound message type 0x0088.

Names stay deliberately neutral where gameplay semantics have not yet been
proven. The ``equipped`` field is the one stable action-correlated exception.
"""

from __future__ import annotations

from dataclasses import dataclass

from .codec import (
    CompactReference,
    Cursor,
    DecodeError,
    ReferenceTable,
    WireFloat32,
    decode_reference,
    encode_reference,
    encode_svarint32,
    encode_u8_varint,
)


MAX_COLLECTION_ITEMS = 1_000_000


@dataclass(frozen=True)
class Type0088ReferenceFloatByte:
    reference: CompactReference
    float_0: WireFloat32
    byte_0: int


@dataclass(frozen=True)
class Type0088Child:
    reference_0: CompactReference
    reference_1: CompactReference
    signed_0: int
    byte_0: int
    byte_1: int
    signed_1: int
    signed_2: int
    signed_3: int
    signed_4: int
    signed_5: int
    signed_6: int
    byte_2: int
    signed_7: int
    signed_8: int
    signed_9: int
    reference_2: CompactReference
    subitems: tuple[Type0088ReferenceFloatByte, ...]
    byte_3: int
    flags: int


@dataclass(frozen=True)
class Type0088Item:
    reference_0: CompactReference
    reference_1: CompactReference
    signed_0: int
    byte_0: int
    byte_1: int
    signed_1: int
    signed_2: int
    signed_3: int
    signed_4: int
    signed_5: int
    signed_6: int
    byte_2: int
    signed_7: int
    signed_8: int
    signed_9: int
    reference_2: CompactReference
    reference_3: CompactReference
    flags: int
    children: tuple[Type0088Child, ...]
    auxiliary: tuple[Type0088ReferenceFloatByte, ...]
    trailing_byte: int
    trailing_signed: int


@dataclass(frozen=True)
class Type0088:
    signed_0: int
    equipped: int
    owner_reference: CompactReference
    item: Type0088Item


def _read_count(cursor: Cursor, name: str) -> int:
    count = cursor.read_svarint32()
    if count < 0:
        raise DecodeError(f"{name} count is negative: {count}")
    if count > MAX_COLLECTION_ITEMS:
        raise DecodeError(f"{name} count exceeds safety limit: {count}")
    return count


def _decode_reference_float_byte(
    cursor: Cursor,
    table: ReferenceTable | None,
) -> Type0088ReferenceFloatByte:
    return Type0088ReferenceFloatByte(
        reference=decode_reference(cursor, table),
        float_0=cursor.read_float32(),
        byte_0=cursor.read_u8_varint(),
    )


def _decode_child(
    cursor: Cursor,
    table: ReferenceTable | None,
) -> Type0088Child:
    reference_0 = decode_reference(cursor, table)
    reference_1 = decode_reference(cursor, table)
    signed_0 = cursor.read_svarint32()
    byte_0 = cursor.read_u8_varint()
    byte_1 = cursor.read_u8_varint()
    signed_1 = cursor.read_svarint32()
    signed_2 = cursor.read_svarint32()
    signed_3 = cursor.read_svarint32()
    signed_4 = cursor.read_svarint32()
    signed_5 = cursor.read_svarint32()
    signed_6 = cursor.read_svarint32()
    byte_2 = cursor.read_u8_varint()
    signed_7 = cursor.read_svarint32()
    signed_8 = cursor.read_svarint32()
    signed_9 = cursor.read_svarint32()
    reference_2 = decode_reference(cursor, table)
    subitem_count = _read_count(cursor, "child subitem")
    subitems = tuple(
        _decode_reference_float_byte(cursor, table)
        for _ in range(subitem_count)
    )
    byte_3 = cursor.read_u8_varint()
    flags = cursor.read_u8_varint()
    return Type0088Child(
        reference_0,
        reference_1,
        signed_0,
        byte_0,
        byte_1,
        signed_1,
        signed_2,
        signed_3,
        signed_4,
        signed_5,
        signed_6,
        byte_2,
        signed_7,
        signed_8,
        signed_9,
        reference_2,
        subitems,
        byte_3,
        flags,
    )


def decode_type0088(
    data: bytes,
    reference_table: ReferenceTable | None,
    *,
    require_complete: bool = True,
) -> Type0088:
    cursor = Cursor(data)
    signed_0 = cursor.read_svarint32()
    equipped = cursor.read_u8_varint()
    owner_reference = decode_reference(cursor, reference_table)

    item = decode_equipment_item(cursor, reference_table)
    if require_complete and cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x0088")
    return Type0088(signed_0, equipped, owner_reference, item)


def decode_equipment_item(
    cursor: Cursor,
    reference_table: ReferenceTable | None,
) -> Type0088Item:
    """Read the shared item structure (client reader RVA 0xc47de0).

    This cursor-level reader mutates its supplied reference table. Callers
    doing partial or transactional decoding must supply their own clone.
    """

    reference_0 = decode_reference(cursor, reference_table)
    reference_1 = decode_reference(cursor, reference_table)
    item_signed_0 = cursor.read_svarint32()
    byte_0 = cursor.read_u8_varint()
    byte_1 = cursor.read_u8_varint()
    signed_1 = cursor.read_svarint32()
    signed_2 = cursor.read_svarint32()
    signed_3 = cursor.read_svarint32()
    signed_4 = cursor.read_svarint32()
    signed_5 = cursor.read_svarint32()
    signed_6 = cursor.read_svarint32()
    byte_2 = cursor.read_u8_varint()
    signed_7 = cursor.read_svarint32()
    signed_8 = cursor.read_svarint32()
    signed_9 = cursor.read_svarint32()
    reference_2 = decode_reference(cursor, reference_table)
    reference_3 = decode_reference(cursor, reference_table)
    flags = cursor.read_u8_varint()
    child_count = _read_count(cursor, "child")
    children = tuple(
        _decode_child(cursor, reference_table) for _ in range(child_count)
    )
    auxiliary_count = _read_count(cursor, "auxiliary")
    auxiliary = tuple(
        _decode_reference_float_byte(cursor, reference_table)
        for _ in range(auxiliary_count)
    )
    trailing_byte = cursor.read_u8_varint()
    trailing_signed = cursor.read_svarint32()
    return Type0088Item(
        reference_0,
        reference_1,
        item_signed_0,
        byte_0,
        byte_1,
        signed_1,
        signed_2,
        signed_3,
        signed_4,
        signed_5,
        signed_6,
        byte_2,
        signed_7,
        signed_8,
        signed_9,
        reference_2,
        reference_3,
        flags,
        children,
        auxiliary,
        trailing_byte,
        trailing_signed,
    )


def _encode_reference_float_byte(
    value: Type0088ReferenceFloatByte,
    table: ReferenceTable | None,
) -> bytes:
    return (
        encode_reference(value.reference, table)
        + value.float_0.encode()
        + encode_u8_varint(value.byte_0)
    )


def _encode_child(
    child: Type0088Child,
    table: ReferenceTable | None,
) -> bytes:
    encoded = bytearray()
    encoded.extend(encode_reference(child.reference_0, table))
    encoded.extend(encode_reference(child.reference_1, table))
    encoded.extend(encode_svarint32(child.signed_0))
    encoded.extend(encode_u8_varint(child.byte_0))
    encoded.extend(encode_u8_varint(child.byte_1))
    for value in (
        child.signed_1,
        child.signed_2,
        child.signed_3,
        child.signed_4,
        child.signed_5,
        child.signed_6,
    ):
        encoded.extend(encode_svarint32(value))
    encoded.extend(encode_u8_varint(child.byte_2))
    for value in (child.signed_7, child.signed_8, child.signed_9):
        encoded.extend(encode_svarint32(value))
    encoded.extend(encode_reference(child.reference_2, table))
    encoded.extend(encode_svarint32(len(child.subitems)))
    for subitem in child.subitems:
        encoded.extend(_encode_reference_float_byte(subitem, table))
    encoded.extend(encode_u8_varint(child.byte_3))
    encoded.extend(encode_u8_varint(child.flags))
    return bytes(encoded)


def encode_type0088(
    message: Type0088,
    reference_table: ReferenceTable | None,
) -> bytes:
    encoded = bytearray()
    encoded.extend(encode_svarint32(message.signed_0))
    encoded.extend(encode_u8_varint(message.equipped))
    encoded.extend(encode_reference(message.owner_reference, reference_table))
    encoded.extend(encode_equipment_item(message.item, reference_table))
    return bytes(encoded)


def encode_equipment_item(
    item: Type0088Item,
    reference_table: ReferenceTable | None,
) -> bytes:
    """Encode the shared item structure, without a message 0x0088 wrapper."""
    encoded = bytearray()
    encoded.extend(encode_reference(item.reference_0, reference_table))
    encoded.extend(encode_reference(item.reference_1, reference_table))
    encoded.extend(encode_svarint32(item.signed_0))
    encoded.extend(encode_u8_varint(item.byte_0))
    encoded.extend(encode_u8_varint(item.byte_1))
    for value in (
        item.signed_1,
        item.signed_2,
        item.signed_3,
        item.signed_4,
        item.signed_5,
        item.signed_6,
    ):
        encoded.extend(encode_svarint32(value))
    encoded.extend(encode_u8_varint(item.byte_2))
    for value in (item.signed_7, item.signed_8, item.signed_9):
        encoded.extend(encode_svarint32(value))
    encoded.extend(encode_reference(item.reference_2, reference_table))
    encoded.extend(encode_reference(item.reference_3, reference_table))
    encoded.extend(encode_u8_varint(item.flags))
    encoded.extend(encode_svarint32(len(item.children)))
    for child in item.children:
        encoded.extend(_encode_child(child, reference_table))
    encoded.extend(encode_svarint32(len(item.auxiliary)))
    for auxiliary in item.auxiliary:
        encoded.extend(_encode_reference_float_byte(auxiliary, reference_table))
    encoded.extend(encode_u8_varint(item.trailing_byte))
    encoded.extend(encode_svarint32(item.trailing_signed))
    return bytes(encoded)
