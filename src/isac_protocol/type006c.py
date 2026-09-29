"""Observed presence-mask subset codec for inbound message type 0x006c."""

from __future__ import annotations

from dataclasses import dataclass

from .codec import (
    CompactReference,
    Cursor,
    DecodeError,
    ReferenceTable,
    WireFloat32,
    decode_reference,
    encode_bool,
    encode_reference,
    encode_u8_varint,
    encode_uvarint,
    encode_vec3f,
)


Vec3f = tuple[WireFloat32, WireFloat32, WireFloat32]

# Type 0x006c has a substantially larger static schema. These are the bits
# validated in captures and their corresponding static reader branches.
SUPPORTED_MASK = sum(1 << bit for bit in (2, 12, 16, 17, 18, 26, 28, 29, 32, 35))


@dataclass(frozen=True)
class Type006CIdentifier:
    kind: int
    value: bytes


@dataclass(frozen=True)
class Type006C:
    identifier: Type006CIdentifier
    vector_bit_2: Vec3f | None = None
    references_bit_12: tuple[CompactReference, ...] | None = None
    uint16_bit_16: int | None = None
    uint8_bit_17: int | None = None
    reference_bit_18: CompactReference | None = None
    reference_bit_26: CompactReference | None = None
    floats_bit_28: Vec3f | None = None
    floats_bit_29: Vec3f | None = None
    boolean_bit_32: bool | None = None
    boolean_bit_35: bool | None = None

    @property
    def presence_mask(self) -> int:
        mask = 0
        for bit, value in (
            (2, self.vector_bit_2),
            (12, self.references_bit_12),
            (16, self.uint16_bit_16),
            (17, self.uint8_bit_17),
            (18, self.reference_bit_18),
            (26, self.reference_bit_26),
            (28, self.floats_bit_28),
            (29, self.floats_bit_29),
            (32, self.boolean_bit_32),
            (35, self.boolean_bit_35),
        ):
            if value is not None:
                mask |= 1 << bit
        return mask


def _decode_identifier(cursor: Cursor) -> Type006CIdentifier:
    kind = cursor.read_u8_varint()
    length = cursor.read_u8_varint()
    return Type006CIdentifier(kind=kind, value=cursor.read(length))


def _encode_identifier(identifier: Type006CIdentifier) -> bytes:
    return (
        encode_u8_varint(identifier.kind)
        + encode_u8_varint(len(identifier.value))
        + identifier.value
    )


def _read_float_triple(cursor: Cursor) -> Vec3f:
    return (cursor.read_float32(), cursor.read_float32(), cursor.read_float32())


def decode_type006c(data: bytes, table: ReferenceTable | None) -> Type006C:
    cursor = Cursor(data)
    mask = cursor.read_uvarint(maximum_bits=64)
    identifier = _decode_identifier(cursor)
    unsupported = mask & ~SUPPORTED_MASK
    if unsupported:
        raise DecodeError(f"unsupported type 0x006c presence bits {unsupported:#x}")

    vector_bit_2 = cursor.read_vec3f() if mask & (1 << 2) else None

    references_bit_12 = None
    if mask & (1 << 12):
        count = cursor.read_u8_varint()
        references_bit_12 = tuple(decode_reference(cursor, table) for _ in range(count))

    # This is the deserializer's actual field order, which is not numerical bit
    # order for the complete schema.
    floats_bit_28 = _read_float_triple(cursor) if mask & (1 << 28) else None
    floats_bit_29 = _read_float_triple(cursor) if mask & (1 << 29) else None
    uint16_bit_16 = (
        cursor.read_uvarint(maximum_bits=16) if mask & (1 << 16) else None
    )
    uint8_bit_17 = cursor.read_u8_varint() if mask & (1 << 17) else None
    reference_bit_18 = (
        decode_reference(cursor, table) if mask & (1 << 18) else None
    )
    reference_bit_26 = (
        decode_reference(cursor, table) if mask & (1 << 26) else None
    )
    boolean_bit_32 = cursor.read_bool() if mask & (1 << 32) else None
    boolean_bit_35 = cursor.read_bool() if mask & (1 << 35) else None

    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x006c")

    return Type006C(
        identifier=identifier,
        vector_bit_2=vector_bit_2,
        references_bit_12=references_bit_12,
        uint16_bit_16=uint16_bit_16,
        uint8_bit_17=uint8_bit_17,
        reference_bit_18=reference_bit_18,
        reference_bit_26=reference_bit_26,
        floats_bit_28=floats_bit_28,
        floats_bit_29=floats_bit_29,
        boolean_bit_32=boolean_bit_32,
        boolean_bit_35=boolean_bit_35,
    )


def encode_type006c(message: Type006C, table: ReferenceTable | None) -> bytes:
    mask = message.presence_mask
    encoded = bytearray(encode_uvarint(mask, maximum_bits=64))
    encoded.extend(_encode_identifier(message.identifier))

    if message.vector_bit_2 is not None:
        encoded.extend(encode_vec3f(message.vector_bit_2))
    if message.references_bit_12 is not None:
        encoded.extend(encode_u8_varint(len(message.references_bit_12)))
        for reference in message.references_bit_12:
            encoded.extend(encode_reference(reference, table))
    if message.floats_bit_28 is not None:
        encoded.extend(encode_vec3f(message.floats_bit_28))
    if message.floats_bit_29 is not None:
        encoded.extend(encode_vec3f(message.floats_bit_29))
    if message.uint16_bit_16 is not None:
        encoded.extend(encode_uvarint(message.uint16_bit_16, maximum_bits=16))
    if message.uint8_bit_17 is not None:
        encoded.extend(encode_u8_varint(message.uint8_bit_17))
    if message.reference_bit_18 is not None:
        encoded.extend(encode_reference(message.reference_bit_18, table))
    if message.reference_bit_26 is not None:
        encoded.extend(encode_reference(message.reference_bit_26, table))
    if message.boolean_bit_32 is not None:
        encoded.extend(encode_bool(message.boolean_bit_32))
    if message.boolean_bit_35 is not None:
        encoded.extend(encode_bool(message.boolean_bit_35))

    return bytes(encoded)
