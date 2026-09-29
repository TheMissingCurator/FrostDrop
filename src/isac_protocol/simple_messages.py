"""Complete neutral codecs for simple schemas found by the broad miner."""

from __future__ import annotations

from dataclasses import dataclass

from .codec import (
    CompactReference,
    Cursor,
    DecodeError,
    ReferenceTable,
    WireFloat32,
    decode_reference,
    encode_length_prefixed_bytes,
    encode_reference,
    encode_svarint32,
    encode_u8_varint,
    encode_vec3f,
)


Vec3f = tuple[WireFloat32, WireFloat32, WireFloat32]


@dataclass(frozen=True)
class Type0024:
    reference_0: CompactReference
    bytes_0: bytes
    byte_0: int
    byte_1: int


@dataclass(frozen=True)
class Type0067:
    reference_0: CompactReference
    vector_0: Vec3f
    float_0: WireFloat32


@dataclass(frozen=True)
class Type019D:
    signed_0: int
    reference_0: CompactReference


@dataclass(frozen=True)
class Type0020:
    reference_0: CompactReference
    byte_0: int


@dataclass(frozen=True)
class Type002D:
    reference_0: CompactReference
    signed_0: int
    float_0: WireFloat32


def _complete(cursor: Cursor, type_id: int) -> None:
    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type {type_id:#06x}")


def decode_type0024(data: bytes, table: ReferenceTable | None) -> Type0024:
    cursor = Cursor(data)
    result = Type0024(
        reference_0=decode_reference(cursor, table),
        bytes_0=cursor.read_length_prefixed_bytes(),
        byte_0=cursor.read_u8_varint(),
        byte_1=cursor.read_u8_varint(),
    )
    _complete(cursor, 0x0024)
    return result


def encode_type0024(message: Type0024, table: ReferenceTable | None) -> bytes:
    return (
        encode_reference(message.reference_0, table)
        + encode_length_prefixed_bytes(message.bytes_0)
        + encode_u8_varint(message.byte_0)
        + encode_u8_varint(message.byte_1)
    )


def decode_type0067(data: bytes, table: ReferenceTable | None) -> Type0067:
    cursor = Cursor(data)
    result = Type0067(
        reference_0=decode_reference(cursor, table),
        vector_0=cursor.read_vec3f(),
        float_0=cursor.read_float32(),
    )
    _complete(cursor, 0x0067)
    return result


def encode_type0067(message: Type0067, table: ReferenceTable | None) -> bytes:
    return (
        encode_reference(message.reference_0, table)
        + encode_vec3f(message.vector_0)
        + message.float_0.encode()
    )


def decode_type019d(data: bytes, table: ReferenceTable | None) -> Type019D:
    cursor = Cursor(data)
    result = Type019D(
        signed_0=cursor.read_svarint32(),
        reference_0=decode_reference(cursor, table),
    )
    _complete(cursor, 0x019D)
    return result


def encode_type019d(message: Type019D, table: ReferenceTable | None) -> bytes:
    return encode_svarint32(message.signed_0) + encode_reference(
        message.reference_0, table
    )


def decode_type0020(data: bytes, table: ReferenceTable | None) -> Type0020:
    cursor = Cursor(data)
    result = Type0020(
        reference_0=decode_reference(cursor, table),
        byte_0=cursor.read_u8_varint(),
    )
    _complete(cursor, 0x0020)
    return result


def encode_type0020(message: Type0020, table: ReferenceTable | None) -> bytes:
    return encode_reference(message.reference_0, table) + encode_u8_varint(
        message.byte_0
    )


def decode_type002d(data: bytes, table: ReferenceTable | None) -> Type002D:
    cursor = Cursor(data)
    result = Type002D(
        reference_0=decode_reference(cursor, table),
        signed_0=cursor.read_svarint32(),
        float_0=cursor.read_float32(),
    )
    _complete(cursor, 0x002D)
    return result


def encode_type002d(message: Type002D, table: ReferenceTable | None) -> bytes:
    return (
        encode_reference(message.reference_0, table)
        + encode_svarint32(message.signed_0)
        + message.float_0.encode()
    )
