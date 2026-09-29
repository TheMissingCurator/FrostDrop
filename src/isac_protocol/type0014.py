"""Structural codec for outbound world message 0x0014 in the analyzed build.

The writer at RVA 0x18a6910/0x18a3a20 and reader at 0x1791a40/0x178dc10
show two references, three signed integers, two vec3f values, one float32
and four bounded byte fields in wire order. The observed 67-byte messages
use raw 16-byte references; other dictionary contexts are not modeled here.
Names deliberately do not assign cover or mission semantics.
"""

from dataclasses import dataclass, field

from .codec import (
    CompactReference, Cursor, DecodeError, ReferenceTable, WireFloat32,
    decode_reference, encode_reference, encode_svarint32, encode_u8_varint,
    encode_vec3f,
)


Vec3f = tuple[WireFloat32, WireFloat32, WireFloat32]


@dataclass(frozen=True)
class Type0014:
    reference_0: bytes = field(repr=False)
    signed_0: int
    reference_1: bytes = field(repr=False)
    signed_1: int
    signed_2: int
    vector_0: Vec3f
    float_0: WireFloat32
    vector_1: Vec3f
    bytes_0_3: tuple[int, int, int, int]


def encode_type0014(value: Type0014) -> bytes:
    if len(value.reference_0) != 16 or len(value.reference_1) != 16:
        raise ValueError('type 0x0014 references must be 16 bytes')
    if len(value.vector_0) != 3 or len(value.vector_1) != 3:
        raise ValueError('type 0x0014 vectors must have three components')
    if len(value.bytes_0_3) != 4 or any(not 0 <= part <= 255 for part in value.bytes_0_3):
        raise ValueError('type 0x0014 byte fields invalid')
    body = (value.reference_0 + encode_svarint32(value.signed_0)
        + value.reference_1 + encode_svarint32(value.signed_1)
        + encode_svarint32(value.signed_2) + encode_vec3f(value.vector_0)
        + value.float_0.encode() + encode_vec3f(value.vector_1)
        + b''.join(encode_u8_varint(part) for part in value.bytes_0_3))
    if len(body) > 128:
        raise ValueError('type 0x0014 body exceeds observed bound')
    return body


def decode_type0014(body: bytes) -> Type0014:
    if len(body) > 128:
        raise DecodeError('type 0x0014 body exceeds observed bound')
    cursor = Cursor(body)
    value = Type0014(cursor.read(16), cursor.read_svarint32(), cursor.read(16),
        cursor.read_svarint32(), cursor.read_svarint32(), cursor.read_vec3f(),
        cursor.read_float32(), cursor.read_vec3f(),
        tuple(cursor.read_u8_varint() for _ in range(4)))
    if cursor.remaining or encode_type0014(value) != body:
        raise DecodeError('noncanonical type 0x0014 body')
    return value


def encode_type0014_compact(value: Type0014, table: ReferenceTable) -> bytes:
    """Encode the observed server echo with existing dictionary references."""
    if value.reference_0 not in table.entries or value.reference_1 not in table.entries:
        raise ValueError('type 0x0014 echo requires existing references')
    body = (encode_reference(CompactReference(value.reference_0), table)
        + encode_svarint32(value.signed_0)
        + encode_reference(CompactReference(value.reference_1), table)
        + encode_svarint32(value.signed_1) + encode_svarint32(value.signed_2)
        + encode_vec3f(value.vector_0) + value.float_0.encode()
        + encode_vec3f(value.vector_1)
        + b''.join(encode_u8_varint(part) for part in value.bytes_0_3))
    if len(body) != 39:
        raise ValueError('unexpected type 0x0014 echo size')
    return body


def decode_type0014_compact(body: bytes, table: ReferenceTable) -> Type0014:
    """Decode the 39-byte retail echo without altering the caller's table."""
    if len(body) != 39:
        raise DecodeError('unexpected type 0x0014 echo size')
    cursor = Cursor(body)
    references = [decode_reference(cursor, table.clone()).value]
    signed_0 = cursor.read_svarint32()
    references.append(decode_reference(cursor, table.clone()).value)
    if any(reference is None for reference in references):
        raise DecodeError('unresolved type 0x0014 echo reference')
    value = Type0014(references[0], signed_0, references[1], cursor.read_svarint32(),
        cursor.read_svarint32(), cursor.read_vec3f(), cursor.read_float32(),
        cursor.read_vec3f(), tuple(cursor.read_u8_varint() for _ in range(4)))
    if cursor.remaining or encode_type0014_compact(value, table.clone()) != body:
        raise DecodeError('noncanonical type 0x0014 echo')
    return value
