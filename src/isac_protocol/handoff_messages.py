"""Bounded structural decoders for retail tutorial handoff messages.

These do not assign gameplay meaning to the recovered fields. In particular,
the component payload of 0x015a/0x015b remains opaque and must not be used
as a standalone backend response.
"""

from __future__ import annotations

from dataclasses import dataclass

from .codec import Cursor, DecodeError, encode_bool, encode_svarint32, encode_uvarint


@dataclass(frozen=True)
class Type01AE:
    signed_first: tuple[int, int, int]
    signed_second: tuple[int, int, int]
    flags: tuple[bool, bool]


def decode_type01ae(body: bytes) -> Type01AE:
    cursor = Cursor(body)
    value = Type01AE(
        tuple(cursor.read_svarint32() for _ in range(3)),
        tuple(cursor.read_svarint32() for _ in range(3)),
        (cursor.read_bool(), cursor.read_bool()),
    )
    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x01ae")
    return value


def encode_type01ae(value: Type01AE) -> bytes:
    if len(value.signed_first) != 3 or len(value.signed_second) != 3 or len(value.flags) != 2:
        raise ValueError("type 0x01ae requires six signed values and two flags")
    return (
        b"".join(encode_svarint32(item) for item in value.signed_first + value.signed_second)
        + b"".join(encode_bool(flag) for flag in value.flags)
    )


@dataclass(frozen=True)
class Type015ABPrefix:
    """Shared confirmed prefix; the polymorphic component stream is unknown."""

    signed_360: int
    component_presence_mask: int
    opaque_components: bytes


def decode_type015ab_prefix(body: bytes) -> Type015ABPrefix:
    cursor = Cursor(body)
    signed = cursor.read_svarint32()
    mask = cursor.read_uvarint(maximum_bits=32)
    return Type015ABPrefix(signed, mask, cursor.read(cursor.remaining))


def encode_type015ab_prefix(value: Type015ABPrefix) -> bytes:
    return (
        encode_svarint32(value.signed_360)
        + encode_uvarint(value.component_presence_mask, maximum_bits=32)
        + value.opaque_components
    )
