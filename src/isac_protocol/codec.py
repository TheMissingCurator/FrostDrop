"""Wire primitives used by the Division protocol research codecs."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


class DecodeError(ValueError):
    """Raised when a wire value is malformed or incomplete."""


class Cursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read(self, length: int) -> bytes:
        if length < 0 or length > self.remaining:
            raise DecodeError(
                f"need {length} bytes at offset {self.offset}, "
                f"only {self.remaining} remain"
            )
        start = self.offset
        self.offset += length
        return self.data[start : self.offset]

    def read_uvarint(self, *, maximum_bits: int = 64) -> int:
        value = 0
        shift = 0
        maximum_bytes = (maximum_bits + 6) // 7
        for index in range(maximum_bytes):
            byte = self.read(1)[0]
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                if value >= 1 << maximum_bits:
                    raise DecodeError(
                        f"varuint exceeds {maximum_bits} bits at offset {self.offset}"
                    )
                return value
            shift += 7
        raise DecodeError(
            f"unterminated varuint at offset {self.offset - maximum_bytes}"
        )

    def read_svarint32(self) -> int:
        encoded = self.read_uvarint(maximum_bits=32)
        return (encoded >> 1) ^ -(encoded & 1)

    def read_svarint64(self) -> int:
        encoded = self.read_uvarint(maximum_bits=64)
        return (encoded >> 1) ^ -(encoded & 1)

    def read_u8_varint(self) -> int:
        return self.read_uvarint(maximum_bits=8)

    def read_bool(self) -> bool:
        return bool(self.read_uvarint(maximum_bits=32))

    def read_float32(self) -> WireFloat32:
        return WireFloat32(struct.unpack("<I", self.read(4))[0])

    def read_length_prefixed_bytes(self, *, maximum_length: int = 1_000_000) -> bytes:
        length = self.read_uvarint(maximum_bits=32)
        if length > maximum_length:
            raise DecodeError(f"byte-string length exceeds safety limit: {length}")
        return self.read(length)

    def read_vec3f(self) -> tuple[WireFloat32, WireFloat32, WireFloat32]:
        return (self.read_float32(), self.read_float32(), self.read_float32())


def encode_uvarint(value: int, *, maximum_bits: int = 64) -> bytes:
    if value < 0 or value >= 1 << maximum_bits:
        raise ValueError(f"value does not fit unsigned {maximum_bits}-bit varint")
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def encode_svarint32(value: int) -> bytes:
    if value < -(1 << 31) or value >= 1 << 31:
        raise ValueError("value does not fit signed 32-bit varint")
    return encode_uvarint((value << 1) ^ (value >> 31), maximum_bits=32)


def encode_svarint64(value: int) -> bytes:
    if value < -(1 << 63) or value >= 1 << 63:
        raise ValueError("value does not fit signed 64-bit varint")
    return encode_uvarint((value << 1) ^ (value >> 63), maximum_bits=64)


def encode_u8_varint(value: int) -> bytes:
    return encode_uvarint(value, maximum_bits=8)


def encode_bool(value: bool) -> bytes:
    if not isinstance(value, bool):
        raise ValueError("boolean field requires bool")
    return encode_uvarint(int(value), maximum_bits=32)


def encode_length_prefixed_bytes(value: bytes) -> bytes:
    return encode_uvarint(len(value), maximum_bits=32) + value


def encode_vec3f(
    value: tuple[WireFloat32, WireFloat32, WireFloat32],
) -> bytes:
    if len(value) != 3:
        raise ValueError("vec3f requires exactly three float32 values")
    return b"".join(component.encode() for component in value)


@dataclass(frozen=True)
class WireFloat32:
    """A float32 represented by its bits so NaNs round-trip exactly."""

    bits: int

    def __post_init__(self) -> None:
        if self.bits < 0 or self.bits > 0xFFFFFFFF:
            raise ValueError("float32 bits must fit in 32 bits")

    @classmethod
    def from_float(cls, value: float) -> WireFloat32:
        return cls(struct.unpack("<I", struct.pack("<f", value))[0])

    @property
    def value(self) -> float:
        return struct.unpack("<f", struct.pack("<I", self.bits))[0]

    def encode(self) -> bytes:
        return struct.pack("<I", self.bits)


@dataclass
class ReferenceTable:
    """The session dictionary used by the compact-reference reader.

    ``assume_existing`` is for decoding a mid-session capture whose bootstrap
    table was not recorded. In that mode indices remain unresolved, but their
    tokens and optional 16-byte side values still round-trip exactly.
    """

    entries: list[bytes] = field(default_factory=list)
    assume_existing: bool = False

    def __post_init__(self) -> None:
        for entry in self.entries:
            _require_reference_bytes(entry)

    def clone(self) -> ReferenceTable:
        return ReferenceTable(list(self.entries), self.assume_existing)


@dataclass(frozen=True)
class CompactReference:
    value: bytes | None
    token: int | None = None
    side_value: bytes | None = None

    def __post_init__(self) -> None:
        if self.value is not None:
            _require_reference_bytes(self.value)
        if self.token is not None and (self.token < 0 or self.token > 0xFFFFFFFF):
            raise ValueError("compact-reference token must fit in 32 bits")
        if self.side_value is not None:
            _require_reference_bytes(self.side_value)

    @property
    def index(self) -> int | None:
        return self.token >> 1 if self.token is not None else None

    @property
    def has_side_value(self) -> bool:
        return self.token is not None and bool(self.token & 1)


def _require_reference_bytes(value: bytes) -> None:
    if len(value) != 16:
        raise ValueError("references must contain exactly 16 bytes")


def decode_reference(
    cursor: Cursor,
    table: ReferenceTable | None,
) -> CompactReference:
    if table is None:
        return CompactReference(value=cursor.read(16))

    token = cursor.read_uvarint(maximum_bits=32)
    index = token >> 1
    existing = table.assume_existing or index < len(table.entries)
    if existing:
        value = None if table.assume_existing else table.entries[index]
        side_value = cursor.read(16) if token & 1 else None
        return CompactReference(value=value, token=token, side_value=side_value)

    value = cursor.read(16)
    table.entries.append(value)
    return CompactReference(value=value, token=token)


def encode_reference(
    reference: CompactReference,
    table: ReferenceTable | None,
) -> bytes:
    if table is None:
        if reference.value is None:
            raise ValueError("a raw reference requires a resolved 16-byte value")
        return reference.value

    if reference.token is not None:
        token = reference.token
        index = token >> 1
        existing = table.assume_existing or index < len(table.entries)
        encoded = bytearray(encode_uvarint(token, maximum_bits=32))
        if existing:
            if token & 1:
                if reference.side_value is None:
                    raise ValueError("odd existing-reference token requires side_value")
                encoded.extend(reference.side_value)
            return bytes(encoded)
        if reference.value is None:
            raise ValueError("new reference-table entry requires a resolved value")
        encoded.extend(reference.value)
        table.entries.append(reference.value)
        return bytes(encoded)

    if reference.value is None:
        raise ValueError("reference requires either a token or a resolved value")
    try:
        index = table.entries.index(reference.value)
    except ValueError:
        index = len(table.entries)
        table.entries.append(reference.value)
        return encode_uvarint(index << 1, maximum_bits=32) + reference.value
    return encode_uvarint(index << 1, maximum_bits=32)
