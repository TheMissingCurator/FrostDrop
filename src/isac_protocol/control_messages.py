"""Structural codecs for early server control messages 0x0002, 0x0003, and 0x0006."""

from __future__ import annotations

from dataclasses import dataclass

from .codec import (
    Cursor,
    DecodeError,
    ReferenceTable,
    encode_svarint32,
    encode_u8_varint,
    encode_uvarint,
)


def _require_identifier(value: bytes, name: str) -> None:
    if len(value) != 16:
        raise ValueError(f"{name} must contain exactly 16 bytes")


def _read_bounded_bytes(
    cursor: Cursor,
    maximum_length: int,
    *,
    length_bits: int = 32,
) -> bytes:
    length = cursor.read_uvarint(maximum_bits=length_bits)
    if length > maximum_length:
        raise DecodeError(
            f"byte-string length {length} exceeds maximum {maximum_length}"
        )
    return cursor.read(length)


def _encode_bounded_bytes(
    value: bytes,
    maximum_length: int,
    *,
    length_bits: int = 32,
) -> bytes:
    if len(value) > maximum_length:
        raise ValueError(
            f"byte-string length {len(value)} exceeds maximum {maximum_length}"
        )
    return encode_uvarint(len(value), maximum_bits=length_bits) + value


@dataclass(frozen=True)
class ControlIdentity:
    byte_0: int
    value: bytes


def _decode_identity(cursor: Cursor) -> ControlIdentity:
    return ControlIdentity(
        byte_0=cursor.read_u8_varint(),
        value=_read_bounded_bytes(cursor, 61, length_bits=8),
    )


def _encode_identity(identity: ControlIdentity) -> bytes:
    return encode_u8_varint(identity.byte_0) + _encode_bounded_bytes(
        identity.value, 61, length_bits=8
    )


@dataclass(frozen=True)
class Type0002TaggedValue:
    discriminator: int
    identifier: bytes | None = None
    uint32_0: int | None = None
    uint32_1: int | None = None


def _decode_tagged_value(cursor: Cursor) -> Type0002TaggedValue:
    discriminator = cursor.read_uvarint(maximum_bits=32)
    if discriminator >= 7:
        raise DecodeError(
            f"type 0x0002 tagged discriminator out of range: {discriminator}"
        )

    identifier = cursor.read(16) if discriminator != 0 else None
    uint32_0 = None
    uint32_1 = None
    if discriminator == 1:
        uint32_1 = cursor.read_uvarint(maximum_bits=32)
        uint32_0 = cursor.read_uvarint(maximum_bits=32)
    elif discriminator == 4:
        uint32_0 = cursor.read_uvarint(maximum_bits=32)
    return Type0002TaggedValue(
        discriminator=discriminator,
        identifier=identifier,
        uint32_0=uint32_0,
        uint32_1=uint32_1,
    )


def _encode_tagged_value(value: Type0002TaggedValue) -> bytes:
    if value.discriminator < 0 or value.discriminator >= 7:
        raise ValueError("type 0x0002 tagged discriminator must be in range 0..6")

    if value.discriminator == 0:
        if value.identifier is not None:
            raise ValueError("tagged discriminator 0 forbids an identifier")
    else:
        if value.identifier is None:
            raise ValueError("nonzero tagged discriminator requires an identifier")
        _require_identifier(value.identifier, "tagged identifier")

    if value.discriminator == 1:
        if value.uint32_0 is None or value.uint32_1 is None:
            raise ValueError("tagged discriminator 1 requires both uint32 values")
    elif value.discriminator == 4:
        if value.uint32_0 is None or value.uint32_1 is not None:
            raise ValueError("tagged discriminator 4 requires only uint32_0")
    elif value.uint32_0 is not None or value.uint32_1 is not None:
        raise ValueError("this tagged discriminator forbids uint32 values")

    encoded = bytearray(encode_uvarint(value.discriminator, maximum_bits=32))
    if value.identifier is not None:
        encoded.extend(value.identifier)
    if value.discriminator == 1:
        assert value.uint32_1 is not None and value.uint32_0 is not None
        encoded.extend(encode_uvarint(value.uint32_1, maximum_bits=32))
        encoded.extend(encode_uvarint(value.uint32_0, maximum_bits=32))
    elif value.discriminator == 4:
        assert value.uint32_0 is not None
        encoded.extend(encode_uvarint(value.uint32_0, maximum_bits=32))
    return bytes(encoded)


@dataclass(frozen=True)
class Type0002Entry:
    identity: ControlIdentity
    bytes_0: bytes
    uint32_0: int
    byte_0: int
    byte_1: int


def _decode_entry(cursor: Cursor) -> Type0002Entry:
    return Type0002Entry(
        identity=_decode_identity(cursor),
        bytes_0=_read_bounded_bytes(cursor, 31),
        uint32_0=cursor.read_uvarint(maximum_bits=32),
        byte_0=cursor.read_u8_varint(),
        byte_1=cursor.read_u8_varint(),
    )


def _encode_entry(entry: Type0002Entry) -> bytes:
    return (
        _encode_identity(entry.identity)
        + _encode_bounded_bytes(entry.bytes_0, 31)
        + encode_uvarint(entry.uint32_0, maximum_bits=32)
        + encode_u8_varint(entry.byte_0)
        + encode_u8_varint(entry.byte_1)
    )


@dataclass(frozen=True)
class Type0002Metadata:
    uint32_0: int
    signed_0: int
    signed_1: int
    uint32_1: int
    uint32_2: int
    uint32_3: int
    uint32_4: int
    narrowed_uint32_0: int
    narrowed_uint32_1: int
    byte_0: int
    byte_1: int
    byte_2: int
    byte_3: int
    byte_4: int
    byte_5: int
    byte_6: int
    byte_7: int
    byte_8: int
    tagged_value: Type0002TaggedValue
    identifier: bytes
    uint32_5: int
    bytes_0: bytes
    entries: tuple[Type0002Entry, ...]


def _decode_metadata(cursor: Cursor) -> Type0002Metadata:
    uint32_0 = cursor.read_uvarint(maximum_bits=32)
    signed_0 = cursor.read_svarint32()
    signed_1 = cursor.read_svarint32()
    uint32_values = tuple(cursor.read_uvarint(maximum_bits=32) for _ in range(4))
    narrowed_values = tuple(
        cursor.read_uvarint(maximum_bits=32) for _ in range(2)
    )
    byte_values = tuple(cursor.read_u8_varint() for _ in range(9))
    tagged_value = _decode_tagged_value(cursor)
    identifier = cursor.read(16)
    uint32_5 = cursor.read_uvarint(maximum_bits=32)
    bytes_0 = _read_bounded_bytes(cursor, 33)
    count = cursor.read_uvarint(maximum_bits=32)
    if count > 3:
        raise DecodeError(f"type 0x0002 entry count exceeds 3: {count}")
    entries = tuple(_decode_entry(cursor) for _ in range(count))
    return Type0002Metadata(
        uint32_0=uint32_0,
        signed_0=signed_0,
        signed_1=signed_1,
        uint32_1=uint32_values[0],
        uint32_2=uint32_values[1],
        uint32_3=uint32_values[2],
        uint32_4=uint32_values[3],
        narrowed_uint32_0=narrowed_values[0],
        narrowed_uint32_1=narrowed_values[1],
        byte_0=byte_values[0],
        byte_1=byte_values[1],
        byte_2=byte_values[2],
        byte_3=byte_values[3],
        byte_4=byte_values[4],
        byte_5=byte_values[5],
        byte_6=byte_values[6],
        byte_7=byte_values[7],
        byte_8=byte_values[8],
        tagged_value=tagged_value,
        identifier=identifier,
        uint32_5=uint32_5,
        bytes_0=bytes_0,
        entries=entries,
    )


def _encode_metadata(metadata: Type0002Metadata) -> bytes:
    _require_identifier(metadata.identifier, "metadata identifier")
    if len(metadata.entries) > 3:
        raise ValueError("type 0x0002 supports at most 3 metadata entries")

    encoded = bytearray(encode_uvarint(metadata.uint32_0, maximum_bits=32))
    encoded.extend(encode_svarint32(metadata.signed_0))
    encoded.extend(encode_svarint32(metadata.signed_1))
    for value in (
        metadata.uint32_1,
        metadata.uint32_2,
        metadata.uint32_3,
        metadata.uint32_4,
        metadata.narrowed_uint32_0,
        metadata.narrowed_uint32_1,
    ):
        encoded.extend(encode_uvarint(value, maximum_bits=32))
    for value in (
        metadata.byte_0,
        metadata.byte_1,
        metadata.byte_2,
        metadata.byte_3,
        metadata.byte_4,
        metadata.byte_5,
        metadata.byte_6,
        metadata.byte_7,
        metadata.byte_8,
    ):
        encoded.extend(encode_u8_varint(value))
    encoded.extend(_encode_tagged_value(metadata.tagged_value))
    encoded.extend(metadata.identifier)
    encoded.extend(encode_uvarint(metadata.uint32_5, maximum_bits=32))
    encoded.extend(_encode_bounded_bytes(metadata.bytes_0, 33))
    encoded.extend(encode_uvarint(len(metadata.entries), maximum_bits=32))
    for entry in metadata.entries:
        encoded.extend(_encode_entry(entry))
    return bytes(encoded)


@dataclass(frozen=True)
class Type0002Payload:
    identity: ControlIdentity
    flags: int
    embedded_0: bytes | None = None
    metadata: Type0002Metadata | None = None


@dataclass(frozen=True)
class Type0002:
    request_id: int
    payload: Type0002Payload | None = None


def decode_type0002(data: bytes, table: ReferenceTable | None) -> Type0002:
    del table
    cursor = Cursor(data)
    request_id = cursor.read_uvarint(maximum_bits=32)
    if cursor.remaining == 0:
        return Type0002(request_id=request_id)

    identity = _decode_identity(cursor)
    flags = cursor.read_uvarint(maximum_bits=32)
    embedded_0 = (
        _read_bounded_bytes(cursor, 1024, length_bits=64) if flags & 1 else None
    )
    metadata = _decode_metadata(cursor) if flags & 2 else None
    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x0002")
    return Type0002(
        request_id=request_id,
        payload=Type0002Payload(identity, flags, embedded_0, metadata),
    )


def encode_type0002(message: Type0002, table: ReferenceTable | None) -> bytes:
    del table
    encoded = bytearray(encode_uvarint(message.request_id, maximum_bits=32))
    if message.payload is None:
        return bytes(encoded)

    payload = message.payload
    has_embedded = payload.embedded_0 is not None
    has_metadata = payload.metadata is not None
    if has_embedded != bool(payload.flags & 1):
        raise ValueError("type 0x0002 flag bit 0 must match embedded_0 presence")
    if has_metadata != bool(payload.flags & 2):
        raise ValueError("type 0x0002 flag bit 1 must match metadata presence")

    encoded.extend(_encode_identity(payload.identity))
    encoded.extend(encode_uvarint(payload.flags, maximum_bits=32))
    if payload.embedded_0 is not None:
        encoded.extend(
            _encode_bounded_bytes(payload.embedded_0, 1024, length_bits=64)
        )
    if payload.metadata is not None:
        encoded.extend(_encode_metadata(payload.metadata))
    return bytes(encoded)


@dataclass(frozen=True)
class Type0003TimedBlob:
    bytes_0: bytes
    uint64_0: int


def _decode_type0003_timed_blob(cursor: Cursor) -> Type0003TimedBlob:
    return Type0003TimedBlob(
        bytes_0=_read_bounded_bytes(cursor, 32768, length_bits=64),
        uint64_0=cursor.read_uvarint(maximum_bits=64),
    )


def _encode_type0003_timed_blob(value: Type0003TimedBlob) -> bytes:
    return _encode_bounded_bytes(
        value.bytes_0,
        32768,
        length_bits=64,
    ) + encode_uvarint(value.uint64_0, maximum_bits=64)


@dataclass(frozen=True)
class Type0003Bundle:
    bool_0: bool
    bool_1: bool
    bool_2: bool
    bool_3: bool
    bool_4: bool
    bool_5: bool
    bool_6: bool
    entries: tuple[bytes, ...]


def _decode_type0003_bundle(cursor: Cursor) -> Type0003Bundle:
    bools = tuple(cursor.read_bool() for _ in range(7))
    count = cursor.read_uvarint(maximum_bits=32)
    # Every entry has at least a one-byte length prefix. This check preserves
    # the native format's unbounded count while avoiding work that cannot
    # possibly succeed on a finite input buffer.
    if count > cursor.remaining:
        raise DecodeError(
            f"type 0x0003 bundle count {count} exceeds remaining wire bytes "
            f"{cursor.remaining}"
        )
    entries = tuple(_read_bounded_bytes(cursor, 7) for _ in range(count))
    return Type0003Bundle(*bools, entries)


def _encode_type0003_bundle(bundle: Type0003Bundle) -> bytes:
    encoded = bytearray()
    for value in (
        bundle.bool_0,
        bundle.bool_1,
        bundle.bool_2,
        bundle.bool_3,
        bundle.bool_4,
        bundle.bool_5,
        bundle.bool_6,
    ):
        if not isinstance(value, bool):
            raise ValueError("type 0x0003 bundle flags must be bool")
        encoded.extend(encode_uvarint(int(value), maximum_bits=32))
    encoded.extend(encode_uvarint(len(bundle.entries), maximum_bits=32))
    for entry in bundle.entries:
        encoded.extend(_encode_bounded_bytes(entry, 7))
    return bytes(encoded)


@dataclass(frozen=True)
class Type0003:
    byte_0: int
    timed_blob_0: Type0003TimedBlob
    timed_blob_1: Type0003TimedBlob
    identity: ControlIdentity
    bytes_0: bytes
    bool_0: bool
    bool_1: bool
    bool_2: bool
    bundle: Type0003Bundle
    timed_blob_2: Type0003TimedBlob


def decode_type0003(data: bytes, table: ReferenceTable | None) -> Type0003:
    del table
    cursor = Cursor(data)
    byte_0 = cursor.read_u8_varint()
    timed_blob_0 = _decode_type0003_timed_blob(cursor)
    timed_blob_1 = _decode_type0003_timed_blob(cursor)
    identity = _decode_identity(cursor)
    bytes_0 = _read_bounded_bytes(cursor, 63)
    bool_0 = cursor.read_bool()
    bool_1 = cursor.read_bool()
    bool_2 = cursor.read_bool()
    bundle = _decode_type0003_bundle(cursor)
    timed_blob_2 = _decode_type0003_timed_blob(cursor)
    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x0003")
    return Type0003(
        byte_0=byte_0,
        timed_blob_0=timed_blob_0,
        timed_blob_1=timed_blob_1,
        identity=identity,
        bytes_0=bytes_0,
        bool_0=bool_0,
        bool_1=bool_1,
        bool_2=bool_2,
        bundle=bundle,
        timed_blob_2=timed_blob_2,
    )


def encode_type0003(message: Type0003, table: ReferenceTable | None) -> bytes:
    del table
    encoded = bytearray(encode_u8_varint(message.byte_0))
    encoded.extend(_encode_type0003_timed_blob(message.timed_blob_0))
    encoded.extend(_encode_type0003_timed_blob(message.timed_blob_1))
    encoded.extend(_encode_identity(message.identity))
    encoded.extend(_encode_bounded_bytes(message.bytes_0, 63))
    for value in (message.bool_0, message.bool_1, message.bool_2):
        if not isinstance(value, bool):
            raise ValueError("type 0x0003 flags must be bool")
        encoded.extend(encode_uvarint(int(value), maximum_bits=32))
    encoded.extend(_encode_type0003_bundle(message.bundle))
    encoded.extend(_encode_type0003_timed_blob(message.timed_blob_2))
    return bytes(encoded)


@dataclass(frozen=True)
class Type0006Details:
    bytes_0: bytes
    identity: ControlIdentity


@dataclass(frozen=True)
class Type0006:
    request_id: int
    presence: int
    details: Type0006Details | None = None


def decode_type0006(data: bytes, table: ReferenceTable | None) -> Type0006:
    del table
    cursor = Cursor(data)
    request_id = cursor.read_uvarint(maximum_bits=32)
    presence = cursor.read_u8_varint()
    details = None
    if presence:
        details = Type0006Details(
            bytes_0=_read_bounded_bytes(cursor, 63),
            identity=_decode_identity(cursor),
        )
    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x0006")
    return Type0006(request_id=request_id, presence=presence, details=details)


def encode_type0006(message: Type0006, table: ReferenceTable | None) -> bytes:
    del table
    if bool(message.presence) != (message.details is not None):
        requirement = "requires" if message.presence else "forbids"
        raise ValueError(f"type 0x0006 presence={message.presence} {requirement} details")
    encoded = bytearray(encode_uvarint(message.request_id, maximum_bits=32))
    encoded.extend(encode_u8_varint(message.presence))
    if message.details is not None:
        encoded.extend(_encode_bounded_bytes(message.details.bytes_0, 63))
        encoded.extend(_encode_identity(message.details.identity))
    return bytes(encoded)
