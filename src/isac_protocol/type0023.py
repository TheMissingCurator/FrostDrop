"""Branch-aware structural codec for inbound message type 0x0023."""

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
    encode_svarint64,
    encode_u8_varint,
    encode_vec3f,
)


Vec3f = tuple[WireFloat32, WireFloat32, WireFloat32]


@dataclass(frozen=True)
class Type0023Tail:
    boolean_0: bool | None
    signed_0: int | None
    float_0: WireFloat32
    float_1: WireFloat32
    float_2: WireFloat32


@dataclass(frozen=True)
class Type0023:
    reference_0: CompactReference
    byte_0: int
    discriminator: int
    reference_1: CompactReference | None = None
    vector_0: Vec3f | None = None
    tail: Type0023Tail | None = None


def decode_type0023(data: bytes, table: ReferenceTable | None) -> Type0023:
    cursor = Cursor(data)
    reference_0 = decode_reference(cursor, table)
    byte_0 = cursor.read_u8_varint()
    discriminator = cursor.read_u8_varint()

    reference_1 = None
    vector_0 = None
    tail = None
    if discriminator == 1:
        reference_1 = decode_reference(cursor, table)
    elif discriminator == 2:
        vector_0 = cursor.read_vec3f()

    if discriminator != 0:
        boolean_0 = None
        signed_0 = None
        if byte_0 == 0:
            boolean_0 = cursor.read_bool()
            signed_0 = cursor.read_svarint64()
        tail = Type0023Tail(
            boolean_0=boolean_0,
            signed_0=signed_0,
            float_0=cursor.read_float32(),
            float_1=cursor.read_float32(),
            float_2=cursor.read_float32(),
        )

    if cursor.remaining:
        raise DecodeError(f"{cursor.remaining} trailing bytes after type 0x0023")

    return Type0023(
        reference_0=reference_0,
        byte_0=byte_0,
        discriminator=discriminator,
        reference_1=reference_1,
        vector_0=vector_0,
        tail=tail,
    )


def _validate_shape(message: Type0023) -> None:
    if message.discriminator == 0:
        if message.reference_1 is not None or message.vector_0 is not None:
            raise ValueError("discriminator 0 forbids a variant payload")
        if message.tail is not None:
            raise ValueError("discriminator 0 forbids a common tail")
        return

    if message.tail is None:
        raise ValueError("nonzero discriminator requires a common tail")
    if message.discriminator == 1:
        if message.reference_1 is None or message.vector_0 is not None:
            raise ValueError("discriminator 1 requires only reference_1")
    elif message.discriminator == 2:
        if message.vector_0 is None or message.reference_1 is not None:
            raise ValueError("discriminator 2 requires only vector_0")
    elif message.reference_1 is not None or message.vector_0 is not None:
        raise ValueError("other discriminators forbid known variant payloads")

    has_metadata = (
        message.tail.boolean_0 is not None or message.tail.signed_0 is not None
    )
    if message.byte_0 == 0:
        if message.tail.boolean_0 is None or message.tail.signed_0 is None:
            raise ValueError("byte_0=0 requires boolean_0 and signed_0")
    elif has_metadata:
        raise ValueError("nonzero byte_0 forbids boolean_0 and signed_0")


def encode_type0023(message: Type0023, table: ReferenceTable | None) -> bytes:
    _validate_shape(message)

    encoded = bytearray(encode_reference(message.reference_0, table))
    encoded.extend(encode_u8_varint(message.byte_0))
    encoded.extend(encode_u8_varint(message.discriminator))

    if message.reference_1 is not None:
        encoded.extend(encode_reference(message.reference_1, table))
    elif message.vector_0 is not None:
        encoded.extend(encode_vec3f(message.vector_0))

    if message.tail is not None:
        if message.tail.boolean_0 is not None:
            encoded.extend(encode_bool(message.tail.boolean_0))
            assert message.tail.signed_0 is not None
            encoded.extend(encode_svarint64(message.tail.signed_0))
        encoded.extend(message.tail.float_0.encode())
        encoded.extend(message.tail.float_1.encode())
        encoded.extend(message.tail.float_2.encode())

    return bytes(encoded)
