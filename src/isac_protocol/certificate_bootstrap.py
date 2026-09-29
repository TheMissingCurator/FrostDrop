"""Port-27015 certificate service framing, not world-stream framing.

The low length bit flags transport control messages here. It is not a
negative ZigZag length. The observed control type 3 carries version 303;
application type 0 carries one length-prefixed DER certificate.
"""

from .codec import Cursor, DecodeError, encode_length_prefixed_bytes, encode_uvarint
from .framing import MessageFrame, encode_length_prefixed_frame

PROTOCOL_VERSION = 303
MAX_CERTIFICATE_BYTES = 10_000


def encode_certificate_bootstrap(certificate_der: bytes) -> bytes:
    if not 1 <= len(certificate_der) <= MAX_CERTIFICATE_BYTES:
        raise ValueError("certificate must contain 1..10000 bytes")
    control = encode_uvarint(3) + encode_uvarint(PROTOCOL_VERSION)
    return (
        encode_uvarint((len(control) << 1) | 1)
        + control
        + encode_length_prefixed_frame(
            MessageFrame(0, encode_length_prefixed_bytes(certificate_der))
        )
    )


def decode_certificate_bootstrap(data: bytes) -> bytes:
    """Validate a complete bootstrap exchange and return its opaque DER blob.

This checks framing, not the X.509 certificate's validity or trust.
"""
    cursor = Cursor(data)
    tag = cursor.read_uvarint(maximum_bits=32)
    if not tag & 1:
        raise DecodeError("expected transport control frame")
    control = Cursor(cursor.read(tag >> 1))
    if control.read_uvarint(maximum_bits=16) != 3:
        raise DecodeError("unexpected transport control type")
    if control.read_uvarint(maximum_bits=32) != PROTOCOL_VERSION:
        raise DecodeError("unexpected protocol version")
    if control.remaining:
        raise DecodeError("trailing transport control bytes")
    tag = cursor.read_uvarint(maximum_bits=32)
    if tag & 1:
        raise DecodeError("expected certificate application frame")
    frame = Cursor(cursor.read(tag >> 1))
    if frame.read_uvarint(maximum_bits=16) != 0:
        raise DecodeError("unexpected certificate message type")
    certificate = frame.read_length_prefixed_bytes(maximum_length=MAX_CERTIFICATE_BYTES)
    if not certificate:
        raise DecodeError("empty certificate")
    if frame.remaining or cursor.remaining:
        raise DecodeError("trailing certificate response bytes")
    return certificate
