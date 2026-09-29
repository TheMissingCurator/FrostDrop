"""Outer-2056 type-5 service records, not the port-51000 endpoint directory.

Layout from reader 0x2258430 and attribute reader 0x65480; field evidence
from the 2026-09-27 successful retail type-5 capture. Keep ordered byte pairs:
neither duplicate keys nor embedded NULs should disappear during decoding.
"""
from dataclasses import dataclass

from .codec import Cursor, DecodeError, encode_length_prefixed_bytes, encode_uvarint
from .transport import TransportFrame


@dataclass(frozen=True)
class ServiceAdvertisement:
    name: bytes
    attributes: tuple[tuple[bytes, bytes], ...]


def encode_service_advertisement(record: ServiceAdvertisement) -> TransportFrame:
    if len(record.name) >= 64 or len(record.attributes) > 24:
        raise ValueError("advertisement name or attribute count exceeds client bounds")
    body = bytearray(encode_length_prefixed_bytes(record.name))
    body.extend(encode_uvarint(len(record.attributes), maximum_bits=32))
    for key, value in record.attributes:
        if len(key) >= 64 or len(value) >= 512:
            raise ValueError("advertisement attribute exceeds client bounds")
        body.extend(encode_length_prefixed_bytes(key))
        body.extend(encode_length_prefixed_bytes(value))
    return TransportFrame(False, 5, bytes(body))


def decode_service_advertisement(frame: TransportFrame) -> ServiceAdvertisement:
    if frame.control or frame.type_id != 5:
        raise DecodeError("not an outer service advertisement")
    cursor = Cursor(frame.body)
    name = cursor.read_length_prefixed_bytes(maximum_length=63)
    count = cursor.read_uvarint(maximum_bits=32)
    if count > 24:
        raise DecodeError("too many service attributes")
    pairs = tuple((cursor.read_length_prefixed_bytes(maximum_length=63),
                   cursor.read_length_prefixed_bytes(maximum_length=511)) for _ in range(count))
    if cursor.remaining:
        raise DecodeError("trailing service advertisement bytes")
    return ServiceAdvertisement(name, pairs)
