"""Normal server-list join and instance-connect wire shapes (finding 114).

Only the observed empty-preferences/no-group starting-zone request is supported.
The packed location descriptor uses fixed-width lengths, not outer varints.
"""
from dataclasses import dataclass, field
import struct

from .codec import Cursor, DecodeError, encode_length_prefixed_bytes, encode_uvarint


def _string(c):
    value = c.read_length_prefixed_bytes(maximum_length=63)
    if b'\0' in value:
        raise DecodeError('embedded NUL in server-list string')
    return value


def _timed(c, *, allow_empty=False):
    length = c.read_uvarint(maximum_bits=64)
    if length > 32768:
        raise DecodeError('oversized timed token')
    token = c.read(length)
    lifetime = c.read_uvarint(maximum_bits=64)
    if not allow_empty and (not token or not lifetime):
        raise DecodeError('empty or expired timed token')
    return token, lifetime


def _encode_timed(token, lifetime):
    if not token or len(token) > 32768 or not 0 < lifetime < 1 << 64:
        raise ValueError('invalid timed token')
    return encode_uvarint(len(token)) + token + encode_uvarint(lifetime)


def decode_server_list_connect(body):
    # Writer 0x225cf90 -> 0xe0200.
    c = Cursor(body)
    result = _timed(c)
    if c.remaining:
        raise DecodeError('trailing server-list connect bytes')
    return result


@dataclass(frozen=True)
class NormalJoinRequest:
    request_id: int
    instance_type: bytes
    token: bytes = field(repr=False)
    lifetime: int


def decode_normal_join_request(body):
    # Writer 0x225d090: ID, three strings, timed blob, two arrays, four bools.
    c = Cursor(body)
    request_id = c.read_uvarint(maximum_bits=32)
    first, second, instance_type = _string(c), _string(c), _string(c)
    token, lifetime = _timed(c)
    if first or second or c.read_uvarint(maximum_bits=32) or c.read_uvarint(maximum_bits=32):
        raise DecodeError('unsupported join preferences')
    if c.read(4) != bytes(4) or c.remaining:
        raise DecodeError('unsupported join flags or trailing bytes')
    return NormalJoinRequest(request_id, instance_type, token, lifetime)


def encode_normal_join_request(value):
    if len(value.instance_type) >= 64 or b'\0' in value.instance_type:
        raise ValueError('invalid instance type')
    return (encode_uvarint(value.request_id, maximum_bits=32) + b'\0\0'
            + encode_length_prefixed_bytes(value.instance_type)
            + _encode_timed(value.token, value.lifetime) + bytes(6))


@dataclass(frozen=True)
class JoinReply:
    request_id: int
    uint32_c: int  # Exact semantics unconfirmed; NOT the descriptor's proxy ID.
    instance_name: bytes
    token: bytes = field(repr=False)
    lifetime: int
    proxy_id: int
    location_name: bytes
    location_type: bytes


def encode_join_reply(value):
    # Reader 0x22592d0 success branch, then packed reader 0x64f10.
    for name in (value.instance_name, value.location_name, value.location_type):
        if not name or len(name) >= 64 or b'\0' in name:
            raise ValueError('invalid local instance descriptor string')
    if not 0 <= value.proxy_id < 1 << 32:
        raise ValueError('invalid proxy ID')
    packed = (struct.pack('<I', value.proxy_id)
              + struct.pack('<I', len(value.location_name)) + value.location_name
              + struct.pack('<I', len(value.location_type)) + value.location_type)
    return (encode_uvarint(value.request_id, maximum_bits=32) + b'\1'
            + encode_uvarint(value.uint32_c, maximum_bits=32)
            + encode_length_prefixed_bytes(value.instance_name)
            + _encode_timed(value.token, value.lifetime)
            + encode_uvarint(len(packed)) + packed)


def decode_join_reply(body):
    c = Cursor(body)
    request_id = c.read_uvarint(maximum_bits=32)
    if c.read(1) != b'\1':
        raise DecodeError('only successful join reply supported')
    value_c, name = c.read_uvarint(maximum_bits=32), _string(c)
    token, lifetime = _timed(c)
    length = c.read_uvarint(maximum_bits=64)
    if length > 512:
        raise DecodeError('oversized packed location')
    packed = Cursor(c.read(length))
    proxy_id = struct.unpack('<I', packed.read(4))[0]
    strings = []
    for _ in range(2):
        size = struct.unpack('<I', packed.read(4))[0]
        if not 0 < size < 64:
            raise DecodeError('invalid packed location string length')
        item = packed.read(size)
        if b'\0' in item:
            raise DecodeError('NUL in packed location string')
        strings.append(item)
    if c.remaining or packed.remaining or not name:
        raise DecodeError('invalid join reply tail')
    return JoinReply(request_id, value_c, name, token, lifetime, proxy_id, *strings)


def decode_instance_connect(body):
    # Writer 0x225adf0: three timed blobs, bool, optional fourth timed blob.
    # Retail lineage: auth blob 0, discovery instance bearer, auth blob 2.
    # Authorization is performed by the backend, not by this structural parser.
    c = Cursor(body)
    tokens = (_timed(c), _timed(c, allow_empty=True), _timed(c, allow_empty=True))
    flag = c.read_u8_varint()
    if flag > 1:
        raise DecodeError('noncanonical instance-connect flag')
    extra = _timed(c, allow_empty=True) if flag else None
    if c.remaining:
        raise DecodeError('trailing instance connect bytes')
    return tokens, extra
