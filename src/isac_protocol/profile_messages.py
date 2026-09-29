"""Profile-client list/delete/create/normal-token codecs (findings 109–113).

Nonempty request filters use a different identifier writer and remain unsupported.
"""
from dataclasses import dataclass

from .codec import Cursor, DecodeError, encode_bool, encode_length_prefixed_bytes, encode_uvarint


def decode_profile_connect(body: bytes) -> tuple[bytes, int]:
    # 0x225cae0 -> 0xe0200: bounded token plus remaining lifetime, no request ID.
    cursor = Cursor(body)
    token = cursor.read_length_prefixed_bytes(maximum_length=32768)
    lifetime = cursor.read_uvarint(maximum_bits=64)
    if cursor.remaining or not token:
        raise DecodeError("invalid profile connect")
    return token, lifetime


def decode_unfiltered_profile_list_request(body: bytes) -> int:
    # Writer 0x225cc50: uint32 request ID, uint32 count, identifier array.
    cursor = Cursor(body)
    request_id = cursor.read_uvarint(maximum_bits=32)
    count = cursor.read_uvarint(maximum_bits=32)
    if count or cursor.remaining:
        raise DecodeError("only unfiltered profile-list requests are supported")
    return request_id


@dataclass(frozen=True)
class EmptyProfileList:
    request_id: int
    success: bool
    flag_128: bool
    flag_129: bool
    uint32_8: int
    bytes_130: bytes


def encode_empty_profile_list(value: EmptyProfileList) -> bytes:
    # Reader 0x2257f90. The string reader rejects length >= 0x40.
    if len(value.bytes_130) >= 64:
        raise ValueError("profile-list string exceeds reader capacity")
    return (encode_uvarint(value.request_id, maximum_bits=32)
            + encode_bool(value.success) + encode_bool(value.flag_128)
            + encode_bool(value.flag_129)
            + encode_uvarint(value.uint32_8, maximum_bits=32)
            + encode_length_prefixed_bytes(value.bytes_130) + b"\0")


def decode_empty_profile_list(body: bytes) -> EmptyProfileList:
    cursor = Cursor(body)
    request_id = cursor.read_uvarint(maximum_bits=32)
    flags = []
    for _ in range(3):
        flag = cursor.read_u8_varint()
        if flag > 1:
            raise DecodeError("noncanonical profile-list boolean")
        flags.append(bool(flag))
    value = EmptyProfileList(request_id, *flags,
                            cursor.read_uvarint(maximum_bits=32),
                            cursor.read_length_prefixed_bytes(maximum_length=63))
    if cursor.read_uvarint(maximum_bits=32) or cursor.remaining:
        raise DecodeError("only empty profile lists are supported")
    return value


def _flag(c):
    value = c.read_u8_varint()
    if value > 1:
        raise DecodeError("noncanonical profile boolean")
    return bool(value)


@dataclass(frozen=True)
class DeleteProfileRequest:
    request_id: int
    identifier: bytes


def decode_delete_profile_request(body: bytes) -> DeleteProfileRequest:
    # Writer 0x225cbb0: delimiter 3, uint32 request ID, raw identifier
    # storage via 0x223f200. Only the observed 16-byte identifier is admitted.
    c = Cursor(body)
    value = DeleteProfileRequest(c.read_uvarint(maximum_bits=32), c.read(16))
    if c.remaining:
        raise DecodeError("trailing delete profile request data")
    return value


def encode_delete_profile_request(value: DeleteProfileRequest) -> bytes:
    if len(value.identifier) != 16:
        raise ValueError("invalid delete profile request identifier")
    return encode_uvarint(value.request_id, maximum_bits=32) + value.identifier


@dataclass(frozen=True)
class DeleteProfileReply:
    request_id: int
    success: bool


def encode_delete_profile_reply(value: DeleteProfileReply) -> bytes:
    # Reader 0x2257eb0: delimiter 4, uint32 ID, boolean at object+4.
    # Consumer 0x959d7 dispatches callback result 4 for true, 3 for false.
    if not isinstance(value.success, bool):
        raise ValueError("invalid delete profile success boolean")
    return encode_uvarint(value.request_id, maximum_bits=32) + encode_bool(value.success)


def decode_delete_profile_reply(body: bytes) -> DeleteProfileReply:
    c = Cursor(body)
    value = DeleteProfileReply(c.read_uvarint(maximum_bits=32), _flag(c))
    if c.remaining:
        raise DecodeError("trailing delete profile reply data")
    return value


@dataclass(frozen=True)
class CreateProfileRequest:
    request_id: int
    flag_5: bool
    flag_4: bool


def decode_create_profile_request(body: bytes) -> CreateProfileRequest:
    c = Cursor(body)
    value = CreateProfileRequest(c.read_uvarint(maximum_bits=32), _flag(c), _flag(c))
    if c.remaining:
        raise DecodeError("trailing create request data")
    return value


@dataclass(frozen=True)
class CreateProfileReply:
    request_id: int
    status: int
    identifier: bytes = b''


def encode_create_profile_reply(value: CreateProfileReply) -> bytes:
    if len(value.identifier) != (16 if value.status == 0 else 0):
        raise ValueError("invalid creation reply identifier")
    return (encode_uvarint(value.request_id, maximum_bits=32)
            + encode_uvarint(value.status, maximum_bits=32) + value.identifier)


def decode_create_profile_reply(body: bytes) -> CreateProfileReply:
    c = Cursor(body)
    request_id, status = c.read_uvarint(maximum_bits=32), c.read_uvarint(maximum_bits=32)
    value = CreateProfileReply(request_id, status, c.read(16) if status == 0 else b'')
    if c.remaining:
        raise DecodeError("trailing creation reply data")
    return value


@dataclass(frozen=True)
class ProfileEntry:
    identifier: bytes
    level: int
    is_male: bool
    last_used: int
    time_played: int
    instance_name: bytes
    instance_type: bytes
    is_locked: bool
    can_unlock: bool
    is_customized: bool
    is_joinable: bool
    is_survival: bool
    character_blob: bytes


@dataclass(frozen=True)
class ProfileList(EmptyProfileList):
    profiles: tuple[ProfileEntry, ...] = ()


def encode_profile_list(value: ProfileList) -> bytes:
    if len(value.profiles) > 8:
        raise ValueError("profile list exceeds supported bound")
    out = bytearray(encode_empty_profile_list(value)[:-1])
    out += encode_uvarint(len(value.profiles), maximum_bits=32)
    for p in value.profiles:
        if len(p.identifier) != 16 or max(len(p.instance_name), len(p.instance_type)) >= 64 or len(p.character_blob) > 10000:
            raise ValueError("invalid profile entry size")
        out += p.identifier + encode_uvarint(p.level, maximum_bits=32) + encode_bool(p.is_male)
        out += encode_uvarint(p.last_used, maximum_bits=64) + encode_uvarint(p.time_played, maximum_bits=64)
        out += encode_length_prefixed_bytes(p.instance_name) + encode_length_prefixed_bytes(p.instance_type)
        out += b''.join(encode_bool(f) for f in (p.is_locked, p.can_unlock, p.is_customized, p.is_joinable, p.is_survival))
        out += encode_length_prefixed_bytes(p.character_blob)
    return bytes(out)


def decode_profile_list(body: bytes) -> ProfileList:
    c = Cursor(body)
    header = (c.read_uvarint(maximum_bits=32), _flag(c), _flag(c), _flag(c),
              c.read_uvarint(maximum_bits=32), c.read_length_prefixed_bytes(maximum_length=63))
    count = c.read_uvarint(maximum_bits=32)
    if count > 8:
        raise DecodeError("profile list exceeds supported bound")
    entries = []
    for _ in range(count):
        entries.append(ProfileEntry(c.read(16), c.read_uvarint(maximum_bits=32), _flag(c),
            c.read_uvarint(maximum_bits=64), c.read_uvarint(maximum_bits=64),
            c.read_length_prefixed_bytes(maximum_length=63), c.read_length_prefixed_bytes(maximum_length=63),
            *(_flag(c) for _ in range(5)), c.read_length_prefixed_bytes(maximum_length=10000)))
    if c.remaining:
        raise DecodeError("trailing profile list data")
    return ProfileList(*header, tuple(entries))


@dataclass(frozen=True)
class ProfileTokenRequest:
    request_id: int
    identifier: bytes


def decode_profile_token_request(body: bytes) -> ProfileTokenRequest:
    # Writer 0x225ccf0: uint32 ID then 16 raw identifier bytes. No length
    # prefix/reference table; 0x223f200 appends raw storage. This narrow
    # shape is also confirmed by the actual local 17-byte selection request.
    c = Cursor(body)
    value = ProfileTokenRequest(c.read_uvarint(maximum_bits=32), c.read(16))
    if c.remaining:
        raise DecodeError("trailing profile token request data")
    return value


def encode_profile_token_request(value: ProfileTokenRequest) -> bytes:
    if len(value.identifier) != 16:
        raise ValueError("invalid profile token request identifier")
    return encode_uvarint(value.request_id, maximum_bits=32) + value.identifier


@dataclass(frozen=True)
class ProfileTokenReply:
    request_id: int
    status: int
    token: bytes
    lifetime: int
    instance_type: bytes
    instance_name: bytes
    has_base_group: bool = False
    has_survival_session: bool = False


def encode_profile_token_reply(value: ProfileTokenReply) -> bytes:
    # Reader 0x2258240 -> timed blob 0x64cb0. Its byte length and lifetime
    # are uint64 varints (same primitive as auth tokens), NOT an absolute
    # timestamp. Status 2 maps to success callback 4 at 0x9cd06/0x9d3ca.
    # Only the two-false optional-field branch is implemented. Never emit a
    # partial base-group/survival compound or invent an error-status shape.
    if (value.status != 2 or value.has_base_group or value.has_survival_session
            or not isinstance(value.has_base_group, bool) or not isinstance(value.has_survival_session, bool)):
        raise ValueError("unsupported profile token reply branch")
    if not 1 <= len(value.token) <= 32768 or not 0 < value.lifetime < 1 << 64:
        raise ValueError("invalid timed profile token")
    if max(len(value.instance_type), len(value.instance_name)) >= 64:
        raise ValueError("profile token string exceeds reader capacity")
    return (encode_uvarint(value.request_id, maximum_bits=32)
            + encode_uvarint(value.status, maximum_bits=32)
            + encode_uvarint(len(value.token), maximum_bits=64) + value.token
            + encode_uvarint(value.lifetime, maximum_bits=64)
            + encode_length_prefixed_bytes(value.instance_type)
            + encode_length_prefixed_bytes(value.instance_name)
            + encode_bool(value.has_base_group) + encode_bool(value.has_survival_session))


def decode_profile_token_reply(body: bytes) -> ProfileTokenReply:
    c = Cursor(body)
    request_id, status = c.read_uvarint(maximum_bits=32), c.read_uvarint(maximum_bits=32)
    if status != 2:
        raise DecodeError("unsupported profile token status")
    length = c.read_uvarint(maximum_bits=64)
    if not 1 <= length <= 32768:
        raise DecodeError("invalid profile token length")
    token, lifetime = c.read(length), c.read_uvarint(maximum_bits=64)
    if not lifetime:
        raise DecodeError("invalid profile token lifetime")
    instance_type = c.read_length_prefixed_bytes(maximum_length=63)
    instance_name = c.read_length_prefixed_bytes(maximum_length=63)
    if _flag(c):
        raise DecodeError("base-group profile token branch unsupported")
    if _flag(c):
        raise DecodeError("survival profile token branch unsupported")
    if c.remaining:
        raise DecodeError("trailing profile token reply data")
    return ProfileTokenReply(request_id, status, token, lifetime, instance_type, instance_name)
