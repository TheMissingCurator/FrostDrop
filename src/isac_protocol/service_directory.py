"""Candidate service-directory schema from client reader RVA 0x2258520.

Not yet validated against port-51000 plaintext. Field semantics beyond host,
port and the two-way kind discriminator remain provisional.
"""
from dataclasses import dataclass

from .codec import Cursor, DecodeError, encode_uvarint
from .framing import MessageFrame, encode_length_prefixed_frame

PROTOCOL_VERSION = 1572  # Constructor call at 0xe5718, r9d=0x624.


@dataclass(frozen=True)
class DirectoryEntry:
    host_index: int
    port: int
    value: int
    kind: int


@dataclass(frozen=True)
class ServiceDirectory:
    identifier: bytes
    hosts: tuple[str, ...]
    entries: tuple[DirectoryEntry, ...]


def encode_directory_body(directory: ServiceDirectory) -> bytes:
    if len(directory.identifier) != 32:
        raise ValueError("directory identifier must be 32 bytes")
    if len(directory.hosts) > 64 or len(directory.entries) > 256:
        raise ValueError("directory exceeds local safety limits")
    body = bytearray(directory.identifier + encode_uvarint(len(directory.hosts)))
    for host in directory.hosts:
        encoded = host.encode("ascii")
        if not encoded or len(encoded) >= 64 or b"\0" in encoded:
            raise ValueError("host must contain 1..63 non-NUL ASCII bytes")
        body.extend(encode_uvarint(len(encoded)) + encoded)
    body.extend(encode_uvarint(len(directory.entries)))
    for entry in directory.entries:
        if not 0 <= entry.host_index < len(directory.hosts):
            raise ValueError("invalid host index")
        if not 1 <= entry.port <= 65535 or entry.kind not in (0, 1):
            raise ValueError("invalid port or kind")
        for value in (entry.host_index, entry.port, entry.value, entry.kind):
            body.extend(encode_uvarint(value, maximum_bits=32))
    return bytes(body)


def decode_directory_body(data: bytes) -> ServiceDirectory:
    cursor = Cursor(data)
    identifier = cursor.read(32)
    count = cursor.read_uvarint(maximum_bits=32)
    if count > 64:
        raise DecodeError("too many hosts")
    hosts = []
    for _ in range(count):
        raw = cursor.read_length_prefixed_bytes(maximum_length=63)
        if not raw or b"\0" in raw:
            raise DecodeError("invalid host")
        try:
            hosts.append(raw.decode("ascii"))
        except UnicodeDecodeError as error:
            raise DecodeError("non-ASCII host") from error
    count = cursor.read_uvarint(maximum_bits=32)
    if count > 256:
        raise DecodeError("too many entries")
    entries = tuple(DirectoryEntry(*(cursor.read_uvarint(maximum_bits=32) for _ in range(4)))
                    for _ in range(count))
    result = ServiceDirectory(identifier, tuple(hosts), entries)
    try:
        encode_directory_body(result)
    except ValueError as error:
        raise DecodeError(str(error)) from error
    if cursor.remaining:
        raise DecodeError("trailing directory bytes")
    return result


def encode_directory_response(directory: ServiceDirectory) -> bytes:
    control = encode_uvarint(3) + encode_uvarint(PROTOCOL_VERSION)
    return (encode_uvarint(len(control) * 2 + 1) + control
            + encode_length_prefixed_frame(MessageFrame(0, encode_directory_body(directory))))


def local_directory(identifier: bytes, *, split_services: bool = False) -> ServiceDirectory:
    # 55000 is the plaintext adapter, NOT a retail-wire listener. Do not send
    # the game there. 55001 reserves the future encrypted backend's port.
    return ServiceDirectory(identifier, ("127.0.0.1",), (
        DirectoryEntry(0, 55001, 0, 0), DirectoryEntry(0, 55002 if split_services else 55001, 0, 1),
    ))
