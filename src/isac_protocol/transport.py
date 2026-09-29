"""Outer TLS stream framing; distinct from inner gameplay message framing.

The low length bit marks transport control, not a negative ZigZag length.
Root application type 3 multiplexes an opaque inner stream onto a channel.
This module does not infer channel registration or authentication semantics.
"""
from dataclasses import dataclass

from .codec import Cursor, DecodeError, encode_uvarint


@dataclass(frozen=True)
class TransportFrame:
    control: bool
    type_id: int
    body: bytes


def encode_transport_frame(frame: TransportFrame) -> bytes:
    content = encode_uvarint(frame.type_id, maximum_bits=32) + frame.body
    return encode_uvarint((len(content) << 1) | int(frame.control), maximum_bits=32) + content


def encode_protocol_version(version: int) -> bytes:
    return encode_transport_frame(TransportFrame(True, 3, encode_uvarint(version, maximum_bits=32)))


def channel_payload(frame: TransportFrame) -> tuple[int, bytes]:
    if frame.control or frame.type_id != 3:
        raise DecodeError("not a root application channel frame")
    cursor = Cursor(frame.body)
    channel = cursor.read_uvarint(maximum_bits=32)
    size = cursor.read_uvarint(maximum_bits=32)
    payload = cursor.read(size)
    if cursor.remaining:
        raise DecodeError("trailing root channel bytes")
    return channel, payload


class TransportStreamDecoder:
    """Bounded, incremental decoder. A decoding error is terminal."""

    def __init__(self, maximum_frame_bytes: int = 262144):
        if not 1 <= maximum_frame_bytes <= 16 * 1024 * 1024:
            raise ValueError("invalid frame limit")
        self.maximum_frame_bytes = maximum_frame_bytes
        self.buffer = bytearray()
        self.failed = False

    @property
    def pending_bytes(self) -> int:
        return len(self.buffer)

    def feed(self, data: bytes) -> list[TransportFrame]:
        if self.failed:
            raise DecodeError("decoder already failed")
        try:
            # The socket reader feeds at most 4096 bytes at a time. Requiring
            # bounded chunks also prevents a coalesced input from bypassing limits.
            if len(data) > self.maximum_frame_bytes + 5:
                raise DecodeError("transport input chunk exceeds limit")
            self.buffer.extend(data)
            result = []
            offset = 0
            while offset < len(self.buffer):
                tag = 0
                prefix_bytes = 0
                for index in range(5):
                    if offset + index >= len(self.buffer):
                        break
                    byte = self.buffer[offset + index]
                    tag |= (byte & 0x7f) << (7 * index)
                    if not byte & 0x80:
                        prefix_bytes = index + 1
                        break
                else:
                    raise DecodeError("unterminated transport length")
                if not prefix_bytes:
                    break
                if tag >= 1 << 32:
                    raise DecodeError("transport length overflow")
                size = tag >> 1
                if not 1 <= size <= self.maximum_frame_bytes:
                    raise DecodeError("invalid transport frame size")
                end = offset + prefix_bytes + size
                if end > len(self.buffer):
                    break
                cursor = Cursor(bytes(self.buffer[offset + prefix_bytes:end]))
                type_id = cursor.read_uvarint(maximum_bits=32)
                result.append(TransportFrame(bool(tag & 1), type_id, cursor.read(cursor.remaining)))
                offset = end
            del self.buffer[:offset]
            if len(self.buffer) > self.maximum_frame_bytes + 5:
                raise DecodeError("transport pending buffer exceeds limit")
            return result
        except DecodeError:
            self.failed = True
            self.buffer.clear()
            raise

    def finish(self) -> None:
        if self.failed or self.buffer:
            raise DecodeError("failed or truncated transport stream")
