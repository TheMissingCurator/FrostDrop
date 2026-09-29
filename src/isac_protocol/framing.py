"""Application framing used on the Division world streams."""

from __future__ import annotations

from dataclasses import dataclass

from .codec import Cursor, DecodeError, encode_uvarint


@dataclass(frozen=True)
class MessageFrame:
    type_id: int
    body: bytes


@dataclass(frozen=True)
class OutboundEnvelope:
    marker: int
    channel: int
    frames: tuple[MessageFrame, ...]


def decode_message_data(data: bytes) -> MessageFrame:
    cursor = Cursor(data)
    if not data:
        raise DecodeError("message frame has no type identifier")
    type_id = cursor.read_uvarint(maximum_bits=16)
    return MessageFrame(type_id=type_id, body=cursor.read(cursor.remaining))


def encode_message_data(frame: MessageFrame) -> bytes:
    return encode_uvarint(frame.type_id, maximum_bits=16) + frame.body


def decode_length_prefixed_frame(data: bytes) -> MessageFrame:
    cursor = Cursor(data)
    encoded_length = cursor.read_uvarint(maximum_bits=32)
    if encoded_length & 1:
        raise DecodeError("negative ZigZag frame length is invalid")
    frame_length = encoded_length >> 1
    if cursor.remaining != frame_length:
        raise DecodeError(
            f"frame declares {frame_length} bytes but {cursor.remaining} remain"
        )
    return decode_message_data(cursor.read(frame_length))


def encode_length_prefixed_frame(frame: MessageFrame) -> bytes:
    data = encode_message_data(frame)
    if len(data) >= 1 << 31:
        raise ValueError("message frame is too large for signed 32-bit length")
    return encode_uvarint(len(data) << 1, maximum_bits=32) + data


def decode_outbound_envelope(data: bytes) -> OutboundEnvelope:
    if len(data) < 3:
        raise DecodeError("outbound envelope is shorter than its header")
    cursor = Cursor(data)
    marker = cursor.read(1)[0]
    channel = cursor.read(1)[0]
    body_length = cursor.read_uvarint(maximum_bits=32)
    if cursor.remaining != body_length:
        raise DecodeError(
            f"envelope declares {body_length} body bytes but "
            f"{cursor.remaining} remain"
        )

    body_end = cursor.offset + body_length
    frames: list[MessageFrame] = []
    while cursor.offset < body_end:
        encoded_length = cursor.read_uvarint(maximum_bits=32)
        if encoded_length & 1:
            raise DecodeError("negative ZigZag nested-frame length is invalid")
        frame_length = encoded_length >> 1
        frames.append(decode_message_data(cursor.read(frame_length)))

    return OutboundEnvelope(marker=marker, channel=channel, frames=tuple(frames))


def encode_outbound_envelope(envelope: OutboundEnvelope) -> bytes:
    if envelope.marker < 0 or envelope.marker > 0xFF:
        raise ValueError("envelope marker must fit in one byte")
    if envelope.channel < 0 or envelope.channel > 0xFF:
        raise ValueError("envelope channel must fit in one byte")

    body = b"".join(encode_length_prefixed_frame(frame) for frame in envelope.frames)
    return (
        bytes((envelope.marker, envelope.channel))
        + encode_uvarint(len(body), maximum_bits=32)
        + body
    )


def _peek_uvarint(
    data: bytearray,
    offset: int,
    maximum_bits: int,
) -> tuple[int, int] | None:
    value = 0
    shift = 0
    maximum_bytes = (maximum_bits + 6) // 7
    for relative in range(maximum_bytes):
        index = offset + relative
        if index >= len(data):
            return None
        byte = data[index]
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            if value >= 1 << maximum_bits:
                raise DecodeError(f"varuint exceeds {maximum_bits} bits")
            return value, index + 1
        shift += 7
    raise DecodeError(f"unterminated {maximum_bits}-bit varuint")


class InboundFrameStreamDecoder:
    """Reassembles server-to-client frames from arbitrary transport chunks."""

    def __init__(self, *, maximum_frame_length: int = 1_000_000) -> None:
        if maximum_frame_length < 1:
            raise ValueError("maximum frame length must be positive")
        self.maximum_frame_length = maximum_frame_length
        self._buffer = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> tuple[MessageFrame, ...]:
        self._buffer.extend(data)
        frames: list[MessageFrame] = []
        while self._buffer:
            decoded = _peek_uvarint(self._buffer, 0, 32)
            if decoded is None:
                break
            encoded_length, body_offset = decoded
            if encoded_length & 1:
                raise DecodeError("negative ZigZag frame length is invalid")
            frame_length = encoded_length >> 1
            if frame_length > self.maximum_frame_length:
                raise DecodeError(
                    f"frame length {frame_length} exceeds configured maximum"
                )
            frame_end = body_offset + frame_length
            if frame_end > len(self._buffer):
                break
            frame_data = bytes(self._buffer[body_offset:frame_end])
            del self._buffer[:frame_end]
            frames.append(decode_message_data(frame_data))
        return tuple(frames)


class OutboundEnvelopeStreamDecoder:
    """Reassembles client-to-server envelopes from arbitrary chunks."""

    def __init__(self, *, maximum_body_length: int = 4_000_000) -> None:
        if maximum_body_length < 0:
            raise ValueError("maximum body length must not be negative")
        self.maximum_body_length = maximum_body_length
        self._buffer = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> tuple[OutboundEnvelope, ...]:
        self._buffer.extend(data)
        envelopes: list[OutboundEnvelope] = []
        while len(self._buffer) >= 2:
            decoded = _peek_uvarint(self._buffer, 2, 32)
            if decoded is None:
                break
            body_length, body_offset = decoded
            if body_length > self.maximum_body_length:
                raise DecodeError(
                    f"envelope body length {body_length} exceeds configured maximum"
                )
            envelope_end = body_offset + body_length
            if envelope_end > len(self._buffer):
                break
            encoded = bytes(self._buffer[:envelope_end])
            del self._buffer[:envelope_end]
            envelopes.append(decode_outbound_envelope(encoded))
        return tuple(envelopes)
