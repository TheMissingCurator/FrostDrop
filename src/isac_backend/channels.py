"""Candidate main-backend channel setup from the retail client code.

This is the outer protocol (2056), NOT the inner login/world protocol.
Registration replies are structurally established by reader 0x2258d10 and
consumer 0xb72c0. Channel-to-application bindings still require game evidence.
"""
from dataclasses import dataclass, field

from isac_protocol.codec import Cursor, DecodeError, encode_uvarint
from isac_protocol.framing import InboundFrameStreamDecoder, MessageFrame
from isac_protocol.transport import TransportFrame, channel_payload


@dataclass(frozen=True)
class Registration:
    request_id: int
    name: bytes
    target: bytes


def decode_registration(body: bytes) -> Registration:
    cursor = Cursor(body)
    request = Registration(cursor.read_uvarint(maximum_bits=32),
        cursor.read_length_prefixed_bytes(maximum_length=63),
        cursor.read_length_prefixed_bytes(maximum_length=63))
    if cursor.remaining or b"\0" in request.name or b"\0" in request.target:
        raise DecodeError("invalid registration body")
    return request


def registration_response(request_id: int, channel: int) -> TransportFrame:
    return TransportFrame(False, 1, encode_uvarint(request_id, maximum_bits=32)
        + encode_uvarint(channel, maximum_bits=32) + b"\x01")


def initial_settings() -> TransportFrame:
    # 0x2258af0 reads one Boolean; false omits the optional policy table.
    # 0xb6920 clears owner+0x53a. False avoids enabling an empty allowlist
    # which would otherwise reject every registration at 0xaf39e.
    return TransportFrame(False, 7, b"\x00")


@dataclass
class Channel:
    registration: Registration
    decoder: InboundFrameStreamDecoder = field(default_factory=lambda:
        InboundFrameStreamDecoder(maximum_frame_length=262144))


@dataclass(frozen=True)
class ChannelEvent:
    stage: str
    responses: tuple[TransportFrame, ...] = ()
    channel: int | None = None
    inner_frames: tuple[MessageFrame, ...] = ()
    request_id: int | None = None


class ChannelSetup:
    def __init__(self, maximum_channels: int = 64):
        if not 1 <= maximum_channels <= 256:
            raise ValueError("invalid channel limit")
        self.maximum_channels = maximum_channels
        self.channels: dict[int, Channel] = {}
        self.requests: dict[int, int] = {}
        self.next_channel = 0

    def handle(self, frame: TransportFrame) -> ChannelEvent:
        if frame.control:
            if frame.type_id != 3:
                raise DecodeError("unsupported transport control")
            cursor = Cursor(frame.body)
            if cursor.read_uvarint(maximum_bits=32) != 2056 or cursor.remaining:
                raise DecodeError("unexpected client protocol version")
            return ChannelEvent("client-version")
        if frame.type_id == 0:
            request = decode_registration(frame.body)
            if request.request_id in self.requests:
                channel = self.requests[request.request_id]
                if channel not in self.channels or self.channels[channel].registration != request:
                    raise DecodeError("conflicting or closed registration")
            else:
                if self.next_channel >= self.maximum_channels:
                    raise DecodeError("registration capacity exhausted")
                channel = self.next_channel
                self.next_channel += 1
                self.requests[request.request_id] = channel
                self.channels[channel] = Channel(request)
            return ChannelEvent("registration-ack-sent", (registration_response(request.request_id, channel),),
                                channel, request_id=request.request_id)
        if frame.type_id == 2:
            cursor = Cursor(frame.body)
            channel = cursor.read_uvarint(maximum_bits=32)
            if cursor.remaining or channel not in self.channels:
                raise DecodeError("invalid channel close")
            del self.channels[channel]
            return ChannelEvent("channel-closed", channel=channel)
        if frame.type_id == 3:
            channel, payload = channel_payload(frame)
            if channel not in self.channels:
                raise DecodeError("data for an unregistered channel")
            frames = self.channels[channel].decoder.feed(payload)
            return ChannelEvent("channel-data", channel=channel, inner_frames=frames)
        if frame.type_id == 8:
            # 0x225cd90 -> 0xe0200: bounded opaque blob plus uint64 lifetime.
            # Retained only in private capture; no ownership/auth claim is made.
            cursor = Cursor(frame.body)
            cursor.read_length_prefixed_bytes(maximum_length=32768)
            cursor.read_uvarint(maximum_bits=64)
            if cursor.remaining:
                raise DecodeError("trailing identity declaration bytes")
            return ChannelEvent("opaque-identity-received")
        if frame.type_id == 9 and not frame.body:
            # Empty heartbeat writer 0x225ce20; reply reader 0x22584f0.
            return ChannelEvent("heartbeat", (TransportFrame(False, 10, b""),))
        if frame.type_id == 11:
            # Client-side diagnostic serializer exists in empty and uint32 forms.
            cursor = Cursor(frame.body)
            if cursor.remaining:
                cursor.read_uvarint(maximum_bits=32)
            if cursor.remaining:
                raise DecodeError("invalid diagnostic message")
            return ChannelEvent("client-diagnostic")
        raise DecodeError("unsupported root application message")
