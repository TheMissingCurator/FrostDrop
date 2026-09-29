"""Central message-codec registry and session-scoped decoding state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .codec import ReferenceTable
from .agent_submission import AgentSubmission, decode_agent_submission, encode_agent_submission
from .control_messages import (
    Type0002,
    Type0003,
    Type0006,
    decode_type0002,
    decode_type0003,
    decode_type0006,
    encode_type0002,
    encode_type0003,
    encode_type0006,
)
from .framing import InboundFrameStreamDecoder, MessageFrame
from .simple_messages import (
    Type0020,
    Type0024,
    Type002D,
    Type0067,
    Type019D,
    decode_type0020,
    decode_type0024,
    decode_type002d,
    decode_type0067,
    decode_type019d,
    encode_type0020,
    encode_type0024,
    encode_type002d,
    encode_type0067,
    encode_type019d,
)
from .type0023 import Type0023, decode_type0023, encode_type0023
from .type002a import Type002A, decode_type002a, encode_type002a
from .type006c import Type006C, decode_type006c, encode_type006c
from .type0088 import Type0088, decode_type0088, encode_type0088
from .type00e6 import Type00E6, decode_type00e6, encode_type00e6
from .world_messages import (
    Type014D, Type0157, Type0167, Type00E8,
    decode_type014d, encode_type014d, decode_type0157, encode_type0157,
    decode_type0167, encode_type0167, decode_type00e8, encode_type00e8,
)


Decoder = Callable[[bytes, ReferenceTable | None], object]
Encoder = Callable[[object, ReferenceTable | None], bytes]
CLIENT_TO_SERVER = "client_to_server"
SERVER_TO_CLIENT = "server_to_client"
MESSAGE_DIRECTIONS = frozenset((CLIENT_TO_SERVER, SERVER_TO_CLIENT))


class UnsupportedMessageType(LookupError):
    pass


@dataclass(frozen=True)
class MessageCodec:
    direction: str
    type_id: int
    name: str
    model_type: type
    decoder: Decoder
    encoder: Encoder


@dataclass(frozen=True)
class DecodedMessage:
    type_id: int
    name: str
    value: object


@dataclass(frozen=True)
class OpaqueMessage:
    type_id: int
    body: bytes


class MessageRegistry:
    def __init__(self) -> None:
        self._codecs: dict[tuple[str, int], MessageCodec] = {}

    def register(self, codec: MessageCodec) -> None:
        if codec.direction not in MESSAGE_DIRECTIONS:
            raise ValueError(f"invalid message direction {codec.direction!r}")
        if codec.type_id < 0 or codec.type_id > 0xFFFF:
            raise ValueError("message type must fit in 16 bits")
        key = (codec.direction, codec.type_id)
        if key in self._codecs:
            raise ValueError(
                f"{codec.direction} message type {codec.type_id:#06x} "
                "is already registered"
            )
        self._codecs[key] = codec

    def type_ids(self, direction: str) -> tuple[int, ...]:
        if direction not in MESSAGE_DIRECTIONS:
            raise ValueError(f"invalid message direction {direction!r}")
        return tuple(
            sorted(type_id for codec_direction, type_id in self._codecs if codec_direction == direction)
        )

    def codec_for(self, direction: str, type_id: int) -> MessageCodec:
        try:
            return self._codecs[(direction, type_id)]
        except KeyError as error:
            raise UnsupportedMessageType(
                f"no {direction} codec registered for message type {type_id:#06x}"
            ) from error

    def decode(
        self,
        direction: str,
        frame: MessageFrame,
        table: ReferenceTable | None,
        *,
        allow_unknown: bool = False,
    ) -> DecodedMessage | OpaqueMessage:
        try:
            codec = self.codec_for(direction, frame.type_id)
        except UnsupportedMessageType:
            if allow_unknown:
                return OpaqueMessage(frame.type_id, frame.body)
            raise
        return DecodedMessage(
            type_id=frame.type_id,
            name=codec.name,
            value=codec.decoder(frame.body, table),
        )

    def encode(
        self,
        direction: str,
        type_id: int,
        value: object,
        table: ReferenceTable | None,
    ) -> MessageFrame:
        codec = self.codec_for(direction, type_id)
        if not isinstance(value, codec.model_type):
            raise TypeError(
                f"type {type_id:#06x} requires {codec.model_type.__name__}, "
                f"got {type(value).__name__}"
            )
        return MessageFrame(type_id, codec.encoder(value, table))


def build_default_registry() -> MessageRegistry:
    registry = MessageRegistry()
    for type_id, model, decoder, encoder in (
        (0x014D, Type014D, decode_type014d, encode_type014d),
        (0x0157, Type0157, decode_type0157, encode_type0157),
        (0x0167, Type0167, decode_type0167, encode_type0167),
        (0x00E8, Type00E8, decode_type00e8, encode_type00e8),
        (0x00E6, Type00E6, decode_type00e6, encode_type00e6),
    ):
        registry.register(MessageCodec(SERVER_TO_CLIENT, type_id,
            f"type{type_id:04x}", model, decoder, encoder))
    for codec in (
        MessageCodec(
            CLIENT_TO_SERVER,
            0x000C,
            "agent_submission_observed",
            AgentSubmission,
            decode_agent_submission,
            encode_agent_submission,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0002,
            "type0002",
            Type0002,
            decode_type0002,
            encode_type0002,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0003,
            "type0003",
            Type0003,
            decode_type0003,
            encode_type0003,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0006,
            "type0006",
            Type0006,
            decode_type0006,
            encode_type0006,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0020,
            "type0020",
            Type0020,
            decode_type0020,
            encode_type0020,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0023,
            "type0023",
            Type0023,
            decode_type0023,
            encode_type0023,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0024,
            "type0024",
            Type0024,
            decode_type0024,
            encode_type0024,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x002A,
            "type002a",
            Type002A,
            decode_type002a,
            encode_type002a,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x002D,
            "type002d",
            Type002D,
            decode_type002d,
            encode_type002d,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0067,
            "type0067",
            Type0067,
            decode_type0067,
            encode_type0067,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x006C,
            "type006c",
            Type006C,
            decode_type006c,
            encode_type006c,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x0088,
            "type0088",
            Type0088,
            decode_type0088,
            encode_type0088,
        ),
        MessageCodec(
            CLIENT_TO_SERVER,
            0x0088,
            "type0088",
            Type0088,
            decode_type0088,
            encode_type0088,
        ),
        MessageCodec(
            SERVER_TO_CLIENT,
            0x019D,
            "type019d",
            Type019D,
            decode_type019d,
            encode_type019d,
        ),
    ):
        registry.register(codec)
    return registry


@dataclass
class ProtocolSession:
    registry: MessageRegistry = field(default_factory=build_default_registry)
    client_to_server_references: ReferenceTable = field(default_factory=ReferenceTable)
    server_to_client_references: ReferenceTable = field(default_factory=ReferenceTable)

    @classmethod
    def from_midstream_capture(cls) -> ProtocolSession:
        return cls(
            client_to_server_references=ReferenceTable(assume_existing=True),
            server_to_client_references=ReferenceTable(assume_existing=True),
        )

    def decode_client_frame(
        self,
        frame: MessageFrame,
        *,
        allow_unknown: bool = True,
    ) -> DecodedMessage | OpaqueMessage:
        return self.registry.decode(
            CLIENT_TO_SERVER,
            frame,
            self.client_to_server_references,
            allow_unknown=allow_unknown,
        )

    def encode_server_message(self, type_id: int, value: object) -> MessageFrame:
        return self.registry.encode(
            SERVER_TO_CLIENT,
            type_id,
            value,
            self.server_to_client_references,
        )

    def decode_server_frame(
        self,
        frame: MessageFrame,
        *,
        allow_unknown: bool = True,
    ) -> DecodedMessage | OpaqueMessage:
        return self.registry.decode(
            SERVER_TO_CLIENT,
            frame,
            self.server_to_client_references,
            allow_unknown=allow_unknown,
        )

    def encode_client_message(self, type_id: int, value: object) -> MessageFrame:
        return self.registry.encode(
            CLIENT_TO_SERVER,
            type_id,
            value,
            self.client_to_server_references,
        )


class MessageReplayDecoder:
    """Decode a captured server-to-client byte stream with session state."""

    def __init__(
        self,
        session: ProtocolSession | None = None,
        *,
        allow_unknown: bool = True,
        maximum_frame_length: int = 1_000_000,
    ) -> None:
        self.session = session if session is not None else ProtocolSession()
        self.allow_unknown = allow_unknown
        self.framer = InboundFrameStreamDecoder(
            maximum_frame_length=maximum_frame_length
        )

    def feed(self, data: bytes) -> tuple[DecodedMessage | OpaqueMessage, ...]:
        return tuple(
            self.session.decode_server_frame(frame, allow_unknown=self.allow_unknown)
            for frame in self.framer.feed(data)
        )
