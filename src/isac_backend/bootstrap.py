"""Application-layer state machine for the first local-backend exchanges."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

from isac_protocol import (
    DecodeError,
    MessageFrame,
    OutboundEnvelope,
    OutboundEnvelopeStreamDecoder,
    ProtocolSession,
    Type0002,
    Type0003,
    Type0006,
    encode_length_prefixed_frame,
)
from isac_protocol.codec import Cursor


class BootstrapProtocolError(ValueError):
    """Raised when a client envelope violates the configured bootstrap flow."""


class BootstrapPhase(str, Enum):
    WAITING_FOR_LOGIN = "waiting_for_login"
    LOGIN_ACCEPTED = "login_accepted"
    CONTROL_READY = "control_ready"


@dataclass(frozen=True)
class BootstrapProfile:
    """Locally supplied response values and observed request selectors.

    Response models are explicit rather than copied from captures. This keeps
    account/session values out of the repository and makes the remaining
    unknown semantics visible to callers.
    """

    login_response: Type0002 | Type0003 | None
    control_response: Type0006 | None
    expected_marker: int = 3
    login_request_type: int = 0x0002
    control_request_type: int = 0x0005
    control_request_channel: int = 0x0A
    correlate_control_response: bool = True
    world_request_channel: int = 0
    world_request_type: int = 0x0000
    world_request_min_body_bytes: int = 512
    world_request_max_body_bytes: int = 2048

    def __post_init__(self) -> None:
        if self.login_response is not None and not isinstance(
            self.login_response,
            (Type0002, Type0003),
        ):
            raise ValueError("login response must be type 0x0002 or 0x0003")
        if self.expected_marker < 0 or self.expected_marker > 0xFF:
            raise ValueError("expected marker must fit in one byte")
        for name, value in (
            ("login request type", self.login_request_type),
            ("control request type", self.control_request_type),
        ):
            if value < 0 or value > 0xFFFF:
                raise ValueError(f"{name} must fit in 16 bits")
        if self.control_request_channel < 0 or self.control_request_channel > 0xFF:
            raise ValueError("control request channel must fit in one byte")
        if self.world_request_channel < 0 or self.world_request_channel > 0xFF:
            raise ValueError("world request channel must fit in one byte")
        if self.world_request_type < 0 or self.world_request_type > 0xFFFF:
            raise ValueError("world request type must fit in 16 bits")
        if (
            self.world_request_min_body_bytes < 0
            or self.world_request_max_body_bytes < self.world_request_min_body_bytes
        ):
            raise ValueError("invalid world request body-length range")


@dataclass(frozen=True)
class BootstrapEvent:
    phase_before: BootstrapPhase
    phase_after: BootstrapPhase
    channel: int
    request_type_ids: tuple[int, ...]
    responses: tuple[MessageFrame, ...]
    control_correlation_id: int | None = None
    world_request_selected: bool = False


class BootstrapStateMachine:
    """Consumes decoded client envelopes and emits typed server frames."""

    def __init__(
        self,
        profile: BootstrapProfile,
        *,
        session: ProtocolSession | None = None,
    ) -> None:
        self.profile = profile
        self.session = session if session is not None else ProtocolSession()
        self.phase = BootstrapPhase.WAITING_FOR_LOGIN

    def _encode_response(self, type_id: int, value: object) -> MessageFrame:
        return self.session.encode_server_message(type_id, value)

    def _control_correlation_id(self, envelope: OutboundEnvelope) -> int:
        frame = next(
            frame
            for frame in envelope.frames
            if frame.type_id == self.profile.control_request_type
        )
        try:
            return Cursor(frame.body).read_uvarint(maximum_bits=32)
        except DecodeError as error:
            raise BootstrapProtocolError(
                "control request does not contain a valid leading "
                "correlation varint"
            ) from error

    def handle_envelope(self, envelope: OutboundEnvelope) -> BootstrapEvent:
        if envelope.marker != self.profile.expected_marker:
            raise BootstrapProtocolError(
                f"expected envelope marker {self.profile.expected_marker:#04x}, "
                f"got {envelope.marker:#04x}"
            )

        before = self.phase
        type_ids = tuple(frame.type_id for frame in envelope.frames)
        responses: list[MessageFrame] = []
        control_correlation_id: int | None = None
        world_request_selected = False

        if self.phase is BootstrapPhase.WAITING_FOR_LOGIN:
            if self.profile.login_request_type not in type_ids:
                raise BootstrapProtocolError(
                    "first envelope does not contain configured login request "
                    f"type {self.profile.login_request_type:#06x}"
                )
            if self.profile.login_response is not None:
                response_type = (
                    0x0003
                    if isinstance(self.profile.login_response, Type0003)
                    else 0x0002
                )
                responses.append(
                    self._encode_response(
                        response_type,
                        self.profile.login_response,
                    )
                )
            self.phase = BootstrapPhase.LOGIN_ACCEPTED
        elif (
            self.phase is BootstrapPhase.LOGIN_ACCEPTED
            and self.profile.control_request_type in type_ids
            and envelope.channel == self.profile.control_request_channel
        ):
            control_correlation_id = self._control_correlation_id(envelope)
            if self.profile.control_response is not None:
                response = self.profile.control_response
                if self.profile.correlate_control_response:
                    response = replace(
                        response,
                        request_id=control_correlation_id,
                    )
                responses.append(
                    self._encode_response(0x0006, response)
                )
            self.phase = BootstrapPhase.CONTROL_READY

        if (
            self.phase is not BootstrapPhase.WAITING_FOR_LOGIN
            and envelope.channel == self.profile.world_request_channel
            and len(envelope.frames) == 1
            and envelope.frames[0].type_id == self.profile.world_request_type
            and self.profile.world_request_min_body_bytes
            <= len(envelope.frames[0].body)
            <= self.profile.world_request_max_body_bytes
        ):
            world_request_selected = True

        return BootstrapEvent(
            phase_before=before,
            phase_after=self.phase,
            channel=envelope.channel,
            request_type_ids=type_ids,
            responses=tuple(responses),
            control_correlation_id=control_correlation_id,
            world_request_selected=world_request_selected,
        )


@dataclass(frozen=True)
class BootstrapBatch:
    events: tuple[BootstrapEvent, ...]
    server_bytes: bytes


@dataclass
class BootstrapConnection:
    """Incremental plaintext adapter suitable for a future TLS transport."""

    state_machine: BootstrapStateMachine
    decoder: OutboundEnvelopeStreamDecoder = field(
        default_factory=OutboundEnvelopeStreamDecoder
    )

    @property
    def buffered_client_bytes(self) -> int:
        return self.decoder.buffered_bytes

    def feed_client_bytes(self, data: bytes) -> BootstrapBatch:
        events: list[BootstrapEvent] = []
        encoded = bytearray()
        for envelope in self.decoder.feed(data):
            event = self.state_machine.handle_envelope(envelope)
            events.append(event)
            for response in event.responses:
                encoded.extend(encode_length_prefixed_frame(response))
        return BootstrapBatch(tuple(events), bytes(encoded))
