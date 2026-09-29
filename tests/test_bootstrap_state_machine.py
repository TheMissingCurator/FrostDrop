#!/usr/bin/env python3
"""Tests for the local application-layer bootstrap state machine."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_backend import (  # noqa: E402
    BootstrapConnection,
    BootstrapPhase,
    BootstrapProfile,
    BootstrapProtocolError,
    BootstrapStateMachine,
)
from isac_protocol import (  # noqa: E402
    ControlIdentity,
    InboundFrameStreamDecoder,
    MessageFrame,
    OutboundEnvelope,
    Type0002,
    Type0002Payload,
    Type0003,
    Type0003Bundle,
    Type0003TimedBlob,
    Type0006,
    Type0006Details,
    decode_type0002,
    decode_type0003,
    decode_type0006,
    encode_outbound_envelope,
)
from isac_protocol.codec import encode_uvarint  # noqa: E402


def profile() -> BootstrapProfile:
    return BootstrapProfile(
        login_response=Type0002(
            request_id=17,
            payload=Type0002Payload(ControlIdentity(1, b"local"), flags=0),
        ),
        control_response=Type0006(
            request_id=23,
            presence=1,
            details=Type0006Details(
                bytes_0=b"control",
                identity=ControlIdentity(2, b"offline"),
            ),
        ),
    )


def envelope(
    channel: int,
    *type_ids: int,
    marker: int = 3,
    bodies: dict[int, bytes] | None = None,
) -> bytes:
    bodies = bodies or {}
    return encode_outbound_envelope(
        OutboundEnvelope(
            marker=marker,
            channel=channel,
            frames=tuple(
                MessageFrame(type_id, bodies.get(type_id, b"opaque"))
                for type_id in type_ids
            ),
        )
    )


class BootstrapStateMachineTests(unittest.TestCase):
    def test_fragmented_login_request_emits_typed_response(self) -> None:
        connection = BootstrapConnection(BootstrapStateMachine(profile()))
        wire = envelope(0, 0x0002)

        first = connection.feed_client_bytes(wire[:2])
        self.assertEqual(first.events, ())
        self.assertEqual(first.server_bytes, b"")
        self.assertEqual(connection.buffered_client_bytes, 2)

        second = connection.feed_client_bytes(wire[2:])
        self.assertEqual(len(second.events), 1)
        self.assertEqual(second.events[0].phase_before, BootstrapPhase.WAITING_FOR_LOGIN)
        self.assertEqual(second.events[0].phase_after, BootstrapPhase.LOGIN_ACCEPTED)
        self.assertEqual(second.events[0].channel, 0)

        frames = InboundFrameStreamDecoder().feed(second.server_bytes)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].type_id, 0x0002)
        self.assertEqual(decode_type0002(frames[0].body, None), profile().login_response)

    def test_intermediate_envelopes_are_observed_without_guessing_responses(self) -> None:
        machine = BootstrapStateMachine(profile())
        connection = BootstrapConnection(machine)
        connection.feed_client_bytes(envelope(0, 0x0002))

        batch = connection.feed_client_bytes(envelope(1, 0x0000, 0x0001))
        self.assertEqual(batch.server_bytes, b"")
        self.assertEqual(batch.events[0].request_type_ids, (0x0000, 0x0001))
        self.assertEqual(machine.phase, BootstrapPhase.LOGIN_ACCEPTED)

    def test_retail_login_profile_emits_type0003(self) -> None:
        login_response = Type0003(
            0,
            Type0003TimedBlob(b"", 0),
            Type0003TimedBlob(b"", 0),
            ControlIdentity(0, b""),
            b"",
            False,
            False,
            False,
            Type0003Bundle(False, False, False, False, False, False, False, ()),
            Type0003TimedBlob(b"", 0),
        )
        selected = replace(profile(), login_response=login_response)
        batch = BootstrapConnection(
            BootstrapStateMachine(selected)
        ).feed_client_bytes(envelope(0, 0x0002))

        frames = InboundFrameStreamDecoder().feed(batch.server_bytes)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].type_id, 0x0003)
        self.assertEqual(decode_type0003(frames[0].body, None), login_response)

    def test_control_request_emits_type0006_and_advances(self) -> None:
        machine = BootstrapStateMachine(profile())
        connection = BootstrapConnection(machine)
        connection.feed_client_bytes(envelope(0, 0x0002))

        batch = connection.feed_client_bytes(
            envelope(
                10,
                0x0000,
                0x0005,
                bodies={0x0005: encode_uvarint(42, maximum_bits=32) + b"opaque"},
            )
        )
        frames = InboundFrameStreamDecoder().feed(batch.server_bytes)
        self.assertEqual(machine.phase, BootstrapPhase.CONTROL_READY)
        self.assertEqual(frames[0].type_id, 0x0006)
        self.assertEqual(
            decode_type0006(frames[0].body, None),
            replace(profile().control_response, request_id=42),
        )
        self.assertEqual(batch.events[0].control_correlation_id, 42)

    def test_multiple_envelopes_can_arrive_in_one_chunk(self) -> None:
        connection = BootstrapConnection(BootstrapStateMachine(profile()))
        batch = connection.feed_client_bytes(
            envelope(0, 0x0002) + envelope(10, 0x0005)
        )
        self.assertEqual(len(batch.events), 2)
        self.assertEqual(
            tuple(frame.type_id for frame in InboundFrameStreamDecoder().feed(batch.server_bytes)),
            (0x0002, 0x0006),
        )

    def test_first_envelope_must_contain_login_selector(self) -> None:
        machine = BootstrapStateMachine(profile())
        with self.assertRaisesRegex(BootstrapProtocolError, "first envelope"):
            machine.handle_envelope(
                OutboundEnvelope(3, 0, (MessageFrame(0x0001, b""),))
            )
        self.assertEqual(machine.phase, BootstrapPhase.WAITING_FOR_LOGIN)

    def test_world_channel_type0005_does_not_advance_bootstrap(self) -> None:
        machine = BootstrapStateMachine(profile())
        connection = BootstrapConnection(machine)
        connection.feed_client_bytes(envelope(0, 0x0002))

        batch = connection.feed_client_bytes(
            envelope(9, 0x0005, bodies={0x0005: encode_uvarint(224)})
        )

        self.assertEqual(batch.server_bytes, b"")
        self.assertEqual(batch.events[0].control_correlation_id, None)
        self.assertEqual(machine.phase, BootstrapPhase.LOGIN_ACCEPTED)

    def test_large_channel_zero_type0000_selects_world_replay(self) -> None:
        connection = BootstrapConnection(BootstrapStateMachine(profile()))
        connection.feed_client_bytes(envelope(0, 0x0002))

        small = connection.feed_client_bytes(
            envelope(0, 0x0000, bodies={0x0000: bytes(100)})
        )
        selected = connection.feed_client_bytes(
            envelope(0, 0x0000, bodies={0x0000: bytes(733)})
        )

        self.assertFalse(small.events[0].world_request_selected)
        self.assertTrue(selected.events[0].world_request_selected)
        self.assertEqual(selected.server_bytes, b"")

    def test_control_request_requires_leading_correlation_varint(self) -> None:
        machine = BootstrapStateMachine(profile())
        connection = BootstrapConnection(machine)
        connection.feed_client_bytes(envelope(0, 0x0002))

        with self.assertRaisesRegex(BootstrapProtocolError, "correlation varint"):
            connection.feed_client_bytes(
                envelope(10, 0x0005, bodies={0x0005: b""})
            )
        self.assertEqual(machine.phase, BootstrapPhase.LOGIN_ACCEPTED)

    def test_marker_is_validated(self) -> None:
        connection = BootstrapConnection(BootstrapStateMachine(profile()))
        with self.assertRaisesRegex(BootstrapProtocolError, "marker"):
            connection.feed_client_bytes(envelope(0, 0x0002, marker=4))

    def test_profile_can_observe_without_emitting_unproven_values(self) -> None:
        machine = BootstrapStateMachine(BootstrapProfile(None, None))
        connection = BootstrapConnection(machine)
        first = connection.feed_client_bytes(envelope(0, 0x0002))
        second = connection.feed_client_bytes(envelope(10, 0x0005))
        self.assertEqual(first.server_bytes, b"")
        self.assertEqual(second.server_bytes, b"")
        self.assertEqual(machine.phase, BootstrapPhase.CONTROL_READY)


if __name__ == "__main__":
    unittest.main()
