#!/usr/bin/env python3
"""Tests for the central message registry and session state."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    CLIENT_TO_SERVER,
    CompactReference,
    MessageCodec,
    MessageFrame,
    MessageReplayDecoder,
    MessageRegistry,
    OpaqueMessage,
    ProtocolSession,
    ReferenceTable,
    SERVER_TO_CLIENT,
    Type0020,
    UnsupportedMessageType,
    build_default_registry,
    encode_length_prefixed_frame,
)


class ProtocolRegistryTests(unittest.TestCase):
    def test_default_registry_contains_all_completed_codecs(self) -> None:
        self.assertEqual(
            build_default_registry().type_ids(SERVER_TO_CLIENT),
            (
                0x0002,
                0x0003,
                0x0006,
                0x0020,
                0x0023,
                0x0024,
                0x002A,
                0x002D,
                0x0067,
                0x006C,
                0x0088,
                0x00E6,
                0x00E8,
                0x014D,
                0x0157,
                0x0167,
                0x019D,
            ),
        )
        self.assertEqual(
            build_default_registry().type_ids(CLIENT_TO_SERVER),
            (0x000C, 0x0088),
        )

    def test_unknown_frame_can_remain_opaque(self) -> None:
        session = ProtocolSession.from_midstream_capture()
        result = session.decode_server_frame(MessageFrame(0x7777, b"unknown"))
        self.assertEqual(result, OpaqueMessage(0x7777, b"unknown"))

    def test_unknown_frame_can_be_rejected(self) -> None:
        session = ProtocolSession.from_midstream_capture()
        with self.assertRaises(UnsupportedMessageType):
            session.decode_server_frame(
                MessageFrame(0x7777, b"unknown"), allow_unknown=False
            )

    def test_reference_table_state_survives_across_messages(self) -> None:
        value = bytes(range(16))
        registry = build_default_registry()
        sender_table = ReferenceTable()
        receiver_table = ReferenceTable()
        message = Type0020(CompactReference(value=value), 7)

        first_frame = registry.encode(
            SERVER_TO_CLIENT, 0x0020, message, sender_table
        )
        second_frame = registry.encode(
            SERVER_TO_CLIENT, 0x0020, message, sender_table
        )
        first = registry.decode(
            SERVER_TO_CLIENT, first_frame, receiver_table, allow_unknown=False
        )
        second = registry.decode(
            SERVER_TO_CLIENT, second_frame, receiver_table, allow_unknown=False
        )

        self.assertGreater(len(first_frame.body), len(second_frame.body))
        self.assertEqual(first.value.reference_0.value, value)
        self.assertEqual(second.value.reference_0.value, value)
        self.assertEqual(sender_table.entries, [value])
        self.assertEqual(receiver_table.entries, [value])

    def test_replay_decoder_combines_chunking_registry_and_reference_state(self) -> None:
        value = bytes(reversed(range(16)))
        registry = build_default_registry()
        sender_table = ReferenceTable()
        frames = (
            registry.encode(
                SERVER_TO_CLIENT,
                0x0020,
                Type0020(CompactReference(value=value), 1),
                sender_table,
            ),
            registry.encode(
                SERVER_TO_CLIENT,
                0x0020,
                Type0020(CompactReference(value=value), 2),
                sender_table,
            ),
            MessageFrame(0x7777, b"opaque"),
        )
        wire = b"".join(encode_length_prefixed_frame(frame) for frame in frames)
        replay = MessageReplayDecoder()
        decoded = []
        for byte in wire:
            decoded.extend(replay.feed(bytes((byte,))))

        self.assertEqual(decoded[0].value.reference_0.value, value)
        self.assertEqual(decoded[1].value.reference_0.value, value)
        self.assertEqual(decoded[2], OpaqueMessage(0x7777, b"opaque"))
        self.assertEqual(replay.framer.buffered_bytes, 0)

    def test_registry_checks_model_type_before_encoding(self) -> None:
        registry = build_default_registry()
        with self.assertRaisesRegex(TypeError, "requires Type0020"):
            registry.encode(
                SERVER_TO_CLIENT, 0x0020, object(), ReferenceTable()
            )

    def test_duplicate_registration_is_rejected(self) -> None:
        registry = MessageRegistry()
        codec = MessageCodec(
            direction=SERVER_TO_CLIENT,
            type_id=1,
            name="test",
            model_type=bytes,
            decoder=lambda data, table: data,
            encoder=lambda value, table: value,
        )
        registry.register(codec)
        with self.assertRaisesRegex(ValueError, "already registered"):
            registry.register(codec)


if __name__ == "__main__":
    unittest.main()
