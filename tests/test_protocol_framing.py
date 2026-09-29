#!/usr/bin/env python3
"""Tests for application framing and transport-chunk reassembly."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    DecodeError,
    InboundFrameStreamDecoder,
    MessageFrame,
    OutboundEnvelope,
    OutboundEnvelopeStreamDecoder,
    decode_length_prefixed_frame,
    decode_outbound_envelope,
    encode_length_prefixed_frame,
    encode_outbound_envelope,
)


class ProtocolFramingTests(unittest.TestCase):
    def test_inbound_frame_round_trip_with_multibyte_type(self) -> None:
        frame = MessageFrame(0x014D, b"payload")
        encoded = encode_length_prefixed_frame(frame)
        self.assertEqual(decode_length_prefixed_frame(encoded), frame)

    def test_outbound_multi_frame_envelope_round_trip(self) -> None:
        envelope = OutboundEnvelope(
            marker=3,
            channel=2,
            frames=(MessageFrame(0x0F, b"a"), MessageFrame(0x88, bytes(300))),
        )
        encoded = encode_outbound_envelope(envelope)
        self.assertEqual(decode_outbound_envelope(encoded), envelope)

    def test_inbound_stream_reassembles_every_byte_split(self) -> None:
        expected = (MessageFrame(1, b"abc"), MessageFrame(0x102, bytes(140)))
        encoded = b"".join(encode_length_prefixed_frame(frame) for frame in expected)
        decoder = InboundFrameStreamDecoder()
        actual = []
        for byte in encoded:
            actual.extend(decoder.feed(bytes((byte,))))
        self.assertEqual(tuple(actual), expected)
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_outbound_stream_reassembles_multiple_envelopes(self) -> None:
        expected = (
            OutboundEnvelope(3, 0, (MessageFrame(0x11, b"first"),)),
            OutboundEnvelope(
                3,
                2,
                (MessageFrame(0x88, bytes(180)), MessageFrame(4, b"last")),
            ),
        )
        encoded = b"".join(encode_outbound_envelope(value) for value in expected)
        decoder = OutboundEnvelopeStreamDecoder()
        actual = []
        for offset in range(0, len(encoded), 7):
            actual.extend(decoder.feed(encoded[offset : offset + 7]))
        self.assertEqual(tuple(actual), expected)
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_rejects_negative_zigzag_length(self) -> None:
        with self.assertRaisesRegex(DecodeError, "negative ZigZag"):
            decode_length_prefixed_frame(b"\x01")

    def test_rejects_frame_over_stream_safety_limit(self) -> None:
        decoder = InboundFrameStreamDecoder(maximum_frame_length=4)
        with self.assertRaisesRegex(DecodeError, "configured maximum"):
            decoder.feed(b"\x0a")


if __name__ == "__main__":
    unittest.main()
