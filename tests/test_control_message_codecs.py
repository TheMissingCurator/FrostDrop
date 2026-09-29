#!/usr/bin/env python3
"""Tests for early control-message schemas recovered from runtime code."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    ControlIdentity,
    DecodeError,
    Type0002,
    Type0002Entry,
    Type0002Metadata,
    Type0002Payload,
    Type0002TaggedValue,
    Type0003,
    Type0003Bundle,
    Type0003TimedBlob,
    Type0006,
    Type0006Details,
    decode_type0002,
    decode_type0003,
    decode_type0006,
    encode_type0002,
    encode_type0003,
    encode_type0006,
)


class ControlMessageCodecTests(unittest.TestCase):
    def assert_round_trip(self, message: object, encoder: object, decoder: object) -> None:
        wire = encoder(message, None)
        decoded = decoder(wire, None)
        self.assertEqual(decoded, message)
        self.assertEqual(encoder(decoded, None), wire)

    def test_type0002_short_variant(self) -> None:
        self.assert_round_trip(Type0002(request_id=300), encode_type0002, decode_type0002)

    def test_type0002_full_without_optional_fields(self) -> None:
        self.assert_round_trip(
            Type0002(
                request_id=7,
                payload=Type0002Payload(
                    identity=ControlIdentity(2, b"identity"),
                    flags=0,
                ),
            ),
            encode_type0002,
            decode_type0002,
        )

    def test_type0002_all_optional_fields_and_entries(self) -> None:
        metadata = Type0002Metadata(
            uint32_0=0xFFFFFFFF,
            signed_0=-(1 << 31),
            signed_1=(1 << 31) - 1,
            uint32_1=1,
            uint32_2=2,
            uint32_3=3,
            uint32_4=4,
            narrowed_uint32_0=0x1234,
            narrowed_uint32_1=0xABCDEF,
            byte_0=0,
            byte_1=1,
            byte_2=2,
            byte_3=3,
            byte_4=4,
            byte_5=5,
            byte_6=6,
            byte_7=7,
            byte_8=255,
            tagged_value=Type0002TaggedValue(
                discriminator=1,
                identifier=bytes(range(16)),
                uint32_0=99,
                uint32_1=100,
            ),
            identifier=bytes(reversed(range(16))),
            uint32_5=123456,
            bytes_0=b"metadata-bytes",
            entries=(
                Type0002Entry(
                    identity=ControlIdentity(3, b"entry-a"),
                    bytes_0=b"entry-payload",
                    uint32_0=77,
                    byte_0=8,
                    byte_1=9,
                ),
                Type0002Entry(
                    identity=ControlIdentity(4, b"entry-b"),
                    bytes_0=b"",
                    uint32_0=0,
                    byte_0=0,
                    byte_1=255,
                ),
            ),
        )
        self.assert_round_trip(
            Type0002(
                request_id=42,
                payload=Type0002Payload(
                    identity=ControlIdentity(1, b"root"),
                    flags=0x83,
                    embedded_0=b"opaque legacy object",
                    metadata=metadata,
                ),
            ),
            encode_type0002,
            decode_type0002,
        )

    def test_type0002_other_tagged_branches(self) -> None:
        for tagged in (
            Type0002TaggedValue(0),
            Type0002TaggedValue(4, bytes(16), uint32_0=8),
            Type0002TaggedValue(6, bytes(range(16))),
        ):
            metadata = Type0002Metadata(
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                tagged,
                bytes(16),
                0,
                b"",
                (),
            )
            self.assert_round_trip(
                Type0002(
                    1,
                    Type0002Payload(ControlIdentity(0, b""), 2, metadata=metadata),
                ),
                encode_type0002,
                decode_type0002,
            )

    def test_type0002_rejects_inconsistent_flags(self) -> None:
        message = Type0002(
            1,
            Type0002Payload(ControlIdentity(0, b""), 0, embedded_0=b"present"),
        )
        with self.assertRaisesRegex(ValueError, "flag bit 0"):
            encode_type0002(message, None)

    def test_type0002_rejects_excess_entry_count(self) -> None:
        # request, identity byte, identity length, flags=2, then enough metadata
        # to reach a deliberately invalid collection count of four.
        metadata = Type0002Metadata(
            0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
            Type0002TaggedValue(0), bytes(16), 0, b"", (),
        )
        wire = bytearray(
            encode_type0002(
                Type0002(
                    1,
                    Type0002Payload(
                        ControlIdentity(0, b""), 2, metadata=metadata
                    ),
                ),
                None,
            )
        )
        wire[-1] = 4
        with self.assertRaisesRegex(DecodeError, "entry count exceeds 3"):
            decode_type0002(bytes(wire), None)

    def test_type0003_round_trip(self) -> None:
        message = Type0003(
            byte_0=255,
            timed_blob_0=Type0003TimedBlob(b"first", 0),
            timed_blob_1=Type0003TimedBlob(bytes(range(64)), (1 << 64) - 1),
            identity=ControlIdentity(7, b"identity"),
            bytes_0=b"bounded\x00bytes",
            bool_0=True,
            bool_1=False,
            bool_2=True,
            bundle=Type0003Bundle(
                True,
                False,
                True,
                False,
                True,
                False,
                True,
                (b"", b"a", bytes(range(7))),
            ),
            timed_blob_2=Type0003TimedBlob(b"last", 123456789),
        )
        self.assert_round_trip(message, encode_type0003, decode_type0003)

    def test_type0003_empty_and_maximum_bounded_fields(self) -> None:
        message = Type0003(
            byte_0=0,
            timed_blob_0=Type0003TimedBlob(bytes(32768), 0),
            timed_blob_1=Type0003TimedBlob(b"", 1),
            identity=ControlIdentity(0, bytes(61)),
            bytes_0=bytes(63),
            bool_0=False,
            bool_1=False,
            bool_2=False,
            bundle=Type0003Bundle(
                False,
                False,
                False,
                False,
                False,
                False,
                False,
                (),
            ),
            timed_blob_2=Type0003TimedBlob(b"", 2),
        )
        self.assert_round_trip(message, encode_type0003, decode_type0003)

    def test_type0003_rejects_oversized_fields(self) -> None:
        base = Type0003(
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
        with self.assertRaisesRegex(ValueError, "exceeds maximum 32768"):
            encode_type0003(
                Type0003(
                    **{
                        **base.__dict__,
                        "timed_blob_0": Type0003TimedBlob(bytes(32769), 0),
                    }
                ),
                None,
            )
        with self.assertRaisesRegex(ValueError, "exceeds maximum 63"):
            encode_type0003(Type0003(**{**base.__dict__, "bytes_0": bytes(64)}), None)
        with self.assertRaisesRegex(ValueError, "exceeds maximum 7"):
            encode_type0003(
                Type0003(
                    **{
                        **base.__dict__,
                        "bundle": Type0003Bundle(
                            False,
                            False,
                            False,
                            False,
                            False,
                            False,
                            False,
                            (bytes(8),),
                        ),
                    }
                ),
                None,
            )

    def test_type0003_rejects_malformed_or_trailing_wire_data(self) -> None:
        # byte_0, then an impossible 64-bit-length-prefixed first blob.
        with self.assertRaisesRegex(DecodeError, "exceeds maximum 32768"):
            decode_type0003(b"\x00\x81\x80\x02", None)

        message = Type0003(
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
        with self.assertRaisesRegex(DecodeError, "trailing bytes"):
            decode_type0003(encode_type0003(message, None) + b"\x00", None)

    def test_type0006_absent_details(self) -> None:
        self.assert_round_trip(Type0006(17, 0), encode_type0006, decode_type0006)

    def test_type0006_present_details_preserves_noncanonical_presence(self) -> None:
        self.assert_round_trip(
            Type0006(
                request_id=18,
                presence=2,
                details=Type0006Details(
                    bytes_0=b"bounded\x00bytes",
                    identity=ControlIdentity(5, b"name"),
                ),
            ),
            encode_type0006,
            decode_type0006,
        )

    def test_type0006_rejects_trailing_bytes(self) -> None:
        with self.assertRaisesRegex(DecodeError, "trailing bytes"):
            decode_type0006(b"\x01\x00\xff", None)

    def test_bounded_fields_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds maximum 63"):
            encode_type0006(
                Type0006(
                    1,
                    1,
                    Type0006Details(bytes(64), ControlIdentity(0, b"")),
                ),
                None,
            )
        with self.assertRaisesRegex(ValueError, "exceeds maximum 61"):
            encode_type0002(
                Type0002(1, Type0002Payload(ControlIdentity(0, bytes(62)), 0)),
                None,
            )


if __name__ == "__main__":
    unittest.main()
