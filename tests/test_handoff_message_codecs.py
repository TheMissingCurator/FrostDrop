"""Synthetic wire fixtures for partially and fully decoded handoff messages."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from isac_protocol.codec import DecodeError
from isac_protocol.handoff_messages import (
    Type01AE, Type015ABPrefix, decode_type01ae, decode_type015ab_prefix,
    encode_type01ae, encode_type015ab_prefix,
)


class HandoffMessageCodecTests(unittest.TestCase):
    def test_type01ae_signed_values_and_flags_round_trip(self):
        value = Type01AE((-17, 0, 2147483647), (-2147483648, 12, 42), (False, True))
        self.assertEqual(decode_type01ae(encode_type01ae(value)), value)

    def test_type01ae_rejects_extra_or_short_body(self):
        for body in (bytes(7), bytes(9)):
            with self.subTest(length=len(body)), self.assertRaises(DecodeError):
                decode_type01ae(body)

    def test_type015ab_prefix_preserves_unresolved_components(self):
        value = Type015ABPrefix(4647, 0x1167, b"synthetic-components")
        self.assertEqual(decode_type015ab_prefix(encode_type015ab_prefix(value)), value)

    def test_type015ab_prefix_requires_two_fields(self):
        with self.assertRaises(DecodeError):
            decode_type015ab_prefix(b"\x01")


if __name__ == "__main__":
    unittest.main()
