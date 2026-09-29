import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_protocol.certificate_bootstrap import (
    decode_certificate_bootstrap,
    encode_certificate_bootstrap,
)
from isac_protocol.codec import DecodeError


class CertificateBootstrapTests(unittest.TestCase):
    def test_observed_659_byte_framing(self):
        # Synthetic bytes, but the exact nine-byte prefix seen in the capture.
        certificate = b"x" * 659
        wire = bytes.fromhex("07 03 af 02 ac 0a 00 93 05") + certificate
        self.assertEqual(encode_certificate_bootstrap(certificate), wire)
        self.assertEqual(decode_certificate_bootstrap(wire), certificate)

    def test_lengths_are_generated_not_replayed(self):
        for length in (1, 63, 64, 127, 128, 512, 659, 10000):
            with self.subTest(length=length):
                cert = bytes(index % 256 for index in range(length))
                self.assertEqual(decode_certificate_bootstrap(encode_certificate_bootstrap(cert)), cert)

    def test_every_truncated_prefix_rejected(self):
        wire = encode_certificate_bootstrap(b"x" * 659)
        for length in range(len(wire)):
            with self.subTest(length=length), self.assertRaises(DecodeError):
                decode_certificate_bootstrap(wire[:length])

    def test_invalid_control_type_version_flags_and_trailing_bytes(self):
        wire = encode_certificate_bootstrap(b"x" * 659)
        for offset, value in ((0, 6), (1, 2), (2, 0xae), (4, 0xad), (6, 1)):
            bad = bytearray(wire)
            bad[offset] = value
            with self.subTest(offset=offset), self.assertRaises(DecodeError):
                decode_certificate_bootstrap(bytes(bad))
        with self.assertRaises(DecodeError):
            decode_certificate_bootstrap(wire + b"\0")

    def test_certificate_limits(self):
        for data in (b"", b"x" * 10001):
            with self.assertRaises(ValueError):
                encode_certificate_bootstrap(data)
        with self.assertRaises(DecodeError):
            decode_certificate_bootstrap(bytes.fromhex("0703af02040000"))
        with self.assertRaises(DecodeError):
            decode_certificate_bootstrap(bytes.fromhex("0703af020600914e"))


if __name__ == "__main__":
    unittest.main()
