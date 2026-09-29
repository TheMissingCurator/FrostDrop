from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_protocol.codec import DecodeError, encode_uvarint
from isac_protocol.transport import (
    TransportFrame, TransportStreamDecoder, channel_payload,
    encode_protocol_version, encode_transport_frame,
)


class TransportTests(unittest.TestCase):
    def test_known_control_versions(self):
        self.assertEqual(encode_protocol_version(303), bytes.fromhex("0703af02"))
        self.assertEqual(encode_protocol_version(2056), bytes.fromhex("07038810"))

    def test_fragmentation_and_coalescing_preserve_control_flag(self):
        frames = [TransportFrame(True, 3, encode_uvarint(2056)),
                  TransportFrame(False, 8, b"opaque" * 100),
                  TransportFrame(False, 3, b"\x0a\x03abc")]
        wire = b"".join(map(encode_transport_frame, frames))
        for chunk in (1, 2, 3, 127, len(wire)):
            decoder = TransportStreamDecoder()
            actual = []
            for offset in range(0, len(wire), chunk):
                actual.extend(decoder.feed(wire[offset:offset + chunk]))
            decoder.finish()
            self.assertEqual(actual, frames)

    def test_channel_body_is_not_assumed_to_be_response_channel(self):
        frame = TransportFrame(False, 3, b"\x80\x01\x03abc")
        self.assertEqual(channel_payload(frame), (128, b"abc"))
        for bad in (TransportFrame(True, 3, frame.body),
                    TransportFrame(False, 1, frame.body),
                    TransportFrame(False, 3, b"\x01\x04abc"),
                    TransportFrame(False, 3, b"\x01\x02abc")):
            with self.assertRaises(DecodeError):
                channel_payload(bad)

    def test_invalid_and_oversize_frames_fail_closed(self):
        for wire in (b"\x00", b"\x01", b"\x80" * 5,
                     b"\xff\xff\xff\xff\x10", encode_uvarint(65 << 1),
                     b"\x02\x80", b"x" * 70):
            decoder = TransportStreamDecoder(64)
            with self.assertRaises(DecodeError):
                decoder.feed(wire)
            self.assertEqual(decoder.pending_bytes, 0)
            with self.assertRaises(DecodeError):
                decoder.feed(b"")

    def test_truncated_stream_is_not_complete(self):
        for wire in (b"\x80", b"\x06\x03"):
            decoder = TransportStreamDecoder()
            self.assertEqual(decoder.feed(wire), [])
            with self.assertRaises(DecodeError):
                decoder.finish()


if __name__ == "__main__":
    unittest.main()
