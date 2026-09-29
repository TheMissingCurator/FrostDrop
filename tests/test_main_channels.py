from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_backend.channels import ChannelSetup, decode_registration, initial_settings
from isac_backend.latency import LatencySession, latency_greeting
from isac_protocol.codec import DecodeError, encode_uvarint, encode_length_prefixed_bytes
from isac_protocol.framing import MessageFrame, encode_length_prefixed_frame
from isac_protocol.transport import TransportFrame, TransportStreamDecoder, encode_transport_frame


def registration(request=17, name=b"synthetic-service", target=b"synthetic-target"):
    return TransportFrame(False, 0, encode_uvarint(request)
        + encode_length_prefixed_bytes(name) + encode_length_prefixed_bytes(target))


class MainChannelsTests(unittest.TestCase):
    def test_settings_disable_policy_table_not_enable_empty_allowlist(self):
        self.assertEqual(encode_transport_frame(initial_settings()), bytes.fromhex("040700"))

    def test_registration_ack_correlates_and_allocates_channel(self):
        setup = ChannelSetup()
        first = setup.handle(registration())
        self.assertEqual(first.request_id, 17)
        self.assertEqual(first.channel, 0)
        self.assertEqual(first.responses, (TransportFrame(False, 1, b"\x11\x00\x01"),))
        self.assertEqual(setup.handle(registration()).responses, first.responses)
        self.assertEqual(setup.handle(registration(300)).channel, 1)

    def test_registration_limits_and_conflicts(self):
        setup = ChannelSetup(maximum_channels=1)
        setup.handle(registration())
        for bad in (registration(name=b"different"), registration(18)):
            with self.assertRaises(DecodeError):
                setup.handle(bad)
        for body in (b"", b"\x01\x40" + b"x" * 64 + b"\0",
                     b"\x01\x02a\0\x00", registration().body + b"\x00"):
            with self.assertRaises(DecodeError):
                decode_registration(body)

    def test_data_reassembles_on_registered_channel_without_guessing_application(self):
        setup = ChannelSetup()
        setup.handle(registration())
        inner = MessageFrame(2, b"opaque-login-candidate")
        wire = encode_length_prefixed_frame(inner)
        actual = []
        for byte in wire:
            event = setup.handle(TransportFrame(False, 3, b"\x00\x01" + bytes([byte])))
            self.assertFalse(event.responses)
            actual.extend(event.inner_frames)
        self.assertEqual(actual, [inner])
        with self.assertRaises(DecodeError):
            setup.handle(TransportFrame(False, 3, b"\x01\x00"))

    def test_close_does_not_reuse_channel_or_accept_late_data(self):
        setup = ChannelSetup()
        setup.handle(registration())
        self.assertEqual(setup.handle(TransportFrame(False, 2, b"\x00")).stage, "channel-closed")
        with self.assertRaises(DecodeError):
            setup.handle(registration())
        with self.assertRaises(DecodeError):
            setup.handle(TransportFrame(False, 3, b"\x00\x00"))
        self.assertEqual(setup.handle(registration(18)).channel, 1)

    def test_identity_is_opaque_heartbeat_is_separate(self):
        setup = ChannelSetup()
        event = setup.handle(TransportFrame(False, 8, b"\x03abc\x01"))
        self.assertEqual(event.stage, "opaque-identity-received")
        self.assertFalse(event.responses)
        self.assertEqual(setup.handle(TransportFrame(False, 9, b"")).responses,
                         (TransportFrame(False, 10, b""),))
        for frame in (TransportFrame(False, 8, b"\x03abc"),
                      TransportFrame(False, 9, b"x"), TransportFrame(False, 42, b""),
                      TransportFrame(True, 3, b"\xac\x04")):
            with self.assertRaises(DecodeError):
                setup.handle(frame)

    def test_multiple_registrations_are_separate_coalesced_transport_frames(self):
        decoder = TransportStreamDecoder()
        setup = ChannelSetup()
        frames = decoder.feed(encode_transport_frame(registration()) + encode_transport_frame(registration(18)))
        self.assertEqual([setup.handle(frame).channel for frame in frames], [0, 1])


class LatencyTests(unittest.TestCase):
    def test_greeting_matches_historical_protocol_shape(self):
        self.assertEqual(latency_greeting(), bytes.fromhex("0703ac040600c801"))

    def test_complete_three_probe_exchange(self):
        session = LatencySession()
        for sequence in range(3):
            self.assertEqual(session.handle(TransportFrame(False, 1, bytes([sequence]))),
                             TransportFrame(False, 2, bytes([sequence])))
        self.assertIsNone(session.handle(TransportFrame(False, 3, b"\x03\x06\x01\x03\x00")))
        self.assertTrue(session.complete)
        with self.assertRaises(DecodeError):
            session.handle(TransportFrame(False, 1, b"\0"))

    def test_wrong_sequence_type_truncation_and_early_summary(self):
        for frame in (TransportFrame(False, 1, b"\x01"), TransportFrame(False, 1, b"\0\0"),
                      TransportFrame(True, 1, b"\0"), TransportFrame(False, 2, b"\0"),
                      TransportFrame(False, 3, b"\x03\x06\x01\x03\x00"),
                      TransportFrame(False, 3, b"\x03")):
            with self.assertRaises(DecodeError):
                LatencySession().handle(frame)


if __name__ == "__main__":
    unittest.main()
