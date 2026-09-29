from datetime import timedelta
import unittest

import test_local_auth
from isac_backend.channels import Registration
from isac_backend.profiles import ProfileSession
from isac_protocol.codec import DecodeError, encode_length_prefixed_bytes, encode_uvarint
from isac_protocol.control_messages import decode_type0003
from isac_protocol.framing import MessageFrame, decode_length_prefixed_frame
from isac_protocol.profile_messages import (
    EmptyProfileList, decode_empty_profile_list, decode_profile_connect,
    decode_unfiltered_profile_list_request, encode_empty_profile_list,
)
from isac_protocol.transport import channel_payload


class ProfileCodecTests(unittest.TestCase):
    def test_empty_golden_and_request_id_not_boolean(self):
        self.assertEqual(decode_unfiltered_profile_list_request(b'\x81\x01\0'), 129)
        value = EmptyProfileList(129, True, False, False, 0, b'')
        wire = b'\x81\x01\1\0\0\0\0\0'
        self.assertEqual(encode_empty_profile_list(value), wire)
        self.assertEqual(decode_empty_profile_list(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_empty_profile_list(wire[:cut])
        for bad in (wire + b'\0', wire[:-1] + b'\1', b'\0\2' + bytes(5)):
            with self.assertRaises(DecodeError):
                decode_empty_profile_list(bad)

    def test_bounds_and_unsupported_shapes(self):
        for bad in (b'', b'\0', b'\0\1', b'\0\0\0', b'\xff' * 10):
            with self.assertRaises(DecodeError):
                decode_unfiltered_profile_list_request(bad)
        for bad in (b'', b'\0\1', b'\1x', b'\1x\1\0', b'\xff' * 10):
            with self.assertRaises(DecodeError):
                decode_profile_connect(bad)
        self.assertEqual(decode_profile_connect(b'\1x\x81\1'), (b'x',129))
        for length in (0,63):
            value = EmptyProfileList(2**32-1, True, True, False, 2**32-1, b'x'*length)
            self.assertEqual(decode_empty_profile_list(encode_empty_profile_list(value)), value)
        with self.assertRaises(ValueError):
            encode_empty_profile_list(EmptyProfileList(0, True, False, False, 0, bytes(64)))


class ProfileSessionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_local_auth.LocalAuthTests()
        self.fixture.setUp()
        self.auth = self.fixture.auth
        result = self.auth.handle(0, self.fixture.registration, self.fixture.request)
        _, payload = channel_payload(result.response)
        self.reply = decode_type0003(decode_length_prefixed_frame(payload).body, None)
        self.token = self.reply.timed_blob_0.bytes_0
        self.profiles = ProfileSession(self.auth)
        self.addCleanup(self.profiles.store.close)
        self.registration = Registration(40, b'profile_client', next(iter(self.profiles.targets)))
        self.connect = MessageFrame(0, encode_length_prefixed_bytes(self.token) + encode_uvarint(8640))
        self.request = MessageFrame(1, b'\x81\1\0')

    def handle(self, frame):
        return self.profiles.handle(37, self.registration, frame)

    def test_auth_close_token_handoff_correlation_and_duplicate(self):
        self.auth.close(0)  # Real game closes auth before finishing service setup.
        self.assertEqual(self.handle(self.connect).stage, 'profile-local-token-bound')
        event = self.handle(self.request)
        channel, payload = channel_payload(event.response)
        self.assertEqual(channel, 37)
        frame = decode_length_prefixed_frame(payload)
        self.assertEqual(frame.type_id, 2)
        self.assertEqual(decode_empty_profile_list(frame.body), EmptyProfileList(129,True,False,False,1800,b'default_start_zone'))
        self.assertEqual(self.handle(self.request).stage, 'profile-duplicate-ignored')
        self.profiles.close(37)
        self.assertEqual(self.handle(self.request).stage, 'profile-not-authenticated')

    def test_exact_binding_and_no_blanket_ack(self):
        for registration in (Registration(1,b'profile_cache_front',self.registration.target),
                             Registration(1,b'profile_client',b'unknown')):
            self.assertEqual(self.profiles.handle(37,registration,self.connect).stage,'unbound-observe-only')
        self.assertIsNone(self.handle(self.connect).response)
        self.assertEqual(self.handle(MessageFrame(9,b'')).stage,'profile-unsupported-message')
        self.assertEqual(self.handle(MessageFrame(1,b'\0\1')).stage,'profile-unsupported-list-request')

    def test_forged_other_token_expired_and_revoked(self):
        for token in (b'forged',self.reply.timed_blob_1.bytes_0):
            request = MessageFrame(0,encode_length_prefixed_bytes(token)+b'\1')
            self.assertEqual(self.handle(request).stage,'profile-token-rejected')
        self.handle(self.connect)
        self.fixture.now += timedelta(seconds=8640)
        self.assertEqual(self.handle(self.request).stage,'profile-not-authenticated')
        self.fixture.now -= timedelta(seconds=8640)
        del self.fixture.sdk.sessions[self.fixture.session['sessionId']]
        self.assertEqual(self.handle(self.request).stage,'profile-not-authenticated')

    def test_connection_scope_conflict_and_limit(self):
        self.handle(self.connect)
        other = self.auth.handle(9,self.fixture.registration,self.fixture.request)
        _,payload = channel_payload(other.response)
        token = decode_type0003(decode_length_prefixed_frame(payload).body,None).timed_blob_0.bytes_0
        self.assertEqual(self.handle(MessageFrame(0,encode_length_prefixed_bytes(token)+b'\1')).stage,
                         'profile-conflicting-connect')
        from isac_backend.auth import AuthSession
        fresh = ProfileSession(AuthSession(self.auth.validator,self.auth.clock))
        self.addCleanup(fresh.store.close)
        self.assertEqual(fresh.handle(37,self.registration,self.connect).stage,'profile-token-rejected')
        for _ in range(130):
            result = self.handle(self.request)
        self.assertEqual(result.stage,'profile-attempt-limit')
        self.assertIsNone(result.response)


if __name__ == '__main__':
    unittest.main()
