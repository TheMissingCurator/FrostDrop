from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import patch

import test_profile_token
from isac_backend.channels import Registration
from isac_backend.server_list import ServerListSession
from isac_protocol.codec import DecodeError, encode_length_prefixed_bytes, encode_uvarint
from isac_protocol.framing import MessageFrame, decode_length_prefixed_frame
from isac_protocol.server_list import (NormalJoinRequest, JoinReply,
    encode_normal_join_request, decode_normal_join_request, encode_join_reply,
    decode_join_reply, decode_server_list_connect, decode_instance_connect)
from isac_protocol.transport import channel_payload
from isac_protocol.game_connect import GameConnectReply, decode_game_connect_reply, encode_game_connect_reply


class ServerListCodecTests(unittest.TestCase):
    def test_game_connect_reply_is_raw_identifier_and_rejection_boolean(self):
        identifier = bytes(range(16))
        for rejected in (False, True):
            message = GameConnectReply(identifier, rejected)
            wire = identifier + bytes([rejected])
            self.assertEqual(encode_game_connect_reply(message), wire)
            self.assertEqual(decode_game_connect_reply(wire), message)
        for body in (b'', bytes(16), bytes(16) + b'\x02', bytes(18)):
            with self.assertRaises(DecodeError):
                decode_game_connect_reply(body)
        with self.assertRaises(ValueError):
            encode_game_connect_reply(GameConnectReply(bytes(15), False))
        self.assertNotIn(repr(identifier), repr(GameConnectReply(identifier, False)))

    def test_request_golden_and_strict_normal_shape(self):
        value = NormalJoinRequest(129, b'default_start_zone', b'test', 900)
        wire = b'\x81\1\0\0\x12default_start_zone\4test\x84\7' + bytes(6)
        self.assertEqual(encode_normal_join_request(value), wire)
        self.assertEqual(decode_normal_join_request(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_normal_join_request(wire[:cut])
        for bad in (wire+b'\0', wire[:-1]+b'\1', wire[:-6]+b'\1'+bytes(5),
                    b'\0\1x'+wire[3:], b'\0\0\0\x40'+bytes(64),
                    b'\0\0\0\0'+encode_uvarint(32769)):
            with self.assertRaises(DecodeError):
                decode_normal_join_request(bad)
        with self.assertRaises(ValueError):
            encode_normal_join_request(replace(value, instance_type=bytes(64)))
        self.assertNotIn('test', repr(value))

    def test_reply_golden_packed_fixed_lengths_not_varints(self):
        value = JoinReply(129, 0, b'local', b'test', 900, 0x01020304, b'zone', b'start')
        wire = (b'\x81\1\1\0\5local\4test\x84\7\x15'
                b'\4\3\2\1\4\0\0\0zone\5\0\0\0start')
        self.assertEqual(encode_join_reply(value), wire)
        self.assertEqual(decode_join_reply(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_join_reply(wire[:cut])
        for bad in (wire+b'\0', wire[:2]+b'\2'+wire[3:], wire[:-21]+bytes(21)):
            with self.assertRaises(DecodeError):
                decode_join_reply(bad)
        for changes in ({'instance_name':b''}, {'token':b''}, {'lifetime':0},
                        {'proxy_id':1<<32}, {'location_type':bytes(64)}):
            with self.assertRaises(ValueError):
                encode_join_reply(replace(value, **changes))

    def test_connect_and_instance_schema(self):
        self.assertEqual(decode_server_list_connect(b'\1x\1'), (b'x',1))
        for bad in (b'', b'\0\1', b'\1x\0', b'\1x\1\0'):
            with self.assertRaises(DecodeError):
                decode_server_list_connect(bad)
        wire = b'\1x\1' + bytes(5)
        tokens, extra = decode_instance_connect(wire)
        self.assertEqual(tokens, ((b'x',1),(b'',0),(b'',0)))
        self.assertIsNone(extra)
        self.assertEqual(decode_instance_connect(wire[:-1]+b'\1\1y\1')[1], (b'y',1))
        for bad in (wire+b'\0', wire[:-1]+b'\2', wire[:-1], bytes(8)):
            with self.assertRaises(DecodeError):
                decode_instance_connect(bad)


class ServerListSessionTests(unittest.TestCase):
    def setUp(self):
        self.f = test_profile_token.ProfileTokenSessionTests()
        self.f.setUp()
        self.addCleanup(self.f.f.profiles.store.close)
        self.profile = self.f.reply(self.f.f.handle(self.f.request()))
        self.auth, self.profiles = self.f.f.auth, self.f.f.profiles
        self.server = ServerListSession(self.auth, self.profiles)
        self.registration = Registration(55, b'server_list', next(iter(self.server.targets)))
        self.connect = MessageFrame(0, encode_length_prefixed_bytes(self.f.f.token)+encode_uvarint(8640))
        self.request = MessageFrame(5, encode_normal_join_request(NormalJoinRequest(
            129, self.profile.instance_type, self.profile.token, self.profile.lifetime)))

    def handle(self, frame, channel=42, registration=None):
        return self.server.handle(channel, registration or self.registration, frame)

    def join(self):
        event = self.handle(self.connect)
        self.assertEqual(event.response_type, 1)
        self.assertEqual(self.inner(event).body, encode_uvarint(1000))
        event = self.handle(self.request)
        self.assertEqual(event.stage, 'server-list-local-instance-reply-sent')
        self.assertEqual(event.response_type,6)
        return decode_join_reply(self.inner(event).body)

    def inner(self, event):
        channel, payload = channel_payload(event.response)
        self.assertEqual(channel,42)
        return decode_length_prefixed_frame(payload)

    def instance_connect(self, joined, *, tokens=None):
        # Retail finding 116: auth slot 1, discovery token, auth slot 3.
        auth_reply = self.f.f.reply
        if tokens is None:
            tokens = ((auth_reply.timed_blob_0.bytes_0, auth_reply.timed_blob_0.uint64_0),
                      (joined.token, joined.lifetime),
                      (auth_reply.timed_blob_2.bytes_0, auth_reply.timed_blob_2.uint64_0))
        return MessageFrame(0, b''.join(encode_length_prefixed_bytes(token)+encode_uvarint(ttl)
                                       for token, ttl in tokens)+b'\0')

    def test_join_local_connection_reply_without_world_snapshot_and_channel_lifetime(self):
        joined = self.join()
        self.assertEqual(joined.request_id,129)
        self.assertEqual(joined.proxy_id,0)
        self.assertEqual(joined.location_type,b'default_start_zone')
        self.assertEqual(joined.location_name,joined.instance_name)
        self.assertNotEqual(joined.token,self.profile.token)
        self.assertEqual(joined.lifetime,900)
        self.assertIn(joined.instance_name,self.server.instances)
        self.assertEqual(self.handle(self.request).stage,'server-list-duplicate-ignored')
        self.server.close(42)
        reg = Registration(56,b'game',joined.instance_name)
        frame = self.instance_connect(joined)
        tokens, extra = decode_instance_connect(frame.body)
        self.assertEqual([len(token) for token, _ in tokens], [240, len(joined.token), 272])
        self.assertIsNone(extra)
        event = self.handle(frame,43,reg)
        self.assertEqual(event.stage,'instance-connect-reply-sent-world-pending')
        channel, payload = channel_payload(event.response)
        self.assertEqual(channel, 43)
        response = decode_length_prefixed_frame(payload)
        self.assertEqual(response.type_id, 2)
        reply = decode_game_connect_reply(response.body)
        self.assertFalse(reply.rejected)
        self.assertEqual(reply.identifier, self.server.instances[joined.instance_name].connection_identifier)
        self.assertTrue(any(reply.identifier))
        self.assertNotEqual(reply.identifier, self.server.instances[joined.instance_name].character.identifier)
        self.assertEqual(self.handle(frame,43,reg).stage,'instance-duplicate-connect-ignored')
        self.assertEqual(self.handle(MessageFrame(2,b''),43,reg).stage,'instance-world-message-unimplemented')
        self.server.close(43)
        self.assertEqual(self.handle(MessageFrame(2,b''),43,reg).stage,'instance-not-authenticated')
        self.assertNotIn(joined.token.decode('ascii'),repr(self.server.instances))

    def test_unbound_unauthorized_wrong_character_and_bad_request(self):
        self.assertEqual(self.handle(self.request).stage,'server-list-not-authenticated')
        self.assertEqual(self.handle(self.connect,registration=replace(self.registration,target=b'foreign')).stage,
                         'unbound-observe-only')
        self.assertEqual(self.handle(MessageFrame(0,b'')).stage,'server-list-invalid-connect')
        self.assertEqual(self.handle(MessageFrame(0,b'\6forged\1')).stage,'server-list-token-rejected')
        self.handle(self.connect)
        self.assertEqual(self.handle(self.connect).stage,'server-list-duplicate-connect-ignored')
        for token in (b'forged',self.f.f.token):
            request=MessageFrame(5,encode_normal_join_request(NormalJoinRequest(1,b'default_start_zone',token,1)))
            self.assertEqual(self.handle(request).stage,'server-list-character-token-rejected')
        self.assertEqual(self.handle(MessageFrame(5,self.request.body+b'\0')).stage,
                         'server-list-invalid-or-unsupported-join')
        self.assertEqual(self.handle(MessageFrame(3,b'')).stage,'server-list-unsupported-message')
        self.assertEqual(self.server.instances,{})

    def test_reconnect_keeps_route_identifier_and_response_failure_is_atomic(self):
        joined = self.join()
        reg = Registration(56, b'game', joined.instance_name)
        frame = self.instance_connect(joined)
        with patch('isac_backend.server_list._reply', side_effect=ValueError('fixture')):
            with self.assertRaises(ValueError):
                self.handle(frame, 43, reg)
        self.assertEqual(self.server.admissions, {})
        first = self.handle(frame, 43, reg).response
        self.server.close(43)
        second = self.handle(frame, 43, reg).response
        self.assertEqual(first, second)
        request = replace(decode_normal_join_request(self.request.body), request_id=130)
        fresh = decode_join_reply(self.inner(self.handle(MessageFrame(5,
            encode_normal_join_request(request)))).body)
        self.assertNotEqual(self.server.instances[joined.instance_name].connection_identifier,
            self.server.instances[fresh.instance_name].connection_identifier)

    def test_duplicate_conflict_wrong_zone_and_admission_token(self):
        joined = self.join()
        different=MessageFrame(5,encode_normal_join_request(NormalJoinRequest(129,b'default_start_zone',self.profile.token,1)))
        self.assertEqual(self.handle(different).stage,'server-list-conflicting-request')
        request=MessageFrame(5,encode_normal_join_request(NormalJoinRequest(2,b'main_zone',self.profile.token,1)))
        self.assertEqual(self.handle(request).stage,'server-list-unsupported-zone')
        reg=Registration(56,b'game',joined.instance_name)
        bad=self.instance_connect(joined, tokens=((self.f.f.token,8640),
            (self.profile.token,1),(self.f.f.reply.timed_blob_2.bytes_0,8640)))
        self.assertEqual(self.handle(bad,43,reg).stage,'instance-token-rejected')
        self.assertEqual(self.handle(MessageFrame(0,b''),43,reg).stage,'instance-invalid-connect')
        self.assertEqual(self.server.admissions,{})

    def test_instance_bearer_must_be_in_second_slot_no_fallback(self):
        joined = self.join()
        reg = Registration(56,b'game',joined.instance_name)
        valid = decode_instance_connect(self.instance_connect(joined).body)[0]
        wrong_tokens = (
            (valid[1], valid[0], valid[2]),  # Old first-slot authorization bug.
            (valid[0], valid[2], valid[1]),  # No third-slot scanning fallback.
            (valid[0], (b'forged',1), valid[2]),
            (valid[0], (b'',0), valid[2]),
        )
        for tokens in wrong_tokens:
            with self.subTest(slot_lengths=[len(token) for token, _ in tokens]):
                event = self.handle(self.instance_connect(joined,tokens=tokens),43,reg)
                self.assertEqual(event.stage,'instance-token-rejected')
                self.assertIsNone(event.response)
                self.assertEqual(self.server.admissions,{})
        frame = self.instance_connect(joined)
        self.assertEqual(self.handle(frame,43,reg).stage,'instance-connect-reply-sent-world-pending')
        changed = self.instance_connect(joined,tokens=(valid[0],valid[1],(b'changed',1)))
        self.assertEqual(self.handle(changed,43,reg).stage,'instance-conflicting-connect')

    def test_expiry_parent_revocation_archive_and_token_renewal(self):
        joined=self.join()
        reg=Registration(56,b'game',joined.instance_name)
        frame=self.instance_connect(joined)
        self.f.f.fixture.now += timedelta(seconds=900)
        self.assertEqual(self.handle(frame,43,reg).stage,'instance-parent-session-rejected')
        self.f.f.fixture.now -= timedelta(seconds=900)
        renewed=self.f.reply(self.f.f.handle(self.f.request(2)))
        self.assertEqual(self.handle(frame,43,reg).stage,'instance-parent-session-rejected')
        self.assertNotEqual(renewed.token,self.profile.token)
        del self.f.f.fixture.sdk.sessions[self.f.f.fixture.session['sessionId']]
        self.assertEqual(self.handle(self.request).stage,'server-list-not-authenticated')

    def test_short_requested_lifetime_caps_instance(self):
        self.handle(self.connect)
        self.request=MessageFrame(5,encode_normal_join_request(NormalJoinRequest(129,b'default_start_zone',self.profile.token,3)))
        joined=decode_join_reply(self.inner(self.handle(self.request)).body)
        self.assertEqual(joined.lifetime,3)

    def test_foreign_owner_archive_and_route_capacity(self):
        self.handle(self.connect)
        character=self.profiles.resolve_character_token(self.profile.token)
        foreign=replace(character,owner=replace(character.owner,profile_id='00000000-0000-0000-0000-000000000001'))
        with patch.object(self.profiles,'resolve_character_token',return_value=foreign):
            self.assertEqual(self.handle(self.request).stage,'server-list-character-token-rejected')
        self.assertEqual(self.server.instances,{})
        event=self.handle(self.request)
        joined=decode_join_reply(self.inner(event).body)
        self.server.instances.update({b'capacity-'+str(i).encode(): next(iter(self.server.instances.values()))
                                      for i in range(31)})
        request=replace(decode_normal_join_request(self.request.body),request_id=130)
        self.assertEqual(self.handle(MessageFrame(5,encode_normal_join_request(request))).stage,
                         'server-list-instance-limit')
        self.profiles.store.archive_unfinished(character.owner.profile_id,character.identifier)
        reg=Registration(56,b'game',joined.instance_name)
        self.assertEqual(self.handle(MessageFrame(0,b''),43,reg).stage,'instance-parent-session-rejected')

    def test_parent_auth_deadline_and_fresh_transport(self):
        self.f.f.fixture.now += timedelta(seconds=8620)
        self.profile=self.f.reply(self.f.f.handle(self.f.request(2)))
        self.request=MessageFrame(5,encode_normal_join_request(NormalJoinRequest(
            129,self.profile.instance_type,self.profile.token,self.profile.lifetime)))
        joined=self.join()
        self.assertEqual(joined.lifetime,20)
        fresh=ServerListSession(self.auth,self.profiles)
        self.assertEqual(fresh.handle(43,Registration(56,b'game',joined.instance_name),MessageFrame(0,b'')).stage,
                         'unbound-observe-only')


if __name__ == '__main__':
    unittest.main()
