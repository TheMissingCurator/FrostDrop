from dataclasses import replace
from datetime import timedelta
import hashlib
import sqlite3
import unittest
from unittest.mock import patch
import uuid

import test_profile_bootstrap
from isac_backend.channels import Registration
from isac_backend.profiles import ProfileSession
from isac_protocol.character_record import CharacterNode, encode_character_record, starting_character_record
from isac_protocol.codec import DecodeError, encode_uvarint
from isac_protocol.framing import MessageFrame, decode_length_prefixed_frame
from isac_protocol.profile_messages import (
    ProfileTokenRequest, ProfileTokenReply, decode_profile_token_request, encode_profile_token_request,
    decode_profile_token_reply, encode_profile_token_reply, decode_create_profile_reply,
)
from isac_protocol.transport import channel_payload


class ProfileTokenCodecTests(unittest.TestCase):
    def test_raw_identifier_request_golden(self):
        value = ProfileTokenRequest(129, bytes(range(16)))
        wire = b'\x81\1' + bytes(range(16))
        self.assertEqual(encode_profile_token_request(value), wire)
        self.assertEqual(decode_profile_token_request(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_profile_token_request(wire[:cut])
        for bad in (wire+b'\0', b'\xff'*10 + bytes(16)):
            with self.assertRaises(DecodeError):
                decode_profile_token_request(bad)
        with self.assertRaises(ValueError):
            encode_profile_token_request(replace(value, identifier=b'x'))

    def test_normal_reply_golden_truncation_and_optional_refusal(self):
        value = ProfileTokenReply(129,2,b'local-test-token',900,b'default_start_zone',b'')
        wire = b'\x81\1\2\x10local-test-token\x84\7\x12default_start_zone\0\0\0'
        self.assertEqual(encode_profile_token_reply(value), wire)
        self.assertEqual(decode_profile_token_reply(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_profile_token_reply(wire[:cut])
        for bad in (wire+b'\0', wire[:-2]+b'\1\0', wire[:-1]+b'\1', wire[:-1]+b'\2',
                    b'\0\0'+wire[3:], b'\0\2\0', b'\0\2'+encode_uvarint(32769),
                    b'\0\2\1x\0\0\0\0\0'):
            with self.assertRaises(DecodeError):
                decode_profile_token_reply(bad)
        for changes in ({'status':0}, {'has_base_group':True}, {'has_survival_session':True},
                        {'token':b''}, {'token':bytes(32769)}, {'lifetime':0}, {'lifetime':1<<64},
                        {'instance_type':bytes(64)}, {'instance_name':bytes(64)}):
            with self.assertRaises(ValueError):
                encode_profile_token_reply(replace(value, **changes))

    def test_maximum_bounded_lengths_and_uints(self):
        value = ProfileTokenReply((1<<32)-1,2,bytes(32768),(1<<64)-1,bytes(63),bytes(63))
        self.assertEqual(decode_profile_token_reply(encode_profile_token_reply(value)), value)


class ProfileTokenSessionTests(unittest.TestCase):
    def setUp(self):
        self.f = test_profile_bootstrap.ProfileSessionTests()
        self.f.setUp()
        self.addCleanup(self.f.profiles.store.close)
        self.f.handle(self.f.connect)
        creation = self.f.handle(MessageFrame(5,b'\0\1\0'))
        _, body = channel_payload(creation.response)
        self.identifier = decode_create_profile_reply(decode_length_prefixed_frame(body).body).identifier

    def request(self, request_id=0, identifier=None):
        return MessageFrame(7, encode_profile_token_request(ProfileTokenRequest(request_id,
            self.identifier if identifier is None else identifier)))

    def reply(self, event):
        self.assertEqual(event.response_type, 8)
        channel, body = channel_payload(event.response)
        self.assertEqual(channel,37)
        frame = decode_length_prefixed_frame(body)
        self.assertEqual(frame.type_id,8)
        return decode_profile_token_reply(frame.body)

    def test_selection_binding_correlation_and_channel_lifetime(self):
        p = self.f.profiles
        self.f.auth.close(0)
        event = self.f.handle(self.request())
        self.assertEqual(event.stage,'profile-character-token-reply-sent')
        reply = self.reply(event)
        self.assertEqual(reply.request_id,0)
        self.assertEqual(reply.status,2)
        self.assertEqual(reply.lifetime,900)
        self.assertEqual((reply.instance_type,reply.instance_name),(b'default_start_zone',b''))
        self.assertFalse(reply.has_base_group or reply.has_survival_session)
        self.assertNotEqual(reply.token,self.f.token)
        self.assertNotIn(self.identifier,reply.token)
        session = p.resolve_character_token(reply.token)
        self.assertEqual(session.identifier,self.identifier)
        self.assertEqual(session.owner.profile_id,self.f.fixture.session['profileId'])
        self.assertNotIn(reply.token,p.character_sessions)
        self.assertIn(hashlib.sha256(reply.token).digest(),p.character_sessions)
        self.assertEqual(self.f.handle(self.request()).stage,'profile-duplicate-ignored')
        self.assertEqual(len(p.character_sessions),1)
        self.assertEqual(self.f.handle(self.request(identifier=bytes(16))).stage,'profile-conflicting-request')
        p.close(37)
        self.assertIsNotNone(p.resolve_character_token(reply.token))
        self.assertIsNone(p.resolve_character_token(b'forged'))
        self.assertIsNone(p.resolve_character_token(self.f.token))
        fresh = ProfileSession(self.f.auth,p.store)
        self.assertIsNone(fresh.resolve_character_token(reply.token))
        self.f.handle(self.f.connect)
        renewed = self.reply(self.f.handle(self.request()))
        self.assertNotEqual(renewed.token,reply.token)
        self.assertIsNone(p.resolve_character_token(reply.token))
        self.assertIsNotNone(p.resolve_character_token(renewed.token))
        self.assertEqual(len(p.character_sessions),1)

    def test_completed_local_slot_can_be_selected_again(self):
        p = self.f.profiles
        node = CharacterNode((1, 2), b'\1\2', (3, 4), 5, b'\6\7', (), (0, 0))
        blob = encode_character_record(replace(starting_character_record(),
            nodes=(node,) * 18, float_bits_458=(0,) * 32))
        account = self.f.fixture.session['profileId']
        self.assertTrue(p.store.finalize(account, self.identifier, blob))
        event = self.f.handle(self.request())
        self.assertEqual(event.stage, 'profile-character-token-reply-sent')
        self.assertEqual(p.resolve_character_token(self.reply(event).token).identifier,
                         self.identifier)

    def test_missing_foreign_account_and_malformed_refused(self):
        for bad in (b'', b'\0'+bytes(15), b'\0'+bytes(17)):
            self.assertEqual(self.f.handle(MessageFrame(7,bad)).stage,'profile-invalid-token-request')
        self.assertEqual(self.f.handle(self.request(identifier=bytes(16))).stage,'profile-character-not-owned')
        other, _ = self.f.profiles.store.create(str(uuid.uuid4()),True,False)
        self.assertEqual(self.f.handle(self.request(identifier=other)).stage,'profile-character-not-owned')
        for registration in (Registration(1,b'profile_cache_front',self.f.registration.target),
                             Registration(1,b'profile_client',b'unknown')):
            event=self.f.profiles.handle(37,registration,self.request())
            self.assertEqual(event.stage,'unbound-observe-only')
            self.assertIsNone(event.response)
        self.assertEqual(self.f.profiles.character_sessions,{})
        self.f.profiles.close(37)
        self.assertEqual(self.f.handle(self.request()).stage,'profile-not-authenticated')

    def test_expiry_revoke_and_character_disappearance(self):
        p = self.f.profiles
        reply = self.reply(self.f.handle(self.request()))
        self.f.fixture.now += timedelta(seconds=900)
        self.assertIsNone(p.resolve_character_token(reply.token))
        self.f.fixture.now -= timedelta(seconds=900)
        with p.store.db:
            p.store.db.execute('DELETE FROM unfinished_characters')
        self.assertIsNone(p.resolve_character_token(reply.token))
        p.store.create(self.f.fixture.session['profileId'],True,False)
        del self.f.fixture.sdk.sessions[self.f.fixture.session['sessionId']]
        self.assertIsNone(p.resolve_character_token(reply.token))
        event=self.f.handle(self.request(1))
        self.assertEqual(event.stage,'profile-not-authenticated')
        self.assertIsNone(event.response)

    def test_parent_auth_deadline_caps_lifetime(self):
        self.f.fixture.now += timedelta(seconds=8620)
        reply = self.reply(self.f.handle(self.request()))
        self.assertEqual(reply.lifetime,20)
        self.f.fixture.now += timedelta(seconds=20)
        self.assertIsNone(self.f.profiles.resolve_character_token(reply.token))
        self.assertIsNone(self.f.handle(self.request(1)).response)

    def test_storage_failure_or_unsupported_mode_never_grants_token(self):
        p = self.f.profiles
        with patch.object(p.store,'list',side_effect=sqlite3.OperationalError('private storage detail')):
            result = self.f.handle(self.request())
            self.assertEqual(result.stage,'profile-store-or-mode-rejected')
            self.assertIsNone(result.response)
        entry = p.store.list(self.f.fixture.session['profileId'])[0]
        for changes in ({'is_locked':True},{'is_survival':True},
                        {'instance_type':b'main_zone'},{'instance_name':b'unknown'}):
            with patch.object(p.store,'list',return_value=(replace(entry,**changes),)):
                result=self.f.handle(self.request())
                self.assertEqual(result.stage,'profile-token-mode-unsupported')
                self.assertIsNone(result.response)
        self.assertEqual(p.character_sessions,{})

    def test_revocation_invalidates_existing_character_token(self):
        reply = self.reply(self.f.handle(self.request()))
        del self.f.fixture.sdk.sessions[self.f.fixture.session['sessionId']]
        self.assertIsNone(self.f.profiles.resolve_character_token(reply.token))
