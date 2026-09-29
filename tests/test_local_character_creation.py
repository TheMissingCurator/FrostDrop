from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

import test_profile_bootstrap
from isac_backend.profiles import ProfileSession
from isac_backend.profile_store import ProfileStore, START_ZONE
from isac_protocol.character_record import (
    CharacterNode, decode_character_record, encode_character_record, starting_character_record,
)
from isac_protocol.codec import DecodeError
from isac_protocol.framing import MessageFrame, decode_length_prefixed_frame
from isac_protocol.profile_messages import (
    CreateProfileReply, CreateProfileRequest, ProfileList, decode_create_profile_request,
    encode_create_profile_reply, decode_create_profile_reply, encode_profile_list, decode_profile_list,
)
from isac_protocol.transport import channel_payload


class CharacterRecordTests(unittest.TestCase):
    def test_starting_layout(self):
        value = starting_character_record()
        wire = encode_character_record(value)
        self.assertEqual(len(wire), 161)
        self.assertEqual([(i, b) for i, b in enumerate(wire) if b], [(0,8),(1,1),(3,27),(149,1),(153,1)])
        self.assertEqual(decode_character_record(wire), value)
        self.assertFalse(value.client_accepts_customized_data)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_character_record(wire[:cut])
        for bad in (wire+b'\0', b'\7'+wire[1:], wire[:1]+b'\2'+wire[2:], b'\10\1\xff\x7f'):
            with self.assertRaises(DecodeError):
                decode_character_record(bad)

    def test_nonempty_nested_layout_preserves_float_bits(self):
        leaf = CharacterNode((1,2), b'\3\4', (5,6), 0x7fc01234, b'\7\10', (), (9,10))
        node = replace(leaf, children=(leaf,))
        value = replace(starting_character_record(), nodes=(node,), float_bits_458=(0x80000000,0x7fc01234), pairs_4d8=((11,12),))
        self.assertEqual(decode_character_record(encode_character_record(value)), value)
        self.assertTrue(value.client_accepts_customized_data)
        for _ in range(10):
            node = replace(node, children=(node,))
        with self.assertRaises(DecodeError):
            encode_character_record(replace(value, nodes=(node,)))


class CreationCodecTests(unittest.TestCase):
    def test_request_reply_and_bounds(self):
        self.assertEqual(decode_create_profile_request(b'\0\1\0'), CreateProfileRequest(0,True,False))
        for body in (b'', b'\0\1', b'\0\2\0', b'\0\1\0\0'):
            with self.assertRaises(DecodeError):
                decode_create_profile_request(body)
        value = CreateProfileReply(129, 0, bytes(range(16)))
        wire = b'\x81\1\0' + bytes(range(16))
        self.assertEqual(encode_create_profile_reply(value), wire)
        self.assertEqual(decode_create_profile_reply(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_create_profile_reply(wire[:cut])
        with self.assertRaises(DecodeError):
            decode_create_profile_reply(wire+b'\0')
        with self.assertRaises(ValueError):
            encode_create_profile_reply(replace(value, status=1))


class ProfileStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'local' / 'characters.sqlite3'
        self.account = str(uuid.uuid4())

    def store(self):
        value = ProfileStore(self.path, clock=lambda: 1234567890)
        self.addCleanup(value.close)
        return value

    def test_persistence_ownership_and_generated_ids(self):
        store = self.store()
        identifier, created = store.create(self.account, True, False)
        self.assertTrue(created)
        self.assertNotEqual(identifier, uuid.UUID(self.account).bytes)
        entries = store.list(self.account)
        self.assertEqual(entries[0].identifier, identifier)
        self.assertEqual(entries[0].last_used, 1234567890)
        self.assertEqual(entries[0].instance_type, START_ZONE)
        self.assertFalse(entries[0].is_customized)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        other = str(uuid.uuid4())
        self.assertEqual(store.list(other), ())
        store.close()
        reopened = self.store()
        self.assertEqual(reopened.list(self.account), entries)
        self.assertEqual(reopened.create(self.account, True, False), (identifier, False))
        self.assertNotEqual(reopened.create(other, True, False)[0], identifier)
        with self.assertRaises(ValueError):
            reopened.create(self.account, False, True)

    def test_finalized_slot_survives_restart_and_cannot_be_archived_as_unfinished(self):
        store = self.store()
        identifier, _ = store.create(self.account, True, False)
        node = CharacterNode((1, 2), b'\1\2', (3, 4), 5, b'\6\7', (), (0, 0))
        record = replace(starting_character_record(), nodes=(node,) * 18,
                         float_bits_458=tuple(range(32)))
        blob = encode_character_record(record)
        self.assertTrue(store.finalize(self.account, identifier, blob))
        self.assertFalse(store.finalize(self.account, identifier, blob))
        entry = store.list(self.account)[0]
        self.assertTrue(entry.is_customized)
        self.assertEqual(entry.character_blob, blob)
        with self.assertRaises(ValueError):
            store.finalize(self.account, identifier, encode_character_record(
                replace(record, float_bits_458=(99,) * 32)))
        with self.assertRaises(ValueError):
            store.finalize(str(uuid.uuid4()), identifier, blob)
        with self.assertRaises(ValueError):
            store.create(self.account, True, False)
        with self.assertRaises(ValueError):
            store.archive_unfinished(self.account, identifier)
        store.close()
        reopened = self.store()
        self.assertEqual(reopened.list(self.account), (entry,))

    def test_concurrent_reconnect_creation_is_single_slot(self):
        a, b = self.store(), self.store()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda i: (a if i%2 else b).create(self.account, True, False), range(20)))
        self.assertEqual(len({r[0] for r in results}), 1)
        self.assertEqual(sum(r[1] for r in results), 1)
        self.assertEqual(len(a.list(self.account)), 1)

    def test_full_list_codec_and_corruption_refusal(self):
        store = self.store()
        store.create(self.account, True, False)
        value = ProfileList(0,True,False,False,1800,START_ZONE,store.list(self.account))
        wire = encode_profile_list(value)
        self.assertEqual(decode_profile_list(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_profile_list(wire[:cut])
        with self.assertRaises(DecodeError):
            decode_profile_list(wire+b'\0')
        with self.assertRaises(ValueError):
            encode_profile_list(replace(value, profiles=(replace(value.profiles[0], identifier=b'x'),)))
        with store.db:
            store.db.execute('UPDATE unfinished_characters SET entry=?', (b'invalid',))
        with self.assertRaises(DecodeError):
            store.list(self.account)
        with self.assertRaises(DecodeError):
            store.create(self.account, True, False)

    def test_symlink_and_future_schema_refused(self):
        self.path.parent.mkdir()
        target = self.path.parent / 'target'
        target.write_bytes(b'untouched')
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            ProfileStore(self.path)
        self.assertEqual(target.read_bytes(), b'untouched')
        future = self.path.parent / 'future.sqlite3'
        with sqlite3.connect(future) as db:
            db.execute('PRAGMA user_version=99')
        db.close()
        with self.assertRaises(ValueError):
            ProfileStore(future)


class CreationSessionTests(unittest.TestCase):
    def setUp(self):
        self.f = test_profile_bootstrap.ProfileSessionTests()
        self.f.setUp()
        self.addCleanup(self.f.profiles.store.close)
        self.creation = MessageFrame(5,b'\0\1\0')

    def frame(self, event):
        channel, body = channel_payload(event.response)
        self.assertEqual(channel,37)
        return decode_length_prefixed_frame(body)

    def test_create_refresh_list_and_reconnect(self):
        f = self.f
        f.handle(f.connect)
        self.assertFalse(decode_profile_list(self.frame(f.handle(MessageFrame(1,b'\0\0'))).body).profiles)
        result = f.handle(self.creation)
        self.assertEqual(result.response_type,6)
        created = decode_create_profile_reply(self.frame(result).body)
        listed = decode_profile_list(self.frame(f.handle(MessageFrame(1,b'\0\0'))).body)
        self.assertEqual(listed.profiles[0].identifier,created.identifier)
        self.assertEqual(f.handle(self.creation).stage,'profile-duplicate-ignored')
        self.assertEqual(f.handle(MessageFrame(5,b'\0\0\1')).stage,'profile-conflicting-request')
        f.profiles.close(37)
        f.handle(f.connect)
        reused = f.handle(self.creation)
        self.assertEqual(reused.stage,'profile-unfinished-character-reused')
        self.assertEqual(decode_create_profile_reply(self.frame(reused).body).identifier, created.identifier)

    def test_no_auth_no_mutation_and_no_false_persistence_ack(self):
        f = self.f
        self.assertEqual(f.handle(self.creation).stage,'profile-not-authenticated')
        f.handle(f.connect)
        self.assertEqual(f.handle(MessageFrame(5,b'\0\0\1')).stage,'profile-store-or-mode-rejected')
        with patch.object(f.profiles.store,'create',side_effect=sqlite3.OperationalError('private detail')):
            result = f.handle(self.creation)
            self.assertIsNone(result.response)
            self.assertEqual(result.stage,'profile-store-or-mode-rejected')
        self.assertEqual(f.profiles.store.list(f.fixture.session['profileId']), ())
        del f.fixture.sdk.sessions[f.fixture.session['sessionId']]
        self.assertEqual(f.handle(self.creation).stage,'profile-not-authenticated')
