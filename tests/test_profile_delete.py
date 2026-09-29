from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

import test_profile_bootstrap
from isac_backend.channels import Registration
from isac_backend.profile_store import ProfileStore
from isac_backend.profiles import ProfileSession
from isac_protocol.codec import DecodeError
from isac_protocol.framing import MessageFrame, decode_length_prefixed_frame
from isac_protocol.profile_messages import (
    DeleteProfileRequest, DeleteProfileReply, decode_delete_profile_request,
    encode_delete_profile_request, decode_delete_profile_reply, encode_delete_profile_reply,
    decode_create_profile_reply, decode_profile_list, encode_profile_list,
    ProfileTokenRequest, encode_profile_token_request, decode_profile_token_reply,
)
from isac_protocol.transport import channel_payload


class DeleteCodecTests(unittest.TestCase):
    def test_request_golden_bounds_and_truncation(self):
        value = DeleteProfileRequest(129, bytes(range(16)))
        wire = b'\x81\1' + bytes(range(16))
        self.assertEqual(encode_delete_profile_request(value), wire)
        self.assertEqual(decode_delete_profile_request(wire), value)
        for cut in range(len(wire)):
            with self.assertRaises(DecodeError):
                decode_delete_profile_request(wire[:cut])
        for bad in (wire+b'\0', b'\xff'*10 + bytes(16)):
            with self.assertRaises(DecodeError):
                decode_delete_profile_request(bad)
        for changes in ({'identifier': bytes(15)}, {'request_id': 1<<32}, {'request_id': -1}):
            with self.assertRaises(ValueError):
                encode_delete_profile_request(replace(value, **changes))

    def test_reply_boolean_not_creation_status(self):
        for success in (True, False):
            value = DeleteProfileReply(129, success)
            wire = b'\x81\1' + bytes((success,))
            self.assertEqual(encode_delete_profile_reply(value), wire)
            self.assertEqual(decode_delete_profile_reply(wire), value)
            for cut in range(len(wire)):
                with self.assertRaises(DecodeError):
                    decode_delete_profile_reply(wire[:cut])
            with self.assertRaises(DecodeError):
                decode_delete_profile_reply(wire+b'\0')
        for bad in (b'\0\2', b'\0\xff\1', b'\xff'*10 + b'\1'):
            with self.assertRaises(DecodeError):
                decode_delete_profile_reply(bad)
        with self.assertRaises(ValueError):
            encode_delete_profile_reply(DeleteProfileReply(0, 1))
        maximum = DeleteProfileReply((1<<32)-1, True)
        self.assertEqual(decode_delete_profile_reply(encode_delete_profile_reply(maximum)), maximum)


class DeleteStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'characters.sqlite3'
        self.account = str(uuid.uuid4())

    def store(self):
        store = ProfileStore(self.path, clock=lambda: 1234567890)
        self.addCleanup(store.close)
        return store

    def test_false_false_creation_persists_and_archives_without_erasing_older_history(self):
        store = self.store()
        old, _ = store.create(self.account, True, False)
        self.assertEqual(store.archive_unfinished(self.account, old), (True, True))
        identifier, created = store.create(self.account, False, False)
        self.assertTrue(created)
        self.assertNotEqual(identifier, old)
        entry = store.list(self.account)[0]
        self.assertFalse(entry.is_male)
        row = store.db.execute('SELECT request_flags FROM unfinished_characters').fetchone()
        self.assertEqual(row[0], b'\x00\x00')
        self.assertEqual(store.create(self.account, False, False), (identifier, False))
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            store.create(self.account, True, False)
        reopened = self.store()
        self.assertEqual(reopened.list(self.account)[0], entry)
        self.assertEqual(reopened.archive_unfinished(self.account, identifier), (True, True))
        self.assertEqual(reopened.archive_unfinished(self.account, identifier), (True, False))
        archived = reopened.db.execute('SELECT request_flags FROM archived_unfinished_characters '
                                      'WHERE identifier=?', (identifier,)).fetchone()
        self.assertEqual(archived[0], b'\x00\x00')
        self.assertEqual(reopened.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 2)
        self.assertEqual(reopened.list(self.account), ())

    def test_archive_is_exact_persistent_and_retry_cannot_delete_new_slot(self):
        store = self.store()
        identifier, _ = store.create(self.account, True, False)
        original = store.db.execute('SELECT * FROM unfinished_characters').fetchone()
        self.assertEqual(store.archive_unfinished(self.account, identifier), (True, True))
        self.assertEqual(store.list(self.account), ())
        archived = store.db.execute('SELECT account, identifier, request_flags, entry, archived_at '
                                    'FROM archived_unfinished_characters').fetchone()
        self.assertEqual(archived, (*original, 1234567890))
        reopened = self.store()
        self.assertEqual(reopened.archive_unfinished(self.account, identifier), (True, False))
        new, created = reopened.create(self.account, True, False)
        self.assertTrue(created)
        self.assertNotEqual(new, identifier)
        self.assertEqual(store.archive_unfinished(self.account, identifier), (True, False))
        self.assertEqual(store.list(self.account)[0].identifier, new)
        self.assertEqual(store.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 1)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_unknown_foreign_and_invalid_ids_leave_both_tables_untouched(self):
        store = self.store()
        identifier, _ = store.create(self.account, True, False)
        other = str(uuid.uuid4())
        self.assertEqual(store.archive_unfinished(other, identifier), (False, False))
        self.assertEqual(store.archive_unfinished(self.account, bytes(16)), (False, False))
        with self.assertRaises(ValueError):
            store.archive_unfinished(self.account, b'x')
        self.assertEqual(store.list(self.account)[0].identifier, identifier)
        self.assertEqual(store.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 0)
        store.archive_unfinished(self.account, identifier)
        self.assertEqual(store.archive_unfinished(other, identifier), (False, False))

    def test_delete_failure_rolls_back_archive_insert(self):
        store = self.store()
        identifier, _ = store.create(self.account, True, False)
        entries = store.list(self.account)
        with store.db:
            store.db.execute("CREATE TRIGGER refuse_delete BEFORE DELETE ON unfinished_characters "
                             "BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            store.archive_unfinished(self.account, identifier)
        self.assertEqual(store.list(self.account), entries)
        self.assertEqual(store.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 0)

    def test_ignored_delete_is_not_acknowledged_as_a_move(self):
        store = self.store()
        identifier, _ = store.create(self.account, True, False)
        entries = store.list(self.account)
        with store.db:
            store.db.execute('CREATE TRIGGER ignore_delete BEFORE DELETE ON unfinished_characters '
                             'BEGIN SELECT RAISE(IGNORE); END')
        with self.assertRaises(ValueError):
            store.archive_unfinished(self.account, identifier)
        self.assertEqual(store.list(self.account), entries)
        self.assertEqual(store.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 0)

    def test_locked_completed_alternate_and_corrupt_records_refused(self):
        store = self.store()
        identifier, _ = store.create(self.account, True, False)
        raw = store.db.execute('SELECT entry FROM unfinished_characters').fetchone()[0]
        listed = decode_profile_list(raw)
        for changes in ({'is_customized':True}, {'is_locked':True}, {'is_survival':True},
                        {'instance_type': b'main_zone'}, {'instance_name': b'other'}):
            modified = encode_profile_list(replace(listed, profiles=(replace(listed.profiles[0], **changes),)))
            with store.db:
                store.db.execute('UPDATE unfinished_characters SET entry=?', (modified,))
            with self.assertRaises(ValueError):
                store.archive_unfinished(self.account, identifier)
            self.assertEqual(store.db.execute('SELECT entry FROM unfinished_characters').fetchone()[0], modified)
        with store.db:
            store.db.execute('UPDATE unfinished_characters SET entry=?', (b'corrupt',))
        with self.assertRaises(ValueError):
            store.archive_unfinished(self.account, identifier)
        self.assertEqual(store.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 0)

    def test_schema_one_migration_preserves_existing_character(self):
        memory = ProfileStore(clock=lambda: 1234567890)
        self.addCleanup(memory.close)
        memory.create(self.account, True, False)
        row = memory.db.execute('SELECT * FROM unfinished_characters').fetchone()
        db = sqlite3.connect(self.path)
        try:
            with db:
                db.execute('CREATE TABLE unfinished_characters (account TEXT PRIMARY KEY, '
                           'identifier BLOB NOT NULL UNIQUE, request_flags BLOB NOT NULL, entry BLOB NOT NULL)')
                db.execute('INSERT INTO unfinished_characters VALUES (?, ?, ?, ?)', row)
                db.execute('PRAGMA user_version=1')
        finally:
            db.close()
        store = self.store()
        self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], 2)
        self.assertEqual(store.db.execute('SELECT * FROM unfinished_characters').fetchone(), row)
        self.assertEqual(store.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 0)

    def test_concurrent_archive_is_one_atomic_move(self):
        a, b = self.store(), self.store()
        identifier, _ = a.create(self.account, True, False)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda i: (a if i%2 else b).archive_unfinished(self.account, identifier), range(20)))
        self.assertTrue(all(r[0] for r in results))
        self.assertEqual(sum(r[1] for r in results), 1)
        self.assertEqual(a.list(self.account), ())
        self.assertEqual(a.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 1)


class DeleteSessionTests(unittest.TestCase):
    def setUp(self):
        self.f = test_profile_bootstrap.ProfileSessionTests()
        self.f.setUp()
        self.addCleanup(self.f.profiles.store.close)
        self.f.handle(self.f.connect)
        self.creation = MessageFrame(5, b'\0\1\0')
        self.identifier = decode_create_profile_reply(self.frame(self.f.handle(self.creation)).body).identifier

    def frame(self, event, channel=37):
        actual, payload = channel_payload(event.response)
        self.assertEqual(actual, channel)
        return decode_length_prefixed_frame(payload)

    def request(self, request_id=0, identifier=None):
        return MessageFrame(3, encode_delete_profile_request(DeleteProfileRequest(request_id,
            self.identifier if identifier is None else identifier)))

    def test_cleanup_refresh_recreate_same_ids_and_revoke_selection(self):
        f = self.f
        f.handle(MessageFrame(1, b'\0\0'))
        selected = self.frame(f.handle(MessageFrame(7, encode_profile_token_request(ProfileTokenRequest(0, self.identifier)))))
        bearer = decode_profile_token_reply(selected.body).token
        self.assertIsNotNone(f.profiles.resolve_character_token(bearer))
        event = f.handle(self.request())
        self.assertEqual((event.stage, event.response_type), ('profile-unfinished-character-archived', 4))
        frame = self.frame(event)
        self.assertEqual(frame.type_id, 4)
        self.assertEqual(decode_delete_profile_reply(frame.body), DeleteProfileReply(0, True))
        self.assertIsNone(f.profiles.resolve_character_token(bearer))
        self.assertFalse(f.profiles.character_sessions)
        self.assertFalse(decode_profile_list(self.frame(f.handle(MessageFrame(1,b'\0\0'))).body).profiles)
        self.assertEqual(f.handle(self.request()).stage, 'profile-duplicate-ignored')
        self.assertEqual(f.handle(self.request(identifier=bytes(16))).stage, 'profile-conflicting-request')
        recreated = decode_create_profile_reply(self.frame(f.handle(self.creation)).body)
        self.assertNotEqual(recreated.identifier, self.identifier)
        self.assertEqual(f.handle(MessageFrame(7, encode_profile_token_request(ProfileTokenRequest(0, self.identifier)))).stage,
                         'profile-character-not-owned')
        self.assertEqual(f.handle(MessageFrame(7, encode_profile_token_request(ProfileTokenRequest(0, recreated.identifier)))).response_type, 8)

    def test_cross_channel_invalidation_and_archived_retry_preserves_new_requests(self):
        f = self.f
        other_channel = 38
        handle = lambda frame: f.profiles.handle(other_channel, f.registration, frame)
        handle(f.connect)
        handle(self.creation)
        handle(MessageFrame(1, b'\0\0'))
        f.handle(self.request())
        self.assertFalse(decode_profile_list(self.frame(handle(MessageFrame(1,b'\0\0')),38).body).profiles)
        created = decode_create_profile_reply(self.frame(handle(self.creation),38).body)
        self.assertNotEqual(created.identifier, self.identifier)
        event = handle(self.request())
        self.assertEqual(event.stage, 'profile-unfinished-character-already-archived')
        self.assertTrue(decode_delete_profile_reply(self.frame(event,38).body).success)
        self.assertEqual(handle(self.creation).stage, 'profile-duplicate-ignored')
        self.assertEqual(f.profiles.store.list(f.fixture.session['profileId'])[0].identifier, created.identifier)

    def test_reconnect_and_new_transport_use_persisted_archive(self):
        f = self.f
        f.handle(self.request())
        f.profiles.close(37)
        f.handle(f.connect)
        self.assertEqual(f.handle(self.request()).stage, 'profile-unfinished-character-already-archived')
        fresh = ProfileSession(f.auth, f.profiles.store)
        fresh.handle(37, f.registration, f.connect)
        event = fresh.handle(37, f.registration, self.request(129))
        self.assertEqual(decode_delete_profile_reply(self.frame(event).body), DeleteProfileReply(129, True))

    def test_missing_foreign_ids_false_reply_and_no_mutation(self):
        f = self.f
        other, _ = f.profiles.store.create(str(uuid.uuid4()), True, False)
        for i, identifier in enumerate((bytes(16), other)):
            event = f.handle(self.request(i, identifier))
            self.assertEqual(event.stage, 'profile-delete-not-owned')
            self.assertEqual(decode_delete_profile_reply(self.frame(event).body), DeleteProfileReply(i, False))
        self.assertEqual(f.profiles.store.list(f.fixture.session['profileId'])[0].identifier, self.identifier)
        self.assertEqual(f.profiles.store.db.execute('SELECT COUNT(*) FROM archived_unfinished_characters').fetchone()[0], 0)

    def test_no_auth_revoked_expired_or_wrong_binding_no_mutation(self):
        f = self.f
        for registration in (Registration(1,b'profile_cache_front', f.registration.target),
                             Registration(1,b'profile_client', b'unknown')):
            self.assertEqual(f.profiles.handle(37, registration, self.request()).stage, 'unbound-observe-only')
        f.profiles.close(37)
        self.assertEqual(f.handle(self.request()).stage, 'profile-not-authenticated')
        f.handle(f.connect)
        f.fixture.now += timedelta(seconds=8640)
        self.assertEqual(f.handle(self.request()).stage, 'profile-not-authenticated')
        f.fixture.now -= timedelta(seconds=8640)
        del f.fixture.sdk.sessions[f.fixture.session['sessionId']]
        self.assertEqual(f.handle(self.request()).stage, 'profile-not-authenticated')
        self.assertEqual(f.profiles.store.list(f.fixture.session['profileId'])[0].identifier, self.identifier)

    def test_malformed_and_failed_commit_no_success_response(self):
        f = self.f
        for body in (b'', b'\0'+bytes(15), b'\0'+bytes(17), b'\xff'*10+bytes(16)):
            self.assertEqual(f.handle(MessageFrame(3, body)).stage, 'profile-invalid-delete-request')
        with patch.object(f.profiles.store, 'archive_unfinished', side_effect=sqlite3.OperationalError('private detail')):
            event = f.handle(self.request())
            self.assertEqual(event.stage, 'profile-store-or-mode-rejected')
            self.assertIsNone(event.response)
        self.assertEqual(f.profiles.store.list(f.fixture.session['profileId'])[0].identifier, self.identifier)
        # Failed attempts were not recorded as completed; normal retry works.
        self.assertEqual(f.handle(self.request()).response_type, 4)
