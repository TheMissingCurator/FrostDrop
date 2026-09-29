"""Creation diagnostics distinguish the two observed normal flag variants."""
import contextlib
import errno
import io
from pathlib import Path
import runpy
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import test_profile_bootstrap
from isac_backend.profiles import profile_failure
from isac_protocol.framing import MessageFrame

ROOT = Path(__file__).resolve().parents[1]
SERVER = runpy.run_path(str(ROOT / 'tools/run-tctd-backend-server.py'))


class ProfileDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_profile_bootstrap.ProfileSessionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.handle(self.fixture.connect)

    def test_all_four_flag_combinations_preserve_existing_policy(self):
        for index, flags in enumerate(((False, False), (False, True), (True, True), (True, False))):
            event = self.fixture.handle(MessageFrame(5, bytes((index, *flags))))
            if flags in ((False, False), (True, False)):
                self.assertEqual(event.stage, 'profile-character-created')
                self.assertIsNotNone(event.response)
                self.assertIsNone(event.failure)
                account = self.fixture.fixture.session['profileId']
                identifier = self.fixture.profiles.store.list(account)[0].identifier
                self.assertEqual(self.fixture.profiles.store.archive_unfinished(account, identifier), (True, True))
            else:
                self.assertEqual(event.stage, 'profile-store-or-mode-rejected')
                self.assertIsNone(event.response)
                self.assertEqual(event.failure.operation, 'store-create')
                self.assertEqual(event.failure.reason, 'unsupported-create-flags')
                self.assertEqual(self.fixture.profiles.store.db.execute(
                    'select count(*) from unfinished_characters').fetchone()[0], 0)

    def test_storage_and_validation_failures_are_distinct_and_redacted(self):
        busy = sqlite3.OperationalError('SECRET account/path')
        busy.sqlite_errorcode = sqlite3.SQLITE_BUSY
        cases = ((busy, 'sqlite-error', sqlite3.SQLITE_BUSY, None),
                 (OSError(errno.ENOSPC, 'SECRET token'), 'os-error', None, errno.ENOSPC),
                 (ValueError('SECRET identity'), 'value-validation-error', None, None),
                 (ValueError('conflicting unfinished character mode'), 'conflicting-stored-create-flags', None, None))
        for error, reason, code, number in cases:
            with patch.object(self.fixture.profiles.store, 'create', side_effect=error):
                event = self.fixture.handle(MessageFrame(5, b'\0\1\0'))
            self.assertIsNone(event.response)
            self.assertEqual((event.failure.reason, event.failure.sqlite_code, event.failure.os_errno),
                             (reason, code, number))
            with contextlib.redirect_stdout(io.StringIO()) as log:
                SERVER['log_profile_failure'](1, 7, MessageFrame(5, b''), event)
            self.assertNotIn('SECRET', log.getvalue())
            self.assertIn('operation=store-create', log.getvalue())

    def test_reply_encoding_failure_distinguished_from_store_rejection(self):
        with patch('isac_backend.profiles.encode_create_profile_reply', side_effect=ValueError('SECRET')):
            event = self.fixture.handle(MessageFrame(5, b'\0\1\0'))
        self.assertIsNone(event.response)
        self.assertEqual(event.failure.operation, 'encode-create-reply')
        self.assertEqual(self.fixture.profiles.store.db.execute(
            'select count(*) from unfinished_characters').fetchone()[0], 1)

    def test_unauthenticated_or_malformed_request_never_reaches_store(self):
        self.fixture.profiles.close(37)
        with patch.object(self.fixture.profiles.store, 'create') as create:
            self.assertEqual(self.fixture.handle(MessageFrame(5, b'\0\1\0')).stage, 'profile-not-authenticated')
            self.fixture.handle(self.fixture.connect)
            self.assertEqual(self.fixture.handle(MessageFrame(5, b'\0\2\0')).stage, 'profile-unsupported-create-request')
            create.assert_not_called()

    def test_request_file_exists_immediately_and_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.redirect_stdout(io.StringIO()) as log:
                SERVER['capture_create_request'](root, 1, 7, 1, b'\0\0\1')
            path = root / 'backend-0001-create-0001.bin'
            self.assertEqual(path.read_bytes(), b'\0\0\1')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn('flag_5=0 flag_4=1 artifact=saved', log.getvalue())
            # A diagnostic retry cannot overwrite evidence or fail dispatch.
            with contextlib.redirect_stdout(io.StringIO()) as log:
                SERVER['capture_create_request'](root, 1, 7, 1, b'\0\1\0')
            self.assertIn('artifact=write-failed', log.getvalue())
            self.assertEqual(path.read_bytes(), b'\0\0\1')

    def test_unknown_shape_is_never_dumped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.redirect_stdout(io.StringIO()) as log:
                for sequence, body in enumerate((b'SECRET oversized credential', b'\0\2\0', b'')):
                    SERVER['capture_create_request'](root, 1, 7, sequence, body)
            self.assertFalse(list(root.iterdir()))
            self.assertNotIn('SECRET', log.getvalue())
            self.assertEqual(log.getvalue().count('shape=unsupported'), 3)


if __name__ == '__main__':
    unittest.main()
