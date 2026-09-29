"""Durable local characters, separate from SDK login sessions.

The legacy table name remains `unfinished_characters` for database compatibility.
The opt-in finalization experiment promotes that row in place, preserving its
local identity and ownership. SQLite commits before success is acknowledged.
"""
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
import uuid

from isac_protocol.character_record import (
    decode_character_record, encode_character_record, starting_character_record,
)
from isac_protocol.profile_messages import ProfileEntry, ProfileList, encode_profile_list, decode_profile_list

START_ZONE = b'default_start_zone'  # Retail value AND static literal RVA 0x2e4b350.


class ProfileStore:
    def __init__(self, path=None, clock=time.time):
        self.clock = clock
        self.lock = threading.Lock()
        if path is not None:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError('profile database must be a locally owned regular file')
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        self.db = sqlite3.connect(str(path) if path is not None else ':memory:',
                                  timeout=5, check_same_thread=False)
        try:
            with self.db:
                self.db.execute('BEGIN IMMEDIATE')
                version = self.db.execute('PRAGMA user_version').fetchone()[0]
                if version not in (0, 1, 2):
                    raise ValueError('unsupported local profile database version')
                self.db.execute('''CREATE TABLE IF NOT EXISTS unfinished_characters (
                    account TEXT PRIMARY KEY, identifier BLOB NOT NULL UNIQUE,
                    request_flags BLOB NOT NULL, entry BLOB NOT NULL)''')
                # Version 1 rows remain unchanged. Deletion moves their complete
                # representation here in the SAME transaction as removing the
                # active slot. No SDK/auth/character bearer is persisted.
                self.db.execute('''CREATE TABLE IF NOT EXISTS archived_unfinished_characters (
                    identifier BLOB PRIMARY KEY, account TEXT NOT NULL,
                    request_flags BLOB NOT NULL, entry BLOB NOT NULL,
                    archived_at INTEGER NOT NULL)''')
                self.db.execute('PRAGMA user_version=2')
        except Exception:
            self.db.close()
            raise

    def close(self):
        with self.lock:
            self.db.close()

    def list(self, account):
        account = str(uuid.UUID(account))
        with self.lock:
            row = self.db.execute('SELECT identifier, entry FROM unfinished_characters WHERE account=?', (account,)).fetchone()
        return self._entries(*row) if row else ()

    @staticmethod
    def _entries(identifier, encoded):
        entries = decode_profile_list(encoded).profiles
        if len(entries) != 1 or entries[0].identifier != identifier:
            raise ValueError('invalid character store entry')
        record = decode_character_record(entries[0].character_blob)
        if entries[0].is_customized != record.client_accepts_customized_data:
            raise ValueError('invalid customized character store entry')
        return entries

    def create(self, account, flag_5, flag_4):
        account = str(uuid.UUID(account))
        # Both observed flag_5 values use the normal starting-zone shape.
        # Preserve flag_5 in the presented character entry; its full business
        # meaning is not yet proven. flag_4=1 remains unsupported.
        if type(flag_5) is not bool or flag_4 is not False:
            raise ValueError('unsupported local creation mode')
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT identifier, request_flags, entry FROM unfinished_characters WHERE account=?', (account,)).fetchone()
            if row:
                if row[1] != bytes((flag_5, flag_4)):
                    raise ValueError('conflicting unfinished character mode')
                if self._entries(row[0], row[2])[0].is_customized:
                    raise ValueError('completed character already occupies local slot')
                return row[0], False
            identifier = uuid.uuid4().bytes
            entry = ProfileEntry(identifier, 1, flag_5, int(self.clock()), 0, b'', START_ZONE,
                                 False, False, False, False, False,
                                 encode_character_record(starting_character_record()))
            encoded = encode_profile_list(ProfileList(0, True, False, False, 1800, START_ZONE, (entry,)))
            self.db.execute('INSERT INTO unfinished_characters VALUES (?, ?, ?, ?)',
                            (account, identifier, bytes((flag_5, flag_4)), encoded))
            return identifier, True

    def finalize(self, account, identifier, character_blob):
        """Atomically promote only the authenticated account's existing slot.

        An identical retry is harmless; conflicting later submissions are not
        silently applied as appearance editing. No retail identity is stored.
        """
        account = str(uuid.UUID(account))
        if len(identifier) != 16:
            raise ValueError('invalid character identifier')
        record = decode_character_record(character_blob)
        if not record.client_accepts_customized_data or len(record.float_bits_458) != 32:
            raise ValueError('invalid finalized character record')
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('''SELECT entry FROM unfinished_characters
                WHERE account=? AND identifier=?''', (account, identifier)).fetchone()
            if row is None:
                raise ValueError('character not owned by local account')
            entry = self._entries(identifier, row[0])[0]
            if entry.is_customized:
                if entry.character_blob != character_blob:
                    raise ValueError('conflicting finalized character record')
                return False
            updated = ProfileEntry(entry.identifier, entry.level, entry.is_male,
                int(self.clock()), entry.time_played, entry.instance_name,
                entry.instance_type, entry.is_locked, entry.can_unlock, True,
                entry.is_joinable, entry.is_survival, character_blob)
            encoded = encode_profile_list(ProfileList(0, True, False, False,
                1800, START_ZONE, (updated,)))
            changed = self.db.execute('''UPDATE unfinished_characters SET entry=?
                WHERE account=? AND identifier=?''', (encoded, account, identifier))
            if changed.rowcount != 1:
                raise ValueError('finalized character update failed')
            return True

    def archive_unfinished(self, account, identifier):
        """Return (success, newly_archived), scoped to the authenticated owner.

        Retries of an already archived ID succeed without touching a newer slot.
        Unknown/foreign IDs fail identically. This is not a general character
        deletion API: completed, locked and alternate-mode records are refused.
        Archived rows retain the exact entry and flags for manual recovery.
        """
        account = str(uuid.UUID(account))
        if len(identifier) != 16:
            raise ValueError('invalid unfinished character identifier')
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('''SELECT request_flags, entry FROM unfinished_characters
                WHERE account=? AND identifier=?''', (account, identifier)).fetchone()
            if row is None:
                archived = self.db.execute('''SELECT request_flags, entry FROM archived_unfinished_characters
                    WHERE account=? AND identifier=?''', (account, identifier)).fetchone()
                if archived is None:
                    return False, False
                self._deletable_entry(identifier, *archived)
                return True, False
            self._deletable_entry(identifier, *row)
            self.db.execute('INSERT INTO archived_unfinished_characters VALUES (?, ?, ?, ?, ?)',
                            (identifier, account, *row, int(self.clock())))
            deleted = self.db.execute('DELETE FROM unfinished_characters WHERE account=? AND identifier=?',
                                      (account, identifier))
            if deleted.rowcount != 1:
                raise ValueError('unfinished character was not removed from the active slot')
            return True, True

    def _deletable_entry(self, identifier, flags, encoded):
        entry = self._entries(identifier, encoded)[0]
        if (entry.is_customized or flags not in (b'\x00\x00', b'\x01\x00')
                or entry.is_male != bool(flags[0]) or entry.is_locked or entry.is_survival
                or entry.instance_type != START_ZONE or entry.instance_name):
            raise ValueError('unsupported unfinished character deletion mode')
