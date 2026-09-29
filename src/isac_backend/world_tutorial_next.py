"""Capture-derived, one-shot handoff into the four-row safe-house activity.

The close companions are deliberately experimental. Their full semantics and
the later safe-house PC/side-mission unlock are not yet decoded.
"""

from dataclasses import dataclass, field
import hashlib
import os
import stat
import struct

from isac_protocol.codec import CompactReference, encode_reference
from isac_protocol.framing import MessageFrame
from isac_protocol.type00e6 import decode_type00e6, encode_type00e6
from isac_protocol.world_messages import Type014D, encode_type014d


MAGIC = b'ISACNXT1'
MAX_BYTES = 1024
DELTA_015A_SHA256 = 'ea41b29974d8e97c5492b4b6032fe306b7e6967f8ca4cfa96fafc3358b3890c7'


@dataclass(frozen=True)
class ExperimentalNextActivity:
    close_dictionary_reference: bytes = field(repr=False)
    close_event_reference: bytes = field(repr=False)
    close_event_tail: bytes = field(repr=False)
    activity_body_raw: bytes = field(repr=False)

    def __post_init__(self):
        if (len(self.close_dictionary_reference) != 16
                or len(self.close_event_reference) != 16
                or len(self.close_event_tail) != 7
                or not 1 <= len(self.activity_body_raw) <= MAX_BYTES - 49):
            raise ValueError('invalid next-activity artifact size')
        value = decode_type00e6(self.activity_body_raw, None)
        if (encode_type00e6(value, None) != self.activity_body_raw
                or value.byte_64 != 7 or len(value.rows_20) != 4
                or tuple(row.signed_0_2[2] for row in value.rows_20) != (1, 0, 0, 0)
                or tuple(len(row.subrows) for row in value.rows_20) != (1, 0, 0, 0)
                or value.reference_signed_88 or value.groups_98):
            raise ValueError('unsupported next-activity state')

    def to_bytes(self):
        return (MAGIC + self.close_dictionary_reference + self.close_event_reference
                + self.close_event_tail + struct.pack('<H', len(self.activity_body_raw))
                + self.activity_body_raw)

    @classmethod
    def from_bytes(cls, data):
        if not len(MAGIC) + 41 < len(data) <= MAX_BYTES or not data.startswith(MAGIC):
            raise ValueError('invalid next-activity artifact')
        size = struct.unpack_from('<H', data, 47)[0]
        if len(data) != 49 + size:
            raise ValueError('truncated next-activity artifact')
        value = cls(data[8:24], data[24:40], data[40:47], data[49:])
        if value.to_bytes() != data:
            raise ValueError('noncanonical next-activity artifact')
        return value

    def bind(self, initial_seed, prior_frames, stages, character_identifier,
             *, include_close_companions=False):
        """Build two batches; unverified close companions stay opt-in."""
        table, _ = stages._table(initial_seed, prior_frames)
        value = decode_type00e6(self.activity_body_raw, None)
        new = (value.reference_0.value, value.rows_20[0].subrows[0].reference_0.value)
        existing = (value.reference_1.value, value.reference_b0.value,
                    *(row.reference_0.value for row in value.rows_20))
        event_reference = (character_identifier if self.close_event_reference == bytes(16)
                           else self.close_event_reference)
        if (character_identifier in (self.close_dictionary_reference, *new, *existing)
                or len(set(new)) != 2 or any(ref is None or ref in table.entries for ref in new)
                or any(ref is None or ref not in table.entries for ref in existing)
                or self.close_dictionary_reference in table.entries
                or event_reference not in table.entries):
            raise ValueError('next activity reference lineage mismatch')
        if include_close_companions:
            close_dictionary = MessageFrame(0x014d, encode_type014d(Type014D((
                CompactReference(self.close_dictionary_reference,
                                 token=len(table.entries) * 2 + 1),)), table))
            close_event = MessageFrame(0x0064,
                encode_reference(CompactReference(event_reference), table)
                + self.close_event_tail)
            if len(close_event.body) != 9:
                raise ValueError('unexpected close companion size')
            close = stages.activity_close_reply(initial_seed, (*prior_frames, close_dictionary))
            close_frames = (close_dictionary, close_event, MessageFrame(0x0102, b''),
                            close, MessageFrame(0x01ae, b'\0' * 8), MessageFrame(0x0102, b''))
        else:
            close = stages.activity_close_reply(initial_seed, prior_frames)
            close_frames = (close, MessageFrame(0x0102, b''))
        dictionary = MessageFrame(0x014d, encode_type014d(Type014D(tuple(
            CompactReference(ref, token=(len(table.entries) + index) * 2 + 1)
            for index, ref in enumerate(new))), table))
        activity = MessageFrame(0x00e6, encode_type00e6(value, table))
        if len(dictionary.body) != 37 or len(activity.body) != 128:
            raise ValueError('unexpected next-activity batch size')
        next_frames = (dictionary, activity, MessageFrame(0x0102, b''))
        return close_frames, next_frames


def read_next_activity(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or not 50 <= info.st_size <= MAX_BYTES):
            raise ValueError('next-activity artifact must be owner-only and bounded')
        return ExperimentalNextActivity.from_bytes(stream.read(MAX_BYTES + 1))


def read_dialogue_015a(path):
    """Read the single pinned, capture-private post-handoff candidate."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size != 35):
            raise ValueError('dialogue candidate must be a 35-byte owner-only regular file')
        body = stream.read(36)
    if len(body) != 35 or hashlib.sha256(body).hexdigest() != DELTA_015A_SHA256:
        raise ValueError('dialogue candidate does not match the pinned retail frame')
    return body
