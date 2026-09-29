"""Private, opt-in first world-state burst from the observed tutorial.

This is a bounded experimental replay, not a decoded world simulator. Known
identity occurrences are replaced before storage and again for each local
character. Unknown fields remain capture-derived and must stay private.
"""

from dataclasses import dataclass, field
import os
import stat
import uuid

from isac_protocol.codec import Cursor, DecodeError, ReferenceTable, encode_uvarint
from isac_protocol.framing import MessageFrame, decode_message_data, encode_message_data
from isac_protocol.world_messages import decode_type014d


MAGIC = b'ISACWCT1'
MAX_BYTES = 65536
MAX_FRAMES = 512


def _substitute(frames, old, new):
    if len(old) != len(new) or not old or old == new:
        raise ValueError('invalid continuation identity substitution')
    return tuple(MessageFrame(frame.type_id, frame.body.replace(old, new)) for frame in frames)


def _substitute_name(frames, old, new):
    if (not 1 <= len(old) <= 63 or not 1 <= len(new) <= 63
            or old == new or b'\0' in new):
        raise ValueError('invalid continuation display-name substitution')
    result = []
    seen = []
    for frame in frames:
        if old not in frame.body:
            result.append(frame)
            continue
        if frame.type_id not in (0x00f4, 0x01b7) or frame.body.count(old) != 1:
            raise ValueError('unsupported continuation display-name location')
        offset = frame.body.index(old)
        if offset < 1 or frame.body[offset - 1] != len(old):
            raise ValueError('unsupported continuation display-name prefix')
        if frame.type_id == 0x00f4 and (offset != 1 or frame.body[offset + len(old):] != b'\1'):
            raise ValueError('unsupported 0x00f4 display-name shape')
        if frame.type_id == 0x01b7 and not frame.body[offset + len(old):].startswith(b'\7soldier'):
            raise ValueError('unsupported 0x01b7 display-name shape')
        body = (frame.body[:offset - 1] + bytes([len(new)]) + new
                + frame.body[offset + len(old):])
        result.append(MessageFrame(frame.type_id, body))
        seen.append(frame.type_id)
    if sorted(seen) != [0x00f4, 0x01b7]:
        raise ValueError('incomplete continuation display-name fields')
    return tuple(result)


@dataclass(frozen=True)
class ExperimentalWorldContinuation:
    character_placeholder: bytes = field(repr=False)
    account_placeholder: bytes = field(repr=False)
    name_placeholder: bytes = field(repr=False)
    frames: tuple[MessageFrame, ...] = field(repr=False)

    def __post_init__(self):
        if (len(self.character_placeholder) != 16 or not any(self.character_placeholder)
                or len(self.account_placeholder) != 36
                or not 1 <= len(self.name_placeholder) <= 63
                or len(self.frames) < 2 or len(self.frames) > MAX_FRAMES
                or self.frames[0].type_id != 0x0102
                or self.frames[-1].type_id != 0x0102
                or sum(frame.type_id == 0x0012 for frame in self.frames) != 1
                or self.frames[-2].type_id != 0x0012):
            raise ValueError('unsupported experimental continuation shape')
        try:
            uuid.UUID(self.account_placeholder.decode('ascii'))
            self.name_placeholder.decode('ascii')
        except (ValueError, UnicodeError) as error:
            raise ValueError('invalid continuation placeholders') from error
        bodies = tuple(frame.body for frame in self.frames)
        for value in (self.character_placeholder, self.account_placeholder,
                      self.name_placeholder):
            if sum(body.count(value) for body in bodies) != 2:
                raise ValueError('unexpected continuation placeholder count')
        # Only these two observed length-prefixed fields may contain the
        # captured display name. Validate their shape before any rebinding.
        _substitute_name(self.frames, self.name_placeholder, b'X' * len(self.name_placeholder)
                         if self.name_placeholder != b'X' * len(self.name_placeholder)
                         else b'Y' * len(self.name_placeholder))

    @classmethod
    def from_bytes(cls, data):
        if not len(MAGIC) < len(data) <= MAX_BYTES or not data.startswith(MAGIC):
            raise ValueError('invalid continuation artifact header/size')
        cursor = Cursor(data[len(MAGIC):])
        character = cursor.read(16)
        account = cursor.read(36)
        name = cursor.read(cursor.read_uvarint(maximum_bits=8))
        count = cursor.read_uvarint(maximum_bits=16)
        if not 2 <= count <= MAX_FRAMES:
            raise ValueError('continuation frame count exceeds bound')
        frames = []
        for _ in range(count):
            length = cursor.read_uvarint(maximum_bits=32)
            if length > cursor.remaining:
                raise DecodeError('truncated continuation frame')
            frames.append(decode_message_data(cursor.read(length)))
        if cursor.remaining:
            raise DecodeError('trailing continuation bytes')
        result = cls(character, account, name, tuple(frames))
        if result.to_bytes() != data:
            raise ValueError('noncanonical continuation artifact')
        return result

    def to_bytes(self):
        body = (MAGIC + self.character_placeholder + self.account_placeholder
                + encode_uvarint(len(self.name_placeholder), maximum_bits=8)
                + self.name_placeholder
                + encode_uvarint(len(self.frames), maximum_bits=16))
        body += b''.join(encode_uvarint(len(message := encode_message_data(frame)),
                                         maximum_bits=32) + message for frame in self.frames)
        if len(body) > MAX_BYTES:
            raise ValueError('continuation artifact exceeds bound')
        return body

    def bind(self, character, initial_seed):
        identifier = character.identifier
        account = str(uuid.UUID(character.owner.profile_id)).encode('ascii')
        name = character.owner.display_name.encode('utf-8')
        if (len(identifier) != 16 or not any(identifier)
                or not 1 <= len(name) <= 63
                or identifier == self.character_placeholder
                or account == self.account_placeholder
                or name == self.name_placeholder
                or b'\0' in name):
            raise ValueError('local continuation identity cannot be rebound')
        frames = self.frames
        for old, new in ((self.character_placeholder, identifier),
                         (self.account_placeholder, account)):
            frames = _substitute(frames, old, new)
        frames = _substitute_name(frames, self.name_placeholder, name)
        table = ReferenceTable()
        decode_type014d(initial_seed, table)
        for frame in frames:
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
        return frames


def read_continuation(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_BYTES):
            raise ValueError('continuation must be a bounded, owner-only regular file')
        return ExperimentalWorldContinuation.from_bytes(stream.read(MAX_BYTES + 1))
