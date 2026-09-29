"""Private, one-shot experimental response to tutorial agent submission.

The response is capture-derived, not a character-creation implementation. It
includes the identifier-dictionary updates missed while the local world has
no simulation, followed by a bounded retail response window. Only a request
for the authenticated local character may trigger it.
"""

from dataclasses import dataclass, field
import os
import stat

from isac_protocol.codec import Cursor, DecodeError, ReferenceTable, encode_uvarint
from isac_protocol.framing import MessageFrame, decode_message_data, encode_message_data
from isac_protocol.world_messages import decode_type014d


MAGIC = b'ISACAUT1'
MAX_BYTES = 16384
MAX_PRELUDE = 64
MAX_RESPONSE = 256


@dataclass(frozen=True)
class ExperimentalAgentResponse:
    dictionary_prelude: tuple[MessageFrame, ...] = field(repr=False)
    response_frames: tuple[MessageFrame, ...] = field(repr=False)

    def __post_init__(self):
        if (not 1 <= len(self.dictionary_prelude) <= MAX_PRELUDE
                or not 1 <= len(self.response_frames) <= MAX_RESPONSE
                or any(frame.type_id != 0x014d for frame in self.dictionary_prelude)
                or not any(frame.type_id == 0x0100 and len(frame.body) == 1
                           for frame in self.response_frames)
                or not any(frame.type_id == 0x0012 and len(frame.body) == 140
                           for frame in self.response_frames)
                or not any(frame.type_id == 0x015a for frame in self.response_frames)
                or not any(frame.type_id == 0x0102 for frame in self.response_frames)):
            raise ValueError('unsupported experimental agent response shape')

    @classmethod
    def from_bytes(cls, data):
        if not len(MAGIC) < len(data) <= MAX_BYTES or not data.startswith(MAGIC):
            raise ValueError('invalid agent response artifact header/size')
        cursor = Cursor(data[len(MAGIC):])
        groups = []
        for maximum in (MAX_PRELUDE, MAX_RESPONSE):
            count = cursor.read_uvarint(maximum_bits=16)
            if not 1 <= count <= maximum:
                raise ValueError('agent response frame count exceeds bound')
            frames = []
            for _ in range(count):
                length = cursor.read_uvarint(maximum_bits=32)
                if length > cursor.remaining:
                    raise DecodeError('truncated agent response frame')
                frames.append(decode_message_data(cursor.read(length)))
            groups.append(tuple(frames))
        if cursor.remaining:
            raise DecodeError('trailing agent response bytes')
        result = cls(*groups)
        if result.to_bytes() != data:
            raise ValueError('noncanonical agent response artifact')
        return result

    def to_bytes(self):
        data = MAGIC
        for frames in (self.dictionary_prelude, self.response_frames):
            data += encode_uvarint(len(frames), maximum_bits=16)
            for frame in frames:
                message = encode_message_data(frame)
                data += encode_uvarint(len(message), maximum_bits=32) + message
        if len(data) > MAX_BYTES:
            raise ValueError('agent response artifact exceeds bound')
        return data

    def bind(self, initial_seed, continuation_frames):
        """Validate dictionary lineage and return the observed ordered burst."""
        table = ReferenceTable()
        decode_type014d(initial_seed, table)
        for frame in (*continuation_frames, *self.dictionary_prelude, *self.response_frames):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
        return (*self.dictionary_prelude, *self.response_frames)


def read_agent_response(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_BYTES):
            raise ValueError('agent response must be a bounded, owner-only regular file')
        return ExperimentalAgentResponse.from_bytes(stream.read(MAX_BYTES + 1))
