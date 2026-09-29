"""One-shot, opt-in experiment for the first tutorial activity activation.

The captured 0x00e6 frame is a state candidate, not a complete mission engine.
It is sent only after authenticated local appearance submission and validated
against the exact local reference-dictionary lineage.
"""
from dataclasses import dataclass, field
import os
import stat

from isac_protocol.codec import ReferenceTable
from isac_protocol.framing import MessageFrame, decode_message_data, encode_message_data
from isac_protocol.type00e6 import decode_type00e6
from isac_protocol.world_messages import decode_type014d

MAGIC = b'ISACTSA1'
MAX_BYTES = 512


@dataclass(frozen=True)
class ExperimentalTutorialActivation:
    frame: MessageFrame = field(repr=False)

    def __post_init__(self):
        if self.frame.type_id != 0x00e6 or len(self.frame.body) > MAX_BYTES - len(MAGIC):
            raise ValueError('unsupported tutorial activation frame')

    def to_bytes(self):
        return MAGIC + encode_message_data(self.frame)

    @classmethod
    def from_bytes(cls, data):
        if not len(MAGIC) < len(data) <= MAX_BYTES or not data.startswith(MAGIC):
            raise ValueError('invalid tutorial activation artifact')
        result = cls(decode_message_data(data[len(MAGIC):]))
        if result.to_bytes() != data:
            raise ValueError('noncanonical tutorial activation artifact')
        return result

    def bind(self, initial_seed, continuation_frames, agent_frames):
        table = ReferenceTable()
        decode_type014d(initial_seed, table)
        initial = None
        for frame in (*continuation_frames, *agent_frames):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x00e6:
                value = decode_type00e6(frame.body, table)
                if not value.rows_20 and value.byte_64 == 0:
                    initial = value
        if initial is None:
            raise ValueError('missing initial tutorial activity state')
        count = len(table.entries)
        value = decode_type00e6(self.frame.body, table)
        if (len(table.entries) != count or value.reference_0.value != initial.reference_0.value
                or value.byte_64 != 7 or len(value.rows_20) != 5
                or any(row.signed_0_2[2] != 0 or row.subrows for row in value.rows_20)):
            raise ValueError('unsupported tutorial activity activation state')
        return self.frame


def read_tutorial_activation(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_BYTES):
            raise ValueError('tutorial activation must be a bounded, owner-only regular file')
        return ExperimentalTutorialActivation.from_bytes(stream.read(MAX_BYTES + 1))
