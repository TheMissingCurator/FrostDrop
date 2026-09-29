"""Opt-in, capture-derived presentation nodes for local finalization.

Only the node collection is borrowed from a retail starting character. The
appearance floats come from the local client's authenticated 0x000c request;
profile identity and all scalar progress fields remain locally generated.
"""
from dataclasses import dataclass, replace
import os
import stat

from isac_protocol.agent_submission import AgentSubmission
from isac_protocol.character_record import (
    CharacterRecord, decode_character_record, encode_character_record,
    starting_character_record,
)

MAGIC = b'ISACCHR1'
MAX_BYTES = 4096


@dataclass(frozen=True)
class ExperimentalCharacterTemplate:
    record: CharacterRecord

    def __post_init__(self):
        baseline = starting_character_record()
        if (len(self.record.nodes) != 18 or any(node.children for node in self.record.nodes)
                or self.record.float_bits_458 != (0,) * 32
                or self.record.pairs_4d8 or not self.record.flag_450
                or self.record.words_510_528 != baseline.words_510_528
                or self.record.words_530_538 != baseline.words_530_538
                or self.record.bits_53c != baseline.bits_53c):
            raise ValueError('unsupported experimental character template')

    def bind(self, submission: AgentSubmission) -> bytes:
        if not submission.final_flag:
            raise ValueError('unfinished agent submission cannot finalize profile')
        record = replace(self.record,
            float_bits_458=tuple(slot.bits for slot in submission.float_slots))
        return encode_character_record(record)

    def to_bytes(self) -> bytes:
        return MAGIC + encode_character_record(self.record)

    @classmethod
    def from_bytes(cls, data: bytes):
        if not len(MAGIC) < len(data) <= MAX_BYTES or not data.startswith(MAGIC):
            raise ValueError('invalid experimental character template')
        value = cls(decode_character_record(data[len(MAGIC):]))
        if value.to_bytes() != data:
            raise ValueError('noncanonical experimental character template')
        return value


def read_character_template(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_BYTES):
            raise ValueError('character template must be a bounded, owner-only regular file')
        return ExperimentalCharacterTemplate.from_bytes(stream.read(MAX_BYTES + 1))
