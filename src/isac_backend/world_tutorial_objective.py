"""Opt-in, one-shot delivery test for the first active tutorial objective.

This tests client display of an observed state. It does not infer the retail
trigger, advance objectives, or implement a mission simulation.
"""

from dataclasses import dataclass, field, replace
import os
import stat
import struct

from isac_protocol.codec import CompactReference, ReferenceTable, WireFloat32
from isac_protocol.framing import MessageFrame
from isac_protocol.type00e6 import Type00E6SubRow, decode_type00e6, encode_type00e6
from isac_protocol.world_messages import Type014D, decode_type014d, encode_type014d


MAGIC = b'ISACOBJ1'
SIZE = len(MAGIC) + 16 + 12


@dataclass(frozen=True)
class ExperimentalFirstObjective:
    objective_reference: bytes = field(repr=False)
    position: tuple[WireFloat32, WireFloat32, WireFloat32] = field(repr=False)

    def __post_init__(self):
        if len(self.objective_reference) != 16 or len(self.position) != 3 or not all(
                isinstance(value, WireFloat32) for value in self.position):
            raise ValueError('invalid first-objective template')

    def to_bytes(self):
        return MAGIC + self.objective_reference + struct.pack('<III',
            *(value.bits for value in self.position))

    @classmethod
    def from_bytes(cls, data):
        if len(data) != SIZE or not data.startswith(MAGIC):
            raise ValueError('invalid first-objective artifact')
        return cls(data[len(MAGIC):len(MAGIC)+16], tuple(WireFloat32(value)
            for value in struct.unpack('<III', data[-12:])))

    def bind(self, initial_seed, continuation_frames, agent_frames, activation):
        """Rebuild the subrow reference at the *local* dictionary index."""
        table = ReferenceTable()
        decode_type014d(initial_seed, table)
        for frame in (*continuation_frames, *agent_frames):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x00e6:
                decode_type00e6(frame.body, table)
        if activation.type_id != 0x00e6:
            raise ValueError('missing zero-state activation')
        baseline = decode_type00e6(activation.body, table)
        if (baseline.byte_64 != 7 or len(baseline.rows_20) != 5
                or any(row.signed_0_2[2] != 0 or row.subrows for row in baseline.rows_20)
                or self.objective_reference in table.entries):
            raise ValueError('unsupported first-objective baseline')
        before = table.clone()
        dictionary = MessageFrame(0x014d, encode_type014d(Type014D((
            CompactReference(self.objective_reference, token=len(table.entries) * 2 + 1),)), table))
        if len(table.entries) != len(before.entries) + 1:
            raise ValueError('first-objective dictionary insertion failed')
        row = baseline.rows_20[1]
        active_row = replace(row, signed_0_2=(row.signed_0_2[0], row.signed_0_2[1], 1),
            subrows=(Type00E6SubRow(CompactReference(self.objective_reference),
                self.position, 0, False),))
        active = replace(baseline, rows_20=(baseline.rows_20[0], active_row,
            *baseline.rows_20[2:]))
        active_frame = MessageFrame(0x00e6, encode_type00e6(active, table))
        if len(table.entries) != len(before.entries) + 1:
            raise ValueError('first-objective activity introduced extra references')
        # Check the exact sequential dictionary/application shape the client sees.
        decode_type014d(dictionary.body, before)
        check = decode_type00e6(active_frame.body, before)
        if (len(before.entries) != len(table.entries) or check.rows_20[1].signed_0_2[2] != 1
                or len(check.rows_20[1].subrows) != 1
                or check.rows_20[1].subrows[0].reference_0.value != self.objective_reference
                or any(check.rows_20[index].signed_0_2[2] != 0 for index in (0, 2, 3, 4))):
            raise ValueError('first-objective local validation failed')
        return dictionary, active_frame, MessageFrame(0x0102, b'')


def read_first_objective(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size != SIZE):
            raise ValueError('first-objective artifact must be owner-only and exact-sized')
        return ExperimentalFirstObjective.from_bytes(stream.read(SIZE + 1))
