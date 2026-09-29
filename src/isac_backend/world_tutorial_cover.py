"""Opt-in first cover-completion experiment; not a mission simulator."""

from dataclasses import dataclass, field, replace
import math
import os
import stat
import struct

from isac_protocol.codec import CompactReference, DecodeError, ReferenceTable, WireFloat32
from isac_protocol.framing import MessageFrame
from isac_protocol.type0014 import decode_type0014, encode_type0014_compact
from isac_protocol.type00e6 import Type00E6SubRow, decode_type00e6, encode_type00e6
from isac_protocol.world_messages import Type014D, decode_type014d, encode_type014d


MAGIC = b'ISACCVR1'
SIZE = len(MAGIC) + 16 + 12 + 16 + 12
Vec3f = tuple[WireFloat32, WireFloat32, WireFloat32]


@dataclass(frozen=True)
class ExperimentalCoverCompletion:
    cover_reference: bytes = field(repr=False)
    cover_position: Vec3f = field(repr=False)
    next_reference: bytes = field(repr=False)
    next_position: Vec3f = field(repr=False)

    def __post_init__(self):
        if (len(self.cover_reference) != 16 or len(self.next_reference) != 16
                or self.cover_reference == self.next_reference
                or len(self.cover_position) != 3 or len(self.next_position) != 3
                or any(not isinstance(component, WireFloat32)
                       or not math.isfinite(component.value)
                       for point in (self.cover_position, self.next_position)
                       for component in point)):
            raise ValueError('invalid cover-completion artifact')

    def to_bytes(self):
        return (MAGIC + self.cover_reference
                + struct.pack('<III', *(v.bits for v in self.cover_position))
                + self.next_reference
                + struct.pack('<III', *(v.bits for v in self.next_position)))

    @classmethod
    def from_bytes(cls, data):
        if len(data) != SIZE or not data.startswith(MAGIC):
            raise ValueError('invalid cover-completion artifact')
        return cls(data[8:24], tuple(WireFloat32(v) for v in struct.unpack_from('<III', data, 24)),
                   data[36:52], tuple(WireFloat32(v) for v in struct.unpack_from('<III', data, 52)))

    def matches(self, body, character_identifier):
        """Exact observed entry fields plus a bounded cover-point vicinity."""
        try:
            value = decode_type0014(body)
        except (DecodeError, ValueError):
            return False
        if (value.reference_0 != character_identifier
                or value.reference_1 != self.cover_reference
                or (value.signed_0, value.signed_1, value.signed_2) != (1, 0, 0)
                or value.bytes_0_3 != (1, 0, 0, 85)):
            return False
        delta = [v.value - target.value for v, target in zip(value.vector_1, self.cover_position)]
        return all(math.isfinite(v) for v in delta) and delta[0] ** 2 + delta[2] ** 2 <= 4.0 and abs(delta[1]) <= 1.0

    def bind(self, initial_seed, continuation_frames, agent_frames, activation, first_frames,
             ack_request=None):
        """Build the observed row-1-complete/row-2-active state at local indices."""
        table = ReferenceTable()
        decode_type014d(initial_seed, table)
        active = None
        for frame in (*continuation_frames, *agent_frames, activation, *first_frames):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x00e6:
                active = decode_type00e6(frame.body, table)
        if (active is None or active.byte_64 != 7 or len(active.rows_20) != 5
                or tuple(row.signed_0_2[2] for row in active.rows_20) != (0, 1, 0, 0, 0)
                or len(active.rows_20[1].subrows) != 1
                or self.next_reference in table.entries):
            raise ValueError('unsupported first-cover activity baseline')
        prelude = ()
        if ack_request is not None:
            request = decode_type0014(ack_request)
            if not self.matches(ack_request, request.reference_0):
                raise ValueError('cover echo request does not match bounded gate')
            if self.cover_reference not in table.entries:
                seed = MessageFrame(0x014d, encode_type014d(Type014D((
                    CompactReference(self.cover_reference,
                        token=len(table.entries) * 2 + 1),)), table))
                prelude = (seed,)
            prelude += (MessageFrame(0x0014, encode_type0014_compact(request, table)),
                        MessageFrame(0x0102, b''))
        dictionary = MessageFrame(0x014d, encode_type014d(Type014D((
            CompactReference(self.next_reference, token=len(table.entries) * 2 + 1),)), table))
        row1, row2 = active.rows_20[1:3]
        row1 = replace(row1, signed_0_2=(row1.signed_0_2[0], row1.signed_0_2[1], 4))
        row2 = replace(row2, signed_0_2=(row2.signed_0_2[0], row2.signed_0_2[1], 1),
            subrows=(Type00E6SubRow(CompactReference(self.next_reference),
                                    self.next_position, 0, False),))
        updated = replace(active, rows_20=(active.rows_20[0], row1, row2, *active.rows_20[3:]))
        state = MessageFrame(0x00e6, encode_type00e6(updated, table))
        if len(state.body) != 161:
            raise ValueError('unexpected cover-completion update size')
        return (*prelude, dictionary, state, MessageFrame(0x0102, b''))


def read_cover_completion(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size != SIZE):
            raise ValueError('cover-completion artifact must be owner-only and exact-sized')
        return ExperimentalCoverCompletion.from_bytes(stream.read(SIZE + 1))
