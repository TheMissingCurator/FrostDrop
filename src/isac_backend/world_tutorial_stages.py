"""Capture-bounded, opt-in tests for two intro-tutorial stage transitions.

The 0x006a header is only partially understood. Three matching messages
prove an observed sequence, not target hits or correct mission semantics.
"""

from dataclasses import dataclass, field, replace
import math
import os
import stat
import struct

from isac_protocol.codec import (CompactReference, Cursor, DecodeError, ReferenceTable,
                                 WireFloat32, decode_reference, encode_reference,
                                 encode_svarint32)
from isac_protocol.framing import MessageFrame
from isac_protocol.type0088 import Type0088, decode_type0088, encode_type0088
from isac_protocol.type00e6 import Type00E6SubRow, decode_type00e6, encode_type00e6
from isac_protocol.world_messages import Type014D, decode_type014d, encode_type014d
from isac_protocol.world_start import decode_world_start


MAGIC = b'ISACSTG2'
SIZE = len(MAGIC) + 16 + 16 + 12 + 4 + 32 + 16


def parse_shot_header(body, character_identifier, shot_reference):
    """Return (item reference, counter) for one observed bounded shape."""
    if not 150 <= len(body) <= 1560:
        return None
    try:
        cursor = Cursor(body)
        character, item, static = (cursor.read(16) for _ in range(3))
        counter, scalar, count = (cursor.read_svarint32() for _ in range(3))
    except DecodeError:
        return None
    if (character != character_identifier or static != shot_reference
            or scalar != 900 or not 1 <= count <= 16
            or len(body) != 56 + 94 * count or counter not in (31, 30, 29)):
        return None
    return item, counter


def parse_final_shot_header(body, character_identifier, item_reference, type_reference):
    """Recognize the first secondary shot observed at the retail final row."""
    if not 149 <= len(body) <= 1559:
        return None
    try:
        cursor = Cursor(body)
        character, item, static = (cursor.read(16) for _ in range(3))
        counter, scalar, count = (cursor.read_svarint32() for _ in range(3))
    except DecodeError:
        return None
    if (character != character_identifier or item != item_reference
            or static != type_reference or counter != 14 or scalar != 36
            or not 1 <= count <= 16 or len(body) != 55 + 94 * count):
        return None
    return count


def _read_shot_parts(body, table):
    """Read the observed 0x006a layout, preserving unnamed byte fields."""
    cursor = Cursor(body)
    references = tuple(decode_reference(cursor, table) for _ in range(3))
    values = tuple(cursor.read_svarint32() for _ in range(3))
    count = values[2]
    if not 1 <= count <= 16:
        raise DecodeError('unsupported shot child count')
    header_tail = cursor.read(4)
    children = []
    for _ in range(count):
        children.append((cursor.read(24), decode_reference(cursor, table),
                         cursor.read(6), decode_reference(cursor, table),
                         decode_reference(cursor, table), cursor.read(16)))
    if cursor.remaining:
        raise DecodeError('trailing shot bytes')
    return references, values, header_tail, children


def decode_shot_echo(body, table):
    """Advance the compact-reference dictionary for a previously sent echo."""
    working = table.clone()
    parts = _read_shot_parts(body, working)
    table.entries[:] = working.entries
    return parts


@dataclass(frozen=True)
class ExperimentalStageProgression:
    shot_reference: bytes = field(repr=False)
    final_reference: bytes = field(repr=False)
    final_position: tuple[WireFloat32, WireFloat32, WireFloat32] = field(repr=False)
    equip_item_index: int
    unequip_item_index: int
    equip_type_reference: bytes = field(repr=False)
    unequip_type_reference: bytes = field(repr=False)
    equip_signed_5: int
    equip_signed_6: int
    unequip_signed_5: int
    unequip_signed_6: int

    def __post_init__(self):
        if (len(self.shot_reference) != 16 or len(self.final_reference) != 16
                or self.shot_reference == self.final_reference
                or len(self.final_position) != 3
                or any(not isinstance(value, WireFloat32) or not math.isfinite(value.value)
                       for value in self.final_position)
                or not 0 <= self.equip_item_index < 4096
                or not 0 <= self.unequip_item_index < 4096
                or self.equip_item_index == self.unequip_item_index
                or len(self.equip_type_reference) != 16
                or len(self.unequip_type_reference) != 16
                or self.equip_type_reference == self.unequip_type_reference
                or any(not -(1 << 31) <= n < (1 << 31) for n in
                       (self.equip_signed_5, self.equip_signed_6,
                        self.unequip_signed_5, self.unequip_signed_6))):
            raise ValueError('invalid stage-progression artifact')

    def to_bytes(self):
        return (MAGIC + self.shot_reference + self.final_reference
                + struct.pack('<IIIHH', *(value.bits for value in self.final_position),
                              self.equip_item_index, self.unequip_item_index)
                + self.equip_type_reference + self.unequip_type_reference
                + struct.pack('<iiii', self.equip_signed_5, self.equip_signed_6,
                              self.unequip_signed_5, self.unequip_signed_6))

    @classmethod
    def from_bytes(cls, data):
        if len(data) != SIZE or not data.startswith(MAGIC):
            raise ValueError('invalid stage-progression artifact')
        position = tuple(WireFloat32(value) for value in struct.unpack_from('<III', data, 40))
        indexes = struct.unpack_from('<HH', data, 52)
        signed = struct.unpack_from('<iiii', data, 88)
        return cls(data[8:24], data[24:40], position, *indexes,
                   data[56:72], data[72:88], *signed)

    def shot_header(self, body, character_identifier):
        """Return (item reference, counter) for the observed bounded shape."""
        return parse_shot_header(body, character_identifier, self.shot_reference)

    @staticmethod
    def final_shot_header(body, character_identifier, item_reference, type_reference):
        return parse_final_shot_header(body, character_identifier, item_reference, type_reference)

    @staticmethod
    def matches_switch(body, character_identifier):
        if len(body) not in (105, 108):
            return False
        try:
            value = decode_type0088(body, None)
        except (DecodeError, ValueError):
            return False
        return (value.owner_reference.value == character_identifier
                and value.signed_0 == 1 and value.equipped == 0)

    @staticmethod
    def _table(initial_seed, frames):
        table = ReferenceTable()
        decode_type014d(initial_seed, table)
        active = None
        for frame in frames:
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x006a:
                decode_shot_echo(frame.body, table)
            elif frame.type_id == 0x00e6:
                active = decode_type00e6(frame.body, table)
        if active is None or len(active.rows_20) != 5 or active.byte_64 != 7:
            raise ValueError('missing tutorial stage state')
        return table, active

    def shot_echo(self, initial_seed, prior_frames, request_body, character_identifier,
                  *, final_item=None, final_type=None):
        """Experimental retail-shaped acknowledgement of one bounded intro shot.

        The last byte of each child middle field is not semantically decoded.
        Only the observed non-primary 0x80 -> 0x00 reconciliation is applied;
        this is a capture-derived hypothesis, not a general hit-result rule.
        """
        valid = (self.shot_header(request_body, character_identifier) is not None
                 if final_item is None else
                 parse_final_shot_header(request_body, character_identifier,
                                         final_item, final_type) is not None)
        if not valid:
            raise ValueError('shot echo request is outside intro sequence')
        table, _ = self._table(initial_seed, prior_frames)
        references, values, tail, children = _read_shot_parts(request_body, None)
        out = bytearray()
        for reference in references:
            out.extend(encode_reference(reference, table))
        for value in values:
            out.extend(encode_svarint32(value))
        out.extend(tail)
        for index, (prefix, reference_0, middle, reference_1, reference_2, suffix) in enumerate(children):
            out.extend(prefix)
            out.extend(encode_reference(reference_0, table))
            if index and middle[-1] == 0x80:
                middle = middle[:-1] + b'\x00'
            out.extend(middle)
            out.extend(encode_reference(reference_1, table))
            out.extend(encode_reference(reference_2, table))
            out.extend(suffix)
        frame = MessageFrame(0x006a, bytes(out))
        check = self._table(initial_seed, (*prior_frames, frame))[0]
        if check.entries != table.entries:
            raise ValueError('shot echo dictionary round-trip failed')
        return frame

    def shooting_reply(self, initial_seed, prior_frames):
        table, active = self._table(initial_seed, prior_frames)
        if tuple(row.signed_0_2[2] for row in active.rows_20) != (0, 4, 1, 0, 0):
            raise ValueError('unexpected shooting-stage baseline')
        rows = list(active.rows_20)
        for index, next_state in ((2, 4), (3, 1)):
            row = rows[index]
            rows[index] = replace(row, signed_0_2=(row.signed_0_2[0], row.signed_0_2[1], next_state))
        frame = MessageFrame(0x00e6, encode_type00e6(replace(active, rows_20=tuple(rows)), table))
        if len(frame.body) != 161:
            raise ValueError('unexpected shooting-stage update size')
        return frame, MessageFrame(0x0102, b'')

    def final_shot_reply(self, initial_seed, prior_frames):
        table, active = self._table(initial_seed, prior_frames)
        if tuple(row.signed_0_2[2] for row in active.rows_20) != (0, 4, 4, 4, 1):
            raise ValueError('unexpected final-shot baseline')
        rows = list(active.rows_20)
        row = rows[4]
        rows[4] = replace(row, signed_0_2=(row.signed_0_2[0], row.signed_0_2[1], 4))
        frame = MessageFrame(0x00e6, encode_type00e6(replace(active, rows_20=tuple(rows)), table))
        if len(frame.body) != 177:
            raise ValueError('unexpected final-shot update size')
        return frame

    def activity_close_reply(self, initial_seed, prior_frames):
        """Close the five-row intro activity using the observed retail header.

        This is a capture-derived transition, not a general mission-complete
        rule. It must follow the final secondary-shot row on the same channel.
        """
        table, active = self._table(initial_seed, prior_frames)
        if tuple(row.signed_0_2[2] for row in active.rows_20) != (0, 4, 4, 4, 4):
            raise ValueError('unexpected activity-close baseline')
        closed = replace(active, rows_20=(), byte_64=19,
                         float_50=WireFloat32(1065353216),
                         unsigned32_68=1, unsigned32_80=1)
        frame = MessageFrame(0x00e6, encode_type00e6(closed, table))
        if len(frame.body) != 44:
            raise ValueError('unexpected activity-close update size')
        return frame

    def switch_reply(self, initial_seed, startup_world, character_identifier,
                     request_body, prior_frames):
        table, active = self._table(initial_seed, prior_frames)
        if (tuple(row.signed_0_2[2] for row in active.rows_20) != (0, 4, 4, 1, 0)
                or self.final_reference in table.entries):
            raise ValueError('unexpected switch-stage baseline')
        seed = ReferenceTable()
        decode_type014d(initial_seed, seed)
        world = decode_world_start(startup_world, seed.clone())
        items = world.core.items_4d0
        if max(self.equip_item_index, self.unequip_item_index) >= len(items):
            raise ValueError('switch item is not in local startup')
        equip = items[self.equip_item_index]
        unequip = items[self.unequip_item_index]
        request = decode_type0088(request_body, None)
        if (request.owner_reference.value != character_identifier
                or request.item.reference_0.value != unequip.reference_0.value
                or request.item.reference_1.value != unequip.reference_1.value
                or equip.reference_1.value != self.equip_type_reference
                or unequip.reference_1.value != self.unequip_type_reference):
            raise ValueError('switch item lineage does not match local startup')
        equipment = []
        for equipped, item, signed_5, signed_6 in (
                (1, equip, self.equip_signed_5, self.equip_signed_6),
                (0, unequip, self.unequip_signed_5, self.unequip_signed_6)):
            body = encode_type0088(Type0088(0, equipped,
                CompactReference(character_identifier),
                replace(item, signed_5=signed_5, signed_6=signed_6)), table.clone())
            if len(body) != 30:
                raise ValueError('unexpected switch equipment update size')
            equipment.append(MessageFrame(0x0088, body))
        dictionary = MessageFrame(0x014d, encode_type014d(Type014D((
            CompactReference(self.final_reference, token=len(table.entries) * 2 + 1),)), table))
        rows = list(active.rows_20)
        row = rows[3]
        rows[3] = replace(row, signed_0_2=(row.signed_0_2[0], row.signed_0_2[1], 4))
        row = rows[4]
        rows[4] = replace(row, signed_0_2=(row.signed_0_2[0], row.signed_0_2[1], 1),
                          subrows=(Type00E6SubRow(CompactReference(self.final_reference),
                                                  self.final_position, 0, False),))
        frame = MessageFrame(0x00e6, encode_type00e6(replace(active, rows_20=tuple(rows)), table))
        if len(frame.body) != 177:
            raise ValueError('unexpected switch-stage update size')
        return (*equipment, dictionary, frame, MessageFrame(0x0102, b''))


def read_stage_progression(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size != SIZE):
            raise ValueError('stage-progression artifact must be owner-only and exact-sized')
        return ExperimentalStageProgression.from_bytes(stream.read(SIZE + 1))
