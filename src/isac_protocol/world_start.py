"""Complete 0x0007 wire codec for the observed EMPTY dynamic-group shape.

This is not a world-state generator. Nonempty dynamically typed subobjects
are explicitly unsupported, never skipped as opaque bytes. Kept separate
from the default registry until broader world variants are understood.
"""
from dataclasses import dataclass, field

from .codec import (CompactReference, Cursor, DecodeError, ReferenceTable,
    WireFloat32, decode_reference, encode_reference, encode_uvarint,
    encode_svarint32, encode_u8_varint, encode_bool, encode_length_prefixed_bytes)
from .type0088 import encode_equipment_item
from .world_messages import (Type0007Prefix, decode_type0007_prefix,
    encode_type0007_core_tail, _read_world_float, _valid_world_float, _counted)


@dataclass(frozen=True)
class WorldStartChild:
    reference: CompactReference = field(repr=False)
    byte_10: int
    flag_18: bool
    float_14: WireFloat32 | None


@dataclass(frozen=True)
class WorldStartGroup:
    reference: CompactReference = field(repr=False)
    children: tuple[WorldStartChild, ...]


@dataclass(frozen=True)
class WorldStart:
    core: Type0007Prefix = field(repr=False)
    byte_float_rows_710: tuple[tuple[int, WireFloat32], ...]
    groups_720: tuple[WorldStartGroup, ...]
    reference_float_rows_730: tuple[tuple[CompactReference, WireFloat32], ...] = field(repr=False)
    # One sint8 per group. Each group has an explicitly empty subobject list.
    empty_group_signed_740: tuple[int, ...]
    signed_750: int
    references_758: tuple[CompactReference, ...] = field(repr=False)


def _sint8(value):
    if not -128 <= value <= 127:
        raise ValueError('world sint8 out of range')
    return encode_u8_varint((value << 1) ^ (value >> 7))


def _read_sint8(c):
    encoded = c.read_u8_varint()
    return (encoded >> 1) ^ -(encoded & 1)


def _floating(value):
    if not _valid_world_float(value):
        raise ValueError('client-rejected world float')
    return value.encode()


def _encode_core(value: Type0007Prefix, table):
    """Serialize typed fields; never read source bytes or diagnostic offsets."""
    def ref(v):
        return encode_reference(v, table)
    def signed(values):
        return b''.join(encode_svarint32(v) for v in values)
    def string(v):
        if len(v) > 255:
            raise ValueError('world prefix byte-string bound exceeded')
        return encode_length_prefixed_bytes(v)
    if (len(value.signed_arrays_3c_64_8c) != 3 or
        any(len(a) != 10 for a in value.signed_arrays_3c_64_8c) or
        len(value.fixed_rows_b4) != 9 or len(value.vector_290) != 3 or
        value.collection_count_4d0 != len(value.items_4d0) or len(value.items_4d0) > 65536):
        raise ValueError('invalid world core collection shape')
    for row in value.fixed_rows_b4:
        if len(row.signed_values) != 6 or len(row.floats) != 6 or len(row.flags) != 2:
            raise ValueError('invalid fixed world row')
    return (ref(value.reference_20) + encode_uvarint(value.unsigned_30, maximum_bits=32)
        + encode_svarint32(value.signed_34) + _sint8(value.signed_38)
        + b''.join(signed(a) for a in value.signed_arrays_3c_64_8c)
        + b''.join(signed(row.signed_values) + b''.join(_floating(f) for f in row.floats)
            + b''.join(encode_bool(b) for b in row.flags) for row in value.fixed_rows_b4)
        + signed((value.signed_288, value.signed_28c))
        + b''.join(_floating(f) for f in value.vector_290) + _floating(value.float_29c)
        + ref(value.reference_2a0) + string(value.bytes_2b0) + encode_svarint32(value.signed_3b0)
        + string(value.bytes_3b8) + ref(value.reference_4b8) + encode_bool(value.flag_4c8)
        + encode_svarint32(len(value.items_4d0))
        + b''.join(encode_equipment_item(item, table) for item in value.items_4d0)
        + ref(value.reference_4e0) + encode_type0007_core_tail(value.core_tail, table))


def decode_world_start(body: bytes, table: ReferenceTable | None) -> WorldStart:
    working = table.clone() if table is not None else None
    core = decode_type0007_prefix(body, working)
    # Prefix intentionally does not commit table state. Its typed encoder
    # reconstructs that state, and validates exact canonical byte equality.
    try:
        encoded = _encode_core(core, working)
    except ValueError as error:
        raise DecodeError('unsupported world core values') from error
    if encoded != body[:core.consumed_bytes]:
        raise DecodeError('noncanonical or unsupported world core')
    c = Cursor(body)
    c.read(core.consumed_bytes)
    def ref():
        return decode_reference(c, working)
    def child():
        reference, byte, flag = ref(), c.read_u8_varint(), c.read_bool()
        return WorldStartChild(reference, byte, flag, None if flag else _read_world_float(c))
    def group():
        # Child count precedes the group's reference, unlike a usual list.
        count = c.read_svarint32()
        if not 0 <= count <= 65536 or count > c.remaining:
            raise DecodeError('world group bound exceeded')
        reference = ref()
        return WorldStartGroup(reference, tuple(child() for _ in range(count)))
    floats = tuple((c.read_u8_varint(), _read_world_float(c)) for _ in range(c.read_u8_varint()))
    groups = _counted(c, group)
    ref_floats = _counted(c, lambda: (ref(), _read_world_float(c)))
    count = c.read_uvarint(maximum_bits=32)
    if count > 65536 or count > c.remaining // 2:
        raise DecodeError('dynamic group bound exceeded')
    flags = []
    for _ in range(count):
        if c.read_uvarint(maximum_bits=32):
            raise DecodeError('nonempty dynamic world subobjects unsupported (reader 0xfe7b60)')
        flags.append(_read_sint8(c))
    signed = _read_sint8(c)
    refs = tuple(ref() for _ in range(c.read_uvarint(maximum_bits=16)))
    if c.remaining:
        raise DecodeError('trailing world-start bytes')
    value = WorldStart(core, floats, groups, ref_floats, tuple(flags), signed, refs)
    # Canonical full-body validation also enforces bool/float output shape.
    check = table.clone() if table is not None else None
    if encode_world_start(value, check) != body or (working is not None and check.entries != working.entries):
        raise DecodeError('nonidentical world-start round trip')
    if table is not None:
        table.entries[:] = working.entries
    return value


def encode_world_start(value: WorldStart, table: ReferenceTable | None) -> bytes:
    working = table.clone() if table is not None else None
    def ref(v):
        return encode_reference(v, working)
    def counted(rows, encode):
        if len(rows) > 65536:
            raise ValueError('world collection bound exceeded')
        return encode_svarint32(len(rows)) + b''.join(encode(row) for row in rows)
    def child(v):
        if v.flag_18 != (v.float_14 is None):
            raise ValueError('world child conditional float mismatch')
        return ref(v.reference) + encode_u8_varint(v.byte_10) + encode_bool(v.flag_18) + (
            b'' if v.float_14 is None else _floating(v.float_14))
    def group(v):
        if len(v.children) > 65536:
            raise ValueError('world child count exceeded')
        return encode_svarint32(len(v.children)) + ref(v.reference) + b''.join(child(row) for row in v.children)
    if len(value.empty_group_signed_740) > 65536:
        raise ValueError('world dynamic group bound exceeded')
    body = (_encode_core(value.core, working)
        + encode_u8_varint(len(value.byte_float_rows_710))
        + b''.join(encode_u8_varint(byte) + _floating(f) for byte, f in value.byte_float_rows_710)
        + counted(value.groups_720, group)
        + counted(value.reference_float_rows_730, lambda row: ref(row[0]) + _floating(row[1]))
        + encode_uvarint(len(value.empty_group_signed_740), maximum_bits=32)
        + b''.join(b'\x00' + _sint8(v) for v in value.empty_group_signed_740)
        + _sint8(value.signed_750)
        + encode_uvarint(len(value.references_758), maximum_bits=16)
        + b''.join(ref(v) for v in value.references_758))
    if table is not None:
        table.entries[:] = working.entries
    return body
