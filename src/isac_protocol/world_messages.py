"""Statically recovered world-message structures (findings 118 and 119).

Only 0x014d's dictionary side effect is named semantically. Reward/progression
candidates remain offset-named. The 0x0007 reader below is explicitly a PREFIX
reader, not a world snapshot decoder or an opaque-tail replay codec.
"""
from dataclasses import dataclass, field

from .codec import (
    CompactReference, Cursor, DecodeError, ReferenceTable, decode_reference,
    encode_reference, encode_uvarint, encode_svarint32, encode_u8_varint,
    encode_bool, WireFloat32, encode_svarint64, encode_length_prefixed_bytes,
)
from .type0088 import Type0088Item, decode_equipment_item


MAX_DICTIONARY_ROWS = 65536


def _finish(cursor, table, working):
    if cursor.remaining:
        raise DecodeError("trailing world-message bytes")
    if table is not None:
        table.entries[:] = working.entries


def _working(table):
    return table.clone() if table is not None else None


@dataclass(frozen=True)
class Type014D:
    references: tuple[CompactReference, ...]


def decode_type014d(body: bytes, table: ReferenceTable | None) -> Type014D:
    c, t = Cursor(body), _working(table)
    count = c.read_uvarint(maximum_bits=32)
    if count > MAX_DICTIONARY_ROWS or count > c.remaining:
        raise DecodeError("dictionary collection bound exceeded")
    value = Type014D(tuple(decode_reference(c, t) for _ in range(count)))
    _finish(c, table, t)
    return value


def encode_type014d(value: Type014D, table: ReferenceTable | None) -> bytes:
    if len(value.references) > MAX_DICTIONARY_ROWS:
        raise ValueError("dictionary collection bound exceeded")
    t = _working(table)
    body = encode_uvarint(len(value.references), maximum_bits=32)
    body += b"".join(encode_reference(ref, t) for ref in value.references)
    if table is not None:
        table.entries[:] = t.entries
    return body


@dataclass(frozen=True)
class Type0007FixedRow:
    signed_values: tuple[int, ...]
    floats: tuple[WireFloat32, ...]
    flags: tuple[bool, bool]


@dataclass(frozen=True)
class Type0007TaggedBytes:
    tag: int
    data: bytes = field(repr=False)


# Parent-relative offsets, not byte offsets in the wire body. Memory allocation
# and inline-array storage flags do NOT add fields to these counted lists.
CORE_TAIL_COLLECTIONS = (
    (0x540, 'reference'), (0x550, 'float'), (0x560, 'reference_bool3'),
    (0x570, 'reference_pair'), (0x580, 'reference'), (0x590, 'reference'),
    (0x5a0, 'reference_signed'), (0x5b0, 'reference_signed_bool'),
    (0x5c0, 'float'), (0x5d0, 'float'), (0x5e0, 'reference_signed'),
    (0x5f0, 'reference'), (0x600, 'reference'), (0x610, 'reference'),
    (0x620, 'reference'), (0x630, 'reference_byte'),
    (0x640, 'reference'), (0x650, 'reference'), (0x660, 'bytes'),
)


@dataclass(frozen=True)
class Type0007Collection:
    parent_offset: int
    rows: tuple = field(repr=False)


@dataclass(frozen=True)
class Type0007CoreTail:
    fixed_bytes_4f0: bytes = field(repr=False)
    tagged_bytes_500: Type0007TaggedBytes
    collections: tuple[Type0007Collection, ...]
    flags_69d_69e_69f_6a3_6a4_6a5: tuple[bool, ...]
    signed64_6a8: int
    floats_6b0_6b4: tuple[WireFloat32, WireFloat32]
    signed_6b8_6bc: tuple[int, int]
    signed64_6c0: int
    references_670_680: tuple[CompactReference, CompactReference]
    signed_690_694: tuple[int, int]
    unsigned_698: int
    flags_69c_6a0_6a1_6a2_6c8: tuple[bool, ...]
    byte_strings_6d0: tuple[bytes, ...] = field(repr=False)
    byte_strings_6e0: tuple[bytes, ...] = field(repr=False)
    unsigned_6f0_6f4: tuple[int, int]
    signed_6f8: int
    signed64_700: int
    flags_708_709: tuple[bool, bool]
    float_70c: WireFloat32


def _validate_tagged_bytes(value: Type0007TaggedBytes):
    # 0x64e50 -> 0xbc7e0 -> 0xaa680. Empty text bypasses tag validation.
    if not 0 <= value.tag <= 255 or len(value.data) > 61:
        raise ValueError('tagged byte-string bound exceeded')
    if not value.data:
        return
    kind = value.tag & 15
    if kind >= 6:
        raise ValueError('invalid nonempty tagged byte-string kind')
    if kind == 2:
        valid = all(97 <= b <= 122 or 48 <= b <= 57 or b == 45 for b in value.data)
    elif kind == 3:
        valid = all(48 <= b <= 57 for b in value.data)
    elif kind == 4:
        valid = 3 <= len(value.data) <= 16 and all(
            65 <= b <= 90 or 97 <= b <= 122 or 48 <= b <= 57 or b in (45, 95)
            for b in value.data)
    else:
        # Client uses a signed-byte comparison against 0x20.
        valid = all(32 <= b < 128 for b in value.data)
    if not valid:
        raise ValueError('invalid tagged byte-string characters')


def _counted(c: Cursor, read):
    count = c.read_svarint32()
    if count < 0 or count > 65536 or count > c.remaining:
        raise DecodeError('world collection bound exceeded')
    return tuple(read() for _ in range(count))


def _valid_world_float(value: WireFloat32) -> bool:
    # Exact 0x1d4b0 predicate, called by 0x223d5f0: not just isfinite.
    magnitude = value.bits & 0x7fffffff
    return not (1 <= magnitude <= 0x7fffff or magnitude >= 0x7f000000)


def _read_world_float(c: Cursor) -> WireFloat32:
    value = c.read_float32()
    if not _valid_world_float(value):
        raise DecodeError('client-rejected world float')
    return value


def _decode_core_tail(c: Cursor, t: ReferenceTable | None) -> Type0007CoreTail:
    # 0x1161366..0x11625df. Size helper 0x12ae0 returns constant 16;
    # 0x129d0 returns the destination pointer, and 0x223d5d0 reads raw bytes.
    fixed = c.read(16)
    tag, length = c.read_u8_varint(), c.read_u8_varint()
    if length > 61:
        raise DecodeError('tagged byte-string bound exceeded')
    tagged = Type0007TaggedBytes(tag, c.read(length))
    try:
        _validate_tagged_bytes(tagged)
    except ValueError as error:
        raise DecodeError(str(error)) from error
    def ref():
        return decode_reference(c, t)
    readers = {
        'reference': ref, 'float': lambda: _read_world_float(c),
        'reference_bool3': lambda: (ref(), c.read_bool(), c.read_bool(), c.read_bool()),
        'reference_pair': lambda: (ref(), ref()),
        'reference_signed': lambda: (ref(), c.read_svarint32()),
        'reference_signed_bool': lambda: (ref(), c.read_svarint32(), c.read_bool()),
        'reference_byte': lambda: (ref(), c.read_u8_varint()),
        # Client uses 0x223ce30 with maximum 0xfffd and checks length+1.
        'bytes': lambda: c.read_length_prefixed_bytes(maximum_length=65532),
    }
    collections = tuple(Type0007Collection(offset, _counted(c, readers[kind]))
        for offset, kind in CORE_TAIL_COLLECTIONS)
    return Type0007CoreTail(fixed, tagged, collections,
        tuple(c.read_bool() for _ in range(6)), c.read_svarint64(),
        (_read_world_float(c), _read_world_float(c)),
        (c.read_svarint32(), c.read_svarint32()), c.read_svarint64(),
        (ref(), ref()), (c.read_svarint32(), c.read_svarint32()),
        c.read_uvarint(maximum_bits=32), tuple(c.read_bool() for _ in range(5)),
        _counted(c, readers['bytes']), _counted(c, readers['bytes']),
        (c.read_uvarint(maximum_bits=32), c.read_uvarint(maximum_bits=32)),
        c.read_svarint32(), c.read_svarint64(), (c.read_bool(), c.read_bool()),
        _read_world_float(c))


def encode_type0007_core_tail(value: Type0007CoreTail, table: ReferenceTable | None) -> bytes:
    """Encode this recovered component only, NOT a complete world message."""
    _validate_tagged_bytes(value.tagged_bytes_500)
    if len(value.fixed_bytes_4f0) != 16:
        raise ValueError('fixed block requires 16 bytes')
    if tuple(row.parent_offset for row in value.collections) != tuple(
            offset for offset, _ in CORE_TAIL_COLLECTIONS):
        raise ValueError('core collections must match the recovered layout')
    for seq, size in (
        (value.flags_69d_69e_69f_6a3_6a4_6a5, 6), (value.floats_6b0_6b4, 2),
        (value.signed_6b8_6bc, 2), (value.references_670_680, 2),
        (value.signed_690_694, 2), (value.flags_69c_6a0_6a1_6a2_6c8, 5),
        (value.unsigned_6f0_6f4, 2), (value.flags_708_709, 2),
    ):
        if len(seq) != size:
            raise ValueError('incorrect fixed field count in core tail')
    t = _working(table)
    def ref(r):
        return encode_reference(r, t)
    def floating(f):
        if not _valid_world_float(f):
            raise ValueError('client-rejected world float')
        return f.encode()
    def bounded_bytes(b):
        if len(b) > 65532:
            raise ValueError('world byte-string bound exceeded')
        return encode_length_prefixed_bytes(b)
    def record(row, parts):
        if len(row) != len(parts):
            raise ValueError('incorrect world row field count')
        return b''.join(encode(part) for encode, part in zip(parts, row))
    encoders = {
        'reference': ref, 'float': floating,
        'reference_bool3': lambda r: record(r, (ref, encode_bool, encode_bool, encode_bool)),
        'reference_pair': lambda r: record(r, (ref, ref)),
        'reference_signed': lambda r: record(r, (ref, encode_svarint32)),
        'reference_signed_bool': lambda r: record(r, (ref, encode_svarint32, encode_bool)),
        'reference_byte': lambda r: record(r, (ref, encode_u8_varint)),
        'bytes': bounded_bytes,
    }
    def counted(rows, encode):
        if len(rows) > 65536:
            raise ValueError('world collection bound exceeded')
        return encode_svarint32(len(rows)) + b''.join(encode(row) for row in rows)
    def signed(seq):
        return b''.join(encode_svarint32(v) for v in seq)
    def unsigned(seq):
        return b''.join(encode_uvarint(v, maximum_bits=32) for v in seq)
    def flags(seq):
        return b''.join(encode_bool(v) for v in seq)
    body = (value.fixed_bytes_4f0 + encode_u8_varint(value.tagged_bytes_500.tag)
        + encode_u8_varint(len(value.tagged_bytes_500.data)) + value.tagged_bytes_500.data
        + b''.join(counted(col.rows, encoders[kind])
            for col, (_, kind) in zip(value.collections, CORE_TAIL_COLLECTIONS))
        + flags(value.flags_69d_69e_69f_6a3_6a4_6a5) + encode_svarint64(value.signed64_6a8)
        + b''.join(floating(f) for f in value.floats_6b0_6b4) + signed(value.signed_6b8_6bc)
        + encode_svarint64(value.signed64_6c0)
        + b''.join(ref(r) for r in value.references_670_680) + signed(value.signed_690_694)
        + unsigned((value.unsigned_698,)) + flags(value.flags_69c_6a0_6a1_6a2_6c8)
        + counted(value.byte_strings_6d0, bounded_bytes) + counted(value.byte_strings_6e0, bounded_bytes)
        + unsigned(value.unsigned_6f0_6f4) + encode_svarint32(value.signed_6f8)
        + encode_svarint64(value.signed64_700) + flags(value.flags_708_709)
        + floating(value.float_70c))
    if table is not None:
        table.entries[:] = t.entries
    return body


@dataclass(frozen=True)
class Type0007Prefix:
    reference_20: CompactReference
    unsigned_30: int
    signed_34: int
    signed_38: int
    signed_arrays_3c_64_8c: tuple[tuple[int, ...], ...]
    fixed_rows_b4: tuple[Type0007FixedRow, ...]
    signed_288: int
    signed_28c: int
    vector_290: tuple[WireFloat32, WireFloat32, WireFloat32]
    float_29c: WireFloat32
    reference_2a0: CompactReference
    bytes_2b0: bytes
    signed_3b0: int
    bytes_3b8: bytes
    reference_4b8: CompactReference
    flag_4c8: bool
    collection_count_4d0: int
    items_4d0: tuple[Type0088Item, ...]
    reference_4e0: CompactReference
    core_tail: Type0007CoreTail
    core_tail_start: int
    core_tail_round_trip: bool
    consumed_bytes: int
    remaining_bytes: int


def decode_type0007_prefix(body: bytes, table: ReferenceTable | None) -> Type0007Prefix:
    # RVA 0xeb63d0 -> 0x1161090. Nested 0xebca80 reads nine fixed
    # rows (6 sint32, 6 float32, 2 bool each), then the shared item
    # structure at 0xc47de0 and the rest of core 0x1161090. Stop before
    # top-level nested object +0x710 (reader 0xc49ba0), not at a guessed tail.
    # Do not commit table mutations from an incompletely understood message.
    c, t = Cursor(body), _working(table)
    reference = decode_reference(c, t)
    unsigned, signed = c.read_uvarint(maximum_bits=32), c.read_svarint32()
    encoded = c.read_u8_varint()
    signed8 = (encoded >> 1) ^ -(encoded & 1)
    arrays = tuple(tuple(c.read_svarint32() for _ in range(10)) for _ in range(3))
    rows = tuple(Type0007FixedRow(tuple(c.read_svarint32() for _ in range(6)),
        tuple(c.read_float32() for _ in range(6)), (c.read_bool(), c.read_bool()))
        for _ in range(9))
    signed_288, signed_28c = c.read_svarint32(), c.read_svarint32()
    vector, float_29c = c.read_vec3f(), c.read_float32()
    ref_2a0 = decode_reference(c, t)
    bytes_2b0 = c.read_length_prefixed_bytes(maximum_length=255)
    signed_3b0 = c.read_svarint32()
    bytes_3b8 = c.read_length_prefixed_bytes(maximum_length=255)
    ref_4b8, flag = decode_reference(c, t), c.read_bool()
    count = c.read_svarint32()
    if count < 0 or count > 65536:
        raise DecodeError("type 0x0007 collection bound exceeded")
    items = tuple(decode_equipment_item(c, t) for _ in range(count))
    ref_4e0 = decode_reference(c, t)
    tail_start = c.offset
    tail_before = _working(t)
    tail = _decode_core_tail(c, t)
    tail_wire = encode_type0007_core_tail(tail, tail_before)
    tail_exact = (tail_wire == body[tail_start:c.offset] and
        (t is None or tail_before.entries == t.entries))
    return Type0007Prefix(reference, unsigned, signed, signed8, arrays, rows,
        signed_288, signed_28c, vector, float_29c, ref_2a0, bytes_2b0,
        signed_3b0, bytes_3b8, ref_4b8, flag, count, items, ref_4e0, tail, tail_start, tail_exact,
        c.offset, c.remaining)


@dataclass(frozen=True)
class Type0157MixedRow:
    reference_0: CompactReference
    reference_1: CompactReference
    flag_38: bool
    signed_3c_24_28_20_30_2c: tuple[int, ...]
    byte_40: int
    byte_41: int
    flag_39: bool


@dataclass(frozen=True)
class Type0157NestedRow:
    unsigned_0: int
    unsigned16_4: int
    signed_values: tuple[int, ...]


@dataclass(frozen=True)
class Type0157:
    reference_20: CompactReference
    byte_30: int
    reference_38: CompactReference
    byte_signed_rows_48: tuple[tuple[int, int], ...]
    reference_signed_rows_58: tuple[tuple[CompactReference, int], ...]
    references_e8: tuple[CompactReference, ...]
    signed_values_110: tuple[int, ...]
    references_128: tuple[CompactReference, ...]
    references_150: tuple[CompactReference, ...]
    reference_signed_rows_178: tuple[tuple[CompactReference, int], ...]
    references_1a8: tuple[CompactReference, ...]
    references_1d0: tuple[CompactReference, ...]
    references_1f8: tuple[CompactReference, ...]
    references_220: tuple[CompactReference, ...]
    references_248: tuple[CompactReference, ...]
    mixed_rows_270: tuple[Type0157MixedRow, ...]
    nested_rows_318: tuple[Type0157NestedRow, ...]


def decode_type0157(body: bytes, table: ReferenceTable | None) -> Type0157:
    # Full reader 0xc4a690..0xc4b4f7, all collection lengths uint8-varint.
    c, t = Cursor(body), _working(table)
    def ref():
        return decode_reference(c, t)
    def rows(read):
        return tuple(read() for _ in range(c.read_u8_varint()))
    def mixed():
        return Type0157MixedRow(ref(), ref(), c.read_bool(),
            tuple(c.read_svarint32() for _ in range(6)), c.read_u8_varint(),
            c.read_u8_varint(), c.read_bool())
    def nested():
        return Type0157NestedRow(c.read_uvarint(maximum_bits=32),
            c.read_uvarint(maximum_bits=16), rows(c.read_svarint32))
    value = Type0157(ref(), c.read_u8_varint(), ref(),
        rows(lambda: (c.read_u8_varint(), c.read_svarint32())),
        rows(lambda: (ref(), c.read_svarint32())), rows(ref), rows(c.read_svarint32),
        rows(ref), rows(ref), rows(lambda: (ref(), c.read_svarint32())),
        rows(ref), rows(ref), rows(ref), rows(ref), rows(ref), rows(mixed), rows(nested))
    _finish(c, table, t)
    return value


def encode_type0157(value: Type0157, table: ReferenceTable | None) -> bytes:
    t = _working(table)
    def ref(r):
        return encode_reference(r, t)
    def rows(values, encode):
        return encode_u8_varint(len(values)) + b"".join(encode(row) for row in values)
    def mixed(row):
        if len(row.signed_3c_24_28_20_30_2c) != 6:
            raise ValueError("mixed row requires six signed values")
        return (ref(row.reference_0) + ref(row.reference_1) + encode_bool(row.flag_38)
            + b"".join(encode_svarint32(v) for v in row.signed_3c_24_28_20_30_2c)
            + encode_u8_varint(row.byte_40) + encode_u8_varint(row.byte_41)
            + encode_bool(row.flag_39))
    def nested(row):
        return (encode_uvarint(row.unsigned_0, maximum_bits=32)
            + encode_uvarint(row.unsigned16_4, maximum_bits=16)
            + rows(row.signed_values, encode_svarint32))
    def ref_signed(row):
        return ref(row[0]) + encode_svarint32(row[1])
    body = (ref(value.reference_20) + encode_u8_varint(value.byte_30) + ref(value.reference_38)
        + rows(value.byte_signed_rows_48, lambda row: encode_u8_varint(row[0]) + encode_svarint32(row[1]))
        + rows(value.reference_signed_rows_58, ref_signed)
        + rows(value.references_e8, ref) + rows(value.signed_values_110, encode_svarint32)
        + rows(value.references_128, ref) + rows(value.references_150, ref)
        + rows(value.reference_signed_rows_178, ref_signed)
        + rows(value.references_1a8, ref) + rows(value.references_1d0, ref)
        + rows(value.references_1f8, ref) + rows(value.references_220, ref)
        + rows(value.references_248, ref) + rows(value.mixed_rows_270, mixed)
        + rows(value.nested_rows_318, nested))
    if table is not None:
        table.entries[:] = t.entries
    return body


@dataclass(frozen=True)
class Type0167:
    reference_20: CompactReference


def decode_type0167(body: bytes, table: ReferenceTable | None) -> Type0167:
    c, t = Cursor(body), _working(table)
    value = Type0167(decode_reference(c, t))
    _finish(c, table, t)
    return value


def encode_type0167(value: Type0167, table: ReferenceTable | None) -> bytes:
    return encode_reference(value.reference_20, table)


@dataclass(frozen=True)
class Type00E8:
    flag_20: bool
    reference_28: CompactReference
    signed_38: int
    byte_3c: int
    flag_40: bool
    bytes_48: bytes
    byte_58: int


def decode_type00e8(body: bytes, table: ReferenceTable | None) -> Type00E8:
    c, t = Cursor(body), _working(table)
    value = Type00E8(c.read_bool(), decode_reference(c, t), c.read_svarint32(),
        c.read_u8_varint(), c.read_bool(),
        c.read_length_prefixed_bytes(maximum_length=65532), c.read_u8_varint())
    _finish(c, table, t)
    return value


def encode_type00e8(value: Type00E8, table: ReferenceTable | None) -> bytes:
    if len(value.bytes_48) > 65532:
        raise ValueError("type 0x00e8 byte-string bound exceeded")
    t = _working(table)
    body = (encode_bool(value.flag_20) + encode_reference(value.reference_28, t)
        + encode_svarint32(value.signed_38) + encode_u8_varint(value.byte_3c)
        + encode_bool(value.flag_40) + encode_uvarint(len(value.bytes_48), maximum_bits=32)
        + value.bytes_48 + encode_u8_varint(value.byte_58))
    if table is not None:
        table.entries[:] = t.entries
    return body
