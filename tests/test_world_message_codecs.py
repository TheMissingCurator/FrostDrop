"""Structural world codecs: synthetic fixtures contain no retail identifiers."""
from dataclasses import replace
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_protocol.codec import (
    CompactReference, Cursor, DecodeError, ReferenceTable, WireFloat32,
    encode_reference, encode_svarint32, encode_uvarint,
)
from isac_protocol.framing import encode_length_prefixed_frame
from isac_protocol.registry import (
    SERVER_TO_CLIENT, MessageReplayDecoder, build_default_registry,
)
from isac_protocol.type0088 import decode_equipment_item, encode_equipment_item
from isac_protocol.world_messages import (
    MAX_DICTIONARY_ROWS, Type014D, Type0157, Type0157MixedRow,
    Type0157NestedRow, Type0167, Type00E8, decode_type0007_prefix,
    decode_type014d, encode_type014d, decode_type0157, encode_type0157,
    decode_type0167, encode_type0167, decode_type00e8, encode_type00e8,
    CORE_TAIL_COLLECTIONS, Type0007Collection, Type0007TaggedBytes,
    Type0007CoreTail, _decode_core_tail, encode_type0007_core_tail,
)


def reward_fixture():
    ref = CompactReference(bytes(range(16)))
    return Type0157(ref, 255, ref, ((255, -1500),), ((ref, 35),),
        (ref,), (-1, 0, 2147483647, -2147483648), (ref,), (ref,),
        ((ref, -2),), (ref,), (ref,), (ref,), (ref,), (ref,),
        (Type0157MixedRow(ref, ref, True, (-3, 4, -5, 6, -7, 8), 128, 255, False),),
        (Type0157NestedRow(0xffffffff, 0xffff, (-2147483648, 2147483647)),))


def core_tail_fixture(ref):
    f = WireFloat32.from_float(0.5)
    rows = {
        'reference': (ref,), 'float': (f, WireFloat32(0x80000000)),
        'reference_bool3': ((ref, True, False, True),),
        'reference_pair': ((ref, ref),), 'reference_signed': ((ref, -123),),
        'reference_signed_bool': ((ref, -2, True),),
        'reference_byte': ((ref, 255),), 'bytes': (b'private-text', b''),
    }
    return Type0007CoreTail(bytes(range(16)), Type0007TaggedBytes(2, b'abc-012'),
        tuple(Type0007Collection(offset, rows[kind]) for offset, kind in CORE_TAIL_COLLECTIONS),
        (True, False, True, False, True, False), -(1 << 60), (f, f), (-1, 2),
        1 << 60, (ref, ref), (-3, 4), 0xffffffff,
        (True, False, True, False, True), (b'private-a',), (b'private-b',),
        (0xffffffff, 0), -2147483648, -(1 << 63), (False, True), f)


def prefix_fixture(table=None, count=0, items=(), tail=b'unknown-tail'):
    """Only a recovered prefix, with an intentionally opaque suffix."""
    ref = (CompactReference(None, token=0) if table is not None and table.assume_existing
        else CompactReference(bytes(range(16))))
    reference = lambda: encode_reference(ref, table)
    body = reference() + encode_uvarint(123) + encode_svarint32(-12) + b'\x01'
    body += b''.join(encode_svarint32(i) for i in range(-15, 15))
    for i in range(9):
        body += b''.join(encode_svarint32(j) for j in range(-3, 3))
        body += b''.join(WireFloat32.from_float(j / 2).encode() for j in range(6))
        body += b'\x01\x00'
    body += encode_svarint32(-1) + encode_svarint32(2)
    body += b''.join(WireFloat32.from_float(i).encode() for i in range(4))
    body += reference() + b'\x03abc' + encode_svarint32(-5) + b'\x03def'
    body += reference() + b'\x01' + encode_svarint32(count)
    for item in items:
        body += encode_equipment_item(item, table)
    if count >= 0:
        body += reference()
        body += encode_type0007_core_tail(core_tail_fixture(ref), table)
    return body + tail


class WorldCodecTests(unittest.TestCase):
    def test_dictionary_seed_then_resolve_in_fragmented_session(self):
        refs = tuple(CompactReference(bytes([i]) * 16) for i in range(3))
        registry, table = build_default_registry(), ReferenceTable()
        frames = [registry.encode(SERVER_TO_CLIENT, 0x014d, Type014D(refs), table),
            registry.encode(SERVER_TO_CLIENT, 0x0167, Type0167(refs[2]), table)]
        replay, result = MessageReplayDecoder(), []
        for byte in b''.join(encode_length_prefixed_frame(frame) for frame in frames):
            result.extend(replay.feed(bytes([byte])))
        self.assertEqual([r.value for r in result[0].value.references], [r.value for r in refs])
        self.assertEqual(result[1].value.reference_20.value, refs[2].value)
        self.assertEqual(replay.framer.buffered_bytes, 0)

    def test_dictionary_empty_raw_and_midstream(self):
        self.assertEqual(decode_type014d(b'\x00', ReferenceTable()), Type014D(()))
        value = Type014D((CompactReference(bytes(range(16))),))
        self.assertEqual(decode_type014d(encode_type014d(value, None), None), value)
        wire = b'\x02\x04\x07' + bytes(range(16))
        table = ReferenceTable(assume_existing=True)
        decoded = decode_type014d(wire, table)
        self.assertEqual(encode_type014d(decoded, table), wire)
        self.assertIsNone(decoded.references[0].value)

    def test_dictionary_odd_existing_reference_resolves_not_side_value(self):
        original, side = bytes(range(16)), bytes(reversed(range(16)))
        table = ReferenceTable([original])
        wire = b'\x01\x01' + side
        value = decode_type014d(wire, table)
        self.assertEqual(value.references[0].value, original)
        self.assertEqual(value.references[0].side_value, side)
        self.assertEqual(encode_type014d(value, table), wire)
        self.assertEqual(table.entries, [original])

    def test_dictionary_invalid_count_and_atomic_failure(self):
        for wire in (encode_uvarint(MAX_DICTIONARY_ROWS + 1), b'\x02\x00',
                     b'\x01\x00' + bytes(range(16)) + b'extra'):
            with self.subTest(length=len(wire)):
                table = ReferenceTable()
                with self.assertRaises(DecodeError):
                    decode_type014d(wire, table)
                self.assertEqual(table.entries, [])

    def test_reward_all_collections_round_trip_raw_and_stateful(self):
        original = reward_fixture()
        for initial in (None, ReferenceTable()):
            writer = initial.clone() if initial is not None else None
            reader = initial.clone() if initial is not None else None
            wire = encode_type0157(original, writer)
            decoded = decode_type0157(wire, reader)
            self.assertEqual(encode_type0157(decoded, initial), wire)
            self.assertEqual(decoded.mixed_rows_270[0].signed_3c_24_28_20_30_2c,
                original.mixed_rows_270[0].signed_3c_24_28_20_30_2c)
            self.assertEqual(decoded.nested_rows_318, original.nested_rows_318)
            if reader is not None:
                self.assertEqual(reader.entries, writer.entries)

    def test_reward_zero_collections(self):
        value = reward_fixture()
        empty = replace(value, **{name: () for name in value.__dataclass_fields__
            if name not in ('reference_20', 'byte_30', 'reference_38')})
        wire = encode_type0157(empty, None)
        self.assertEqual(decode_type0157(wire, None), empty)

    def test_reward_truncation_and_trailing_leave_table_unchanged(self):
        wire = encode_type0157(reward_fixture(), ReferenceTable())
        for broken in (wire[:-1], wire + b'extra'):
            table = ReferenceTable()
            with self.assertRaises(DecodeError):
                decode_type0157(broken, table)
            self.assertEqual(table.entries, [])

    def test_reward_encode_validation_and_atomic_failure(self):
        value = reward_fixture()
        for invalid in (
            replace(value, references_e8=(value.reference_20,) * 256),
            replace(value, mixed_rows_270=(replace(value.mixed_rows_270[0],
                signed_3c_24_28_20_30_2c=(1,)),)),
            replace(value, nested_rows_318=(Type0157NestedRow(1, 65536, ()),)),
        ):
            table = ReferenceTable()
            with self.assertRaises(ValueError):
                encode_type0157(invalid, table)
            self.assertEqual(table.entries, [])

    def test_small_messages_raw_and_stateful_round_trip(self):
        ref = CompactReference(bytes(range(16)))
        for value, encode, decode in (
            (Type0167(ref), encode_type0167, decode_type0167),
            (Type00E8(True, ref, -2147483648, 255, False, b'private-name', 128),
                encode_type00e8, decode_type00e8),
        ):
            for table in (None, ReferenceTable()):
                before = table.clone() if table is not None else None
                wire = encode(value, table)
                decoded = decode(wire, before)
                self.assertEqual(decoded.reference_20.value if isinstance(decoded, Type0167)
                    else decoded.reference_28.value, ref.value)
                self.assertEqual(encode(decoded, ReferenceTable() if table is not None else None), wire)

    def test_small_message_decode_atomicity(self):
        ref = CompactReference(bytes(range(16)))
        for value, encode, decode in (
            (Type0167(ref), encode_type0167, decode_type0167),
            (Type00E8(True, ref, -1, 2, False, b'x', 3), encode_type00e8, decode_type00e8),
        ):
            wire = encode(value, ReferenceTable())
            table = ReferenceTable()
            with self.assertRaises(DecodeError):
                decode(wire + b'extra', table)
            self.assertEqual(table.entries, [])

    def test_e8_string_boundaries(self):
        value = Type00E8(False, CompactReference(bytes(16)), 0, 0, True, b'x' * 65532, 0)
        self.assertEqual(decode_type00e8(encode_type00e8(value, None), None), value)
        with self.assertRaises(ValueError):
            encode_type00e8(replace(value, bytes_48=value.bytes_48 + b'x'), None)
        with self.assertRaises(DecodeError):
            decode_type00e8(b'\x00' + bytes(16) + b'\x00\x00\x01'
                + encode_uvarint(65533) + b'x' * 65533 + b'\x00', None)

    def test_prefix_is_partial_and_does_not_commit_dictionary(self):
        wire = prefix_fixture(ReferenceTable())
        table = ReferenceTable()
        value = decode_type0007_prefix(wire, table)
        self.assertEqual(table.entries, [])
        self.assertEqual(value.remaining_bytes, len(b'unknown-tail'))
        self.assertEqual(value.consumed_bytes + value.remaining_bytes, len(wire))
        self.assertEqual(value.signed_38, -1)
        self.assertEqual(len(value.fixed_rows_b4), 9)
        self.assertEqual(tuple(map(len, value.signed_arrays_3c_64_8c)), (10, 10, 10))
        self.assertEqual(value.bytes_2b0, b'abc')
        self.assertTrue(value.core_tail_round_trip)
        self.assertNotIn(7, build_default_registry().type_ids(SERVER_TO_CLIENT))

    def test_prefix_negative_collection_and_truncation(self):
        with self.assertRaises(DecodeError):
            decode_type0007_prefix(prefix_fixture(count=-1), None)
        with self.assertRaises(DecodeError):
            decode_type0007_prefix(prefix_fixture()[:20], None)

    def test_shared_equipment_reader_accepts_embedded_items_without_wrapper(self):
        item = runpy.run_path(str(ROOT / 'tests/test_type0088_codec.py'))['message']().item
        table = ReferenceTable(assume_existing=True)
        wire = encode_equipment_item(item, table)
        c = Cursor(wire + b'tail')
        self.assertEqual(decode_equipment_item(c, table), item)
        self.assertEqual(c.remaining, 4)
        # Same component can now be read inside the world startup prefix.
        prefix = decode_type0007_prefix(prefix_fixture(table, 2, (item, item)),
            ReferenceTable(assume_existing=True))
        self.assertEqual(prefix.items_4d0, (item, item))
        self.assertEqual(prefix.remaining_bytes, len(b'unknown-tail'))

    def test_core_tail_all_collections_round_trip_and_leave_suffix(self):
        value = core_tail_fixture(CompactReference(bytes(range(16))))
        for initial in (None, ReferenceTable()):
            before = initial.clone() if initial is not None else None
            writer = initial.clone() if initial is not None else None
            wire = encode_type0007_core_tail(value, writer)
            c = Cursor(wire + b'top-level-suffix')
            decoded = _decode_core_tail(c, initial)
            self.assertEqual(c.remaining, len(b'top-level-suffix'))
            self.assertEqual(encode_type0007_core_tail(decoded, before), wire)
            if initial is not None:
                self.assertEqual(initial.entries, writer.entries)
            self.assertEqual(decoded.signed64_700, -(1 << 63))

    def test_core_tail_fixed_width_and_rejects_guessed_lengths(self):
        value = core_tail_fixture(CompactReference(bytes(range(16))))
        wire = encode_type0007_core_tail(value, None)
        for broken in (wire[:15], wire[:16] + b'\x02\x3e' + b'x' * 62,
                       wire[:-1], wire[:16] + b'\x02\x01!' + wire[25:]):
            with self.assertRaises(DecodeError):
                _decode_core_tail(Cursor(broken), None)
        with self.assertRaises(ValueError):
            encode_type0007_core_tail(replace(value, fixed_bytes_4f0=bytes(15)), None)

    def test_core_tail_tag_validation_matches_client_branches(self):
        value = core_tail_fixture(CompactReference(bytes(range(16))))
        for tag, text in ((255, b''), (0, b'Printable text'), (1, b'!'),
                          (2, b'abc-123'), (3, b'123'), (4, b'A_b-1'), (5, b' ')):
            message = replace(value, tagged_bytes_500=Type0007TaggedBytes(tag, text))
            wire = encode_type0007_core_tail(message, None)
            self.assertEqual(_decode_core_tail(Cursor(wire), None), message)
        for tag, text in ((6, b'x'), (2, b'UPPER'), (3, b'a'),
                          (4, b'ab'), (4, b'a' * 17), (0, b'\x80')):
            with self.assertRaises(ValueError):
                encode_type0007_core_tail(replace(value,
                    tagged_bytes_500=Type0007TaggedBytes(tag, text)), None)

    def test_core_tail_float_guard_is_stricter_than_finite(self):
        value = core_tail_fixture(CompactReference(bytes(range(16))))
        for bits in (1, 0x7fffff, 0x7f000000, 0x7f800000, 0x7fc00000):
            table = ReferenceTable()
            with self.assertRaises(ValueError):
                encode_type0007_core_tail(replace(value, float_70c=WireFloat32(bits)), table)
            self.assertEqual(table.entries, [])
            wire = encode_type0007_core_tail(value, None)
            with self.assertRaises(DecodeError):
                _decode_core_tail(Cursor(wire[:-4] + WireFloat32(bits).encode()), None)
        for bits in (0, 0x80000000, 0x800000, 0x7effffff):
            message = replace(value, float_70c=WireFloat32(bits))
            self.assertEqual(_decode_core_tail(Cursor(
                encode_type0007_core_tail(message, None)), None), message)

    def test_core_tail_counts_order_and_atomic_encoding(self):
        value = core_tail_fixture(CompactReference(bytes(range(16))))
        for invalid in (replace(value, collections=value.collections[::-1]),
                        replace(value, flags_708_709=(True,)),
                        replace(value, byte_strings_6e0=(b'x' * 65533,))):
            table = ReferenceTable()
            with self.assertRaises(ValueError):
                encode_type0007_core_tail(invalid, table)
            self.assertEqual(table.entries, [])
        wire = encode_type0007_core_tail(value, None)
        start = 16 + 2 + len(value.tagged_bytes_500.data)
        for invalid_count in (-1, 65537):
            with self.assertRaises(DecodeError):
                _decode_core_tail(Cursor(wire[:start] + encode_svarint32(invalid_count)
                    + wire[start+1:]), None)

    def test_private_tutorial_core_tail_regression_if_available(self):
        path = ROOT / ('evidence/20260927-064853-retail-tutorial-x3s3v01n/'
            'tutorial-private/tutorial-1200.bin')
        if not path.exists():
            self.skipTest('private tutorial capture unavailable')
        from isac_protocol.framing import InboundFrameStreamDecoder
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        table, stream = ReferenceTable(), InboundFrameStreamDecoder()
        for tick, kind, source, aux, payload in records(path):
            if kind != 1:
                continue
            for frame in stream.feed(payload):
                if frame.type_id == 0x014d:
                    decode_type014d(frame.body, table)
                if frame.type_id != 7:
                    continue
                value = decode_type0007_prefix(frame.body, table)
                self.assertEqual((value.core_tail_start, value.consumed_bytes,
                    value.remaining_bytes), (5920, 8304, 146))
                self.assertEqual(encode_type0007_core_tail(value.core_tail, table.clone()),
                    frame.body[value.core_tail_start:value.consumed_bytes])
                self.assertEqual(len(value.items_4d0), 199)
                self.assertEqual(len(value.core_tail.tagged_bytes_500.data), 36)
                self.assertTrue(value.core_tail_round_trip)
                return
        self.fail('captured world startup absent')

    def test_private_static_size_and_pointer_helpers_if_available(self):
        path = ROOT / ('private/tctd-runtime-text-'
            'dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin')
        if not path.exists():
            self.skipTest('private analyzed text unavailable')
        signatures = {
            0x12ae0: bytes.fromhex('b8 10 00 00 00 c3'),
            0x129d0: bytes.fromhex('48 8b c1 c3'),
            0x116136d: bytes.fromhex('e8 6e 17 eb fe'),
            0x1161389: bytes.fromhex('e8 42 c2 0d 01'),
            0x64ec2: bytes.fromhex('3c 3d'),
        }
        with path.open('rb') as stream:
            for rva, code in signatures.items():
                stream.seek(rva - 0x1000)
                self.assertEqual(stream.read(len(code)), code, hex(rva))


if __name__ == '__main__':
    unittest.main()
