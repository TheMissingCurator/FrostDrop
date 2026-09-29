"""Structural type-0x00e6 tests; private fixtures emit no identifiers."""

from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from isac_protocol.codec import CompactReference, DecodeError, ReferenceTable, WireFloat32
from isac_protocol.framing import InboundFrameStreamDecoder
from isac_protocol.registry import SERVER_TO_CLIENT, build_default_registry
from isac_protocol.type00e6 import (
    Type00E6, Type00E6Group, Type00E6Row, Type00E6SubRow,
    decode_type00e6, encode_type00e6,
)
from isac_protocol.world_messages import decode_type014d


def synthetic_message():
    refs = [CompactReference(bytes((i,)) * 16) for i in range(1, 8)]
    fl = lambda value: WireFloat32.from_float(value)
    vec = (fl(1.0), fl(2.0), fl(3.0))
    return Type00E6(
        refs[0], refs[1], (1, -2, 3), True, 0b1010, 7,
        (Type00E6Row(
            (4, -5, 6), (True, False), fl(4.0), True, fl(5.0),
            refs[2], (Type00E6SubRow(refs[3], vec, -9, False),), -1),),
        (123, 456), fl(6.0), vec, 20, (1, 2, 3, 4, 5), 21, 22, 23,
        ((refs[4], -10),),
        (Type00E6Group(refs[5], ((refs[6], 11),)),),
        True, 12, False, True, refs[0])


class Type00E6Tests(unittest.TestCase):
    def test_synthetic_nested_roundtrip_with_dictionary(self):
        value = synthetic_message()
        sender, receiver = ReferenceTable(), ReferenceTable()
        registry = build_default_registry()
        frame = registry.encode(SERVER_TO_CLIENT, 0x00e6, value, sender)
        decoded = registry.decode(SERVER_TO_CLIENT, frame, receiver).value
        self.assertEqual(decoded.signed_54_58_5c, value.signed_54_58_5c)
        self.assertEqual(decoded.rows_20[0].subrows[0].signed_0, -9)
        self.assertEqual(decoded.reference_0.value, value.reference_0.value)
        self.assertEqual(sender.entries, receiver.entries)
        self.assertEqual(len(sender.entries), 7)
        self.assertEqual(encode_type00e6(value, ReferenceTable()), frame.body)

    def test_synthetic_raw_references_and_atomic_failure(self):
        body = encode_type00e6(synthetic_message(), None)
        self.assertEqual(decode_type00e6(body, None), synthetic_message())
        for damaged in (body[:-1], body + b'\0', body[:35] + b'\x02' + body[36:]):
            with self.subTest(length=len(damaged)):
                with self.assertRaises(DecodeError):
                    decode_type00e6(damaged, None)
        table = ReferenceTable()
        compact = encode_type00e6(synthetic_message(), ReferenceTable())
        with self.assertRaises(DecodeError):
            decode_type00e6(compact[:-1], table)
        self.assertEqual(table.entries, [])

    def test_private_marked_capture_roundtrip_if_available(self):
        capture = ROOT / ('evidence/20260927-064853-retail-tutorial-x3s3v01n/'
                          'tutorial-private/tutorial-1200.bin')
        if not capture.exists():
            self.skipTest('private retail fixture unavailable')
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        framer, table = InboundFrameStreamDecoder(maximum_frame_length=16777216), ReferenceTable()
        found = []
        for tick, kind, source, aux, payload in records(capture):
            if kind != 1:
                continue
            for frame in framer.feed(payload):
                if frame.type_id == 0x014d:
                    decode_type014d(frame.body, table)
                elif frame.type_id == 0x00e6:
                    before = table.clone()
                    value = decode_type00e6(frame.body, table)
                    encoded_table = before.clone()
                    self.assertEqual(encode_type00e6(value, encoded_table), frame.body)
                    self.assertEqual(encoded_table.entries, table.entries)
                    found.append((value.reference_0.index,
                                  tuple(row.signed_0_2[2] for row in value.rows_20),
                                  tuple(len(row.subrows) for row in value.rows_20)))
        self.assertEqual(len(found), 38)
        self.assertIn((1001, (0, 4, 1, 0, 0), (0, 1, 1, 0, 0)), found)
        self.assertIn((1001, (0, 4, 4, 4, 4), (0, 1, 1, 0, 1)), found)
        self.assertIn((1081, (4, 4, 4, 1), (1, 1, 1, 1)), found)
        self.assertIn((1814, (4, 4, 4, 4, 4, 4, 4, 4, 1),
                       (1, 1, 1, 2, 2, 1, 3, 2, 1)), found)
        self.assertEqual(framer.buffered_bytes, 0)


if __name__ == '__main__':
    unittest.main()
