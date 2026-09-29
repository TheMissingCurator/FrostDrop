"""Complete observed-shape startup, without generated-world semantics."""
from dataclasses import replace
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
fixtures = runpy.run_path(str(ROOT / 'tests/test_world_message_codecs.py'))
from isac_protocol.codec import CompactReference, DecodeError, ReferenceTable, WireFloat32
from isac_protocol.framing import InboundFrameStreamDecoder
from isac_protocol.world_messages import decode_type0007_prefix, decode_type014d
from isac_protocol.world_start import (WorldStart, WorldStartChild, WorldStartGroup,
    decode_world_start, encode_world_start)


def startup_fixture():
    core = decode_type0007_prefix(fixtures['prefix_fixture'](tail=b''), None)
    ref = CompactReference(bytes(reversed(range(16))))
    f = WireFloat32.from_float(1.25)
    return WorldStart(core, ((255, f),), (WorldStartGroup(ref, (
        WorldStartChild(ref, 255, False, f), WorldStartChild(ref, 0, True, None))),),
        ((ref, f),), (-128, -1, 0, 127), -1, (ref,))


class WorldStartTests(unittest.TestCase):
    def test_all_supported_fields_round_trip_and_table_state(self):
        value = startup_fixture()
        for initial in (None, ReferenceTable()):
            writer = initial.clone() if initial is not None else None
            reader = initial.clone() if initial is not None else None
            wire = encode_world_start(value, writer)
            decoded = decode_world_start(wire, reader)
            self.assertEqual(encode_world_start(decoded, initial), wire)
            self.assertEqual(decoded.empty_group_signed_740, (-128, -1, 0, 127))
            self.assertEqual(decoded.groups_720[0].children[0].float_14.value, 1.25)
            self.assertIsNone(decoded.groups_720[0].children[1].float_14)
            if reader is not None:
                self.assertEqual(reader.entries, writer.entries)

    def test_empty_collections(self):
        value = replace(startup_fixture(), byte_float_rows_710=(), groups_720=(),
            reference_float_rows_730=(), empty_group_signed_740=(), references_758=())
        wire = encode_world_start(value, None)
        self.assertEqual(encode_world_start(decode_world_start(wire, None), None), wire)

    def test_nonempty_dynamic_subobjects_refused(self):
        value = replace(startup_fixture(), byte_float_rows_710=(), groups_720=(),
            reference_float_rows_730=(), empty_group_signed_740=(-1,), references_758=())
        wire = encode_world_start(value, ReferenceTable())
        offset = decode_type0007_prefix(wire, ReferenceTable()).consumed_bytes
        # Empty lists, one group, then replace its zero subobject count.
        broken = wire[:offset + 4] + b'\x01' + wire[offset + 5:]
        table = ReferenceTable()
        with self.assertRaisesRegex(DecodeError, 'nonempty dynamic'):
            decode_world_start(broken, table)
        self.assertEqual(table.entries, [])

    def test_decode_failure_never_commits_dictionary(self):
        wire = encode_world_start(startup_fixture(), ReferenceTable())
        for broken in (wire[:1], wire[:-1], wire + b'\x00'):
            table = ReferenceTable()
            with self.assertRaises(DecodeError):
                decode_world_start(broken, table)
            self.assertEqual(table.entries, [])

    def test_encode_validation_never_commits_dictionary(self):
        value = startup_fixture()
        invalid_child = replace(value.groups_720[0].children[0], flag_18=True)
        for invalid in (replace(value, signed_750=128),
            replace(value, empty_group_signed_740=(-129,)),
            replace(value, byte_float_rows_710=((1, WireFloat32(1)),)),
            replace(value, groups_720=(replace(value.groups_720[0], children=(invalid_child,)),)),
            replace(value, core=replace(value.core, vector_290=()))):
            table = ReferenceTable()
            with self.assertRaises(ValueError):
                encode_world_start(invalid, table)
            self.assertEqual(table.entries, [])

    def check_frames(self, payloads, size, created=None):
        table, stream = ReferenceTable(), InboundFrameStreamDecoder()
        for payload in payloads:
            for frame in stream.feed(payload):
                if frame.type_id == 0x014d:
                    decode_type014d(frame.body, table)
                if frame.type_id != 7:
                    continue
                before = table.clone()
                value = decode_world_start(frame.body, table)
                self.assertEqual(len(frame.body), size)
                self.assertEqual(encode_world_start(value, before), frame.body)
                self.assertEqual(before.entries, table.entries)
                self.assertEqual(value.empty_group_signed_740, (-1,) * 6)
                self.assertEqual(len(value.byte_float_rows_710), 24)
                if created is not None:
                    self.assertTrue(value.core.core_tail.fixed_bytes_4f0 == created)
                return
        self.fail('world start missing')

    def test_private_tutorial_round_trip_and_character_binding(self):
        path = ROOT / ('evidence/20260927-064853-retail-tutorial-x3s3v01n/'
            'tutorial-private/tutorial-1200.bin')
        if not path.exists():
            self.skipTest('private tutorial unavailable')
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        created = next(payload for _, kind, _, aux, payload in records(path) if kind == 4 and aux == 0)
        self.check_frames((payload for _, kind, _, _, payload in records(path) if kind == 1), 8450, created)

    def test_older_private_worlds_round_trip(self):
        decode = runpy.run_path(str(ROOT / 'tools/inspect-world-bootstrap.py'))['decode_capture']
        found = False
        for name, size in (('first-gate', 11179), ('hub-stable', 11666)):
            path = ROOT / f'private/world-bootstrap-{name}-20260925.bin'
            if not path.exists():
                continue
            found = True
            with self.subTest(capture=name):
                self.check_frames((span.data for span in decode(path.read_bytes())[2]), size)
        if not found:
            self.skipTest('older private worlds unavailable')


if __name__ == '__main__':
    unittest.main()
