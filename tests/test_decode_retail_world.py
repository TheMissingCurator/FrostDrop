"""Redacted offline world analysis; fixtures are synthetic, not retail bytes."""
from pathlib import Path
import json
import runpy
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
analyze = runpy.run_path(str(ROOT / 'tools/decode-retail-world.py'))['analyze']
fixtures = runpy.run_path(str(ROOT / 'tests/test_world_message_codecs.py'))
from isac_protocol.codec import CompactReference, ReferenceTable
from isac_protocol.framing import MessageFrame, encode_length_prefixed_frame
from isac_protocol.world_messages import Type014D, encode_type014d


class RedactedWorldAnalysisTests(unittest.TestCase):
    def fixture(self, directory, *, request_twice=False, partial=False, full_world=False):
        path = Path(directory) / 'tutorial-1.bin'
        table = ReferenceTable()
        ref = bytes(range(16))
        seed = encode_type014d(Type014D((CompactReference(ref),)), table)
        connect = b'PRIVATE-CONNECT!' + b'\x00'
        world = fixtures['prefix_fixture'](table,
            tail=b'\x00\x00\x00\x00\x01\x00' if full_world else b'unknown-tail')
        wire = b''.join(encode_length_prefixed_frame(frame) for frame in (
            MessageFrame(2, connect), MessageFrame(0x014d, seed),
            MessageFrame(7, world), MessageFrame(0xffff, b'PRIVATE-UNKNOWN')))
        events = [(5, b'', 740), (4, ref, 0), (3, connect, 0),
            (1, wire[:5], 1), (1, wire[5:], 0)]
        if request_twice:
            events.append((5, b'', 740))
        if partial:
            events.append((1, b'\x80', 0))
        capture = struct.pack('<8sII', b'ISACTUT1', 1, 16)
        for sequence, (kind, payload, aux) in enumerate(events, 1):
            capture += struct.pack('<QQIIII', sequence, sequence * 100,
                kind, 13, len(payload), aux) + payload
        path.write_bytes(capture)
        path.with_suffix('.jsonl').write_text('\n'.join(json.dumps(row) for row in (
            {'event': 'marker', 'key': 1, 'tick_ms': 450},
            {'event': 'marker', 'key': 1, 'tick_ms': 490},
            {'event': 'end', 'resume_failures': 0})))
        return path

    def test_summary_is_redacted_and_marks_partial_not_full_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(self.fixture(directory))
        summary = json.dumps(result)
        self.assertNotIn('PRIVATE', summary)
        self.assertNotIn(bytes(range(16)).hex(), summary)
        self.assertTrue(result['connect_reply_correlated'])
        self.assertEqual(result['inbound_frames'], 4)
        self.assertEqual(result['dictionary_entries'], 1)
        self.assertEqual(result['marker_counts'], {1: 2})
        self.assertEqual(result['skipped_full_decode_types']['0x0007'], 1)
        prefix = result['type0007_prefixes_only'][0]
        self.assertEqual(prefix['fixed_block_width'], 16)
        self.assertTrue(prefix['core_tail_byte_identical_round_trip'])
        self.assertEqual(prefix['remaining_bytes'], len(b'unknown-tail'))

    def test_second_actual_world_request_is_rejected_not_duplicate_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'multiple world requests'):
                analyze(self.fixture(directory, request_twice=True))

    def test_extended_numpad_markers_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(directory)
            metadata = path.with_suffix('.jsonl')
            rows = [json.loads(line) for line in metadata.read_text().splitlines()]
            rows.insert(2, {'event': 'marker', 'key': 0, 'tick_ms': 520})
            rows.insert(3, {'event': 'marker', 'key': 10, 'tick_ms': 540})
            metadata.write_text('\n'.join(json.dumps(row) for row in rows))
            self.assertEqual(analyze(path)['marker_counts'], {0: 1, 1: 2, 10: 1})

    def test_complete_supported_shape_is_distinct_from_partial_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(self.fixture(directory, full_world=True))
        self.assertNotIn('0x0007', result['skipped_full_decode_types'])
        self.assertNotIn('0x0007', result['unsupported_or_failed_bodies'])
        self.assertEqual(result['byte_identical_round_trips']['0x0007'], 1)
        full = result['type0007_complete_observed_shape'][0]
        self.assertEqual(full['remaining_bytes'], 0)
        self.assertTrue(full['fixed_block_matches_created_character'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_incomplete_wire_tail_is_not_claimed_gap_free(self):
        with tempfile.TemporaryDirectory() as directory:
            result = analyze(self.fixture(directory, partial=True))
        self.assertGreater(result['pending_bytes'], 0)
        self.assertIn('incomplete frame tail', result['notes'])


if __name__ == '__main__':
    unittest.main()
