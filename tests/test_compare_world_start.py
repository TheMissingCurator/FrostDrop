"""Redacted cross-session startup comparison; no captured defaults."""
from dataclasses import replace
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[1]
tool = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))
fixture = runpy.run_path(str(ROOT / 'tests/test_world_start.py'))['startup_fixture']
CompactReference = tool['CompactReference']
Snapshot = tool['Snapshot']


class CompareWorldStartTests(unittest.TestCase):
    def test_dictionary_indices_do_not_define_identity(self):
        a = CompactReference(b'A' * 16, 2)
        b = CompactReference(b'A' * 16, 200)
        c = CompactReference(b'B' * 16, 2)
        self.assertEqual(tool['equivalence']([a, b, c]), [0, 0, 1])

    def test_unresolved_reference_is_not_evidence_of_equality(self):
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            tool['equivalence']([CompactReference(None, 2)] * 2)

    def test_float_comparison_preserves_wire_bits(self):
        f = tool['WireFloat32']
        self.assertEqual(tool['equivalence']([f(0), f(0x80000000), f(0)]), [0, 1, 0])

    def test_no_private_strings_or_reference_values_in_report(self):
        value = fixture()
        identity = b'PRIVATE-ID-12345'
        value = replace(value, core=replace(value.core,
            bytes_2b0=b'PRIVATE-DISPLAY-NAME',
            reference_4e0=CompactReference(identity),
            core_tail=replace(value.core.core_tail, fixed_bytes_4f0=identity)))
        sample = Snapshot(value, 1, 1, identity)
        report = tool['compare']([sample, sample])
        serialized = json.dumps(report)
        for secret in ('PRIVATE', identity.hex(), str(list(identity))):
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, repr(sample))
        self.assertEqual(report['created_id_matches_4e0'], [True, True])
        self.assertEqual(report['created_id_matches_4f0'], [True, True])
        self.assertEqual(report['character_fields_agree'], [True, True])

    def test_requires_multiple_snapshots(self):
        with self.assertRaisesRegex(ValueError, 'at least two'):
            tool['compare']([Snapshot(fixture(), 1, 1)])

    def test_private_three_initial_worlds(self):
        paths = [ROOT / name for name in (
            'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin',
            'private/world-bootstrap-first-gate-20260925.bin',
            'private/world-bootstrap-hub-stable-20260925.bin')]
        if not all(path.exists() for path in paths):
            self.skipTest('private captures unavailable')
        report = tool['compare']([tool['load_snapshot'](p) for p in paths])
        self.assertEqual(report['body_bytes'], [8450, 11179, 11666])
        self.assertEqual(report['created_id_matches_4e0'], [True, None, None])
        self.assertEqual(report['created_id_matches_4f0'], [True, None, None])
        self.assertEqual(report['character_fields_agree'], [True] * 3)
        slots = report['item_reference_slots']
        self.assertEqual(slots['reference_0']['unique_counts'], [199, 244, 244])
        self.assertEqual(slots['reference_0']['pairwise_shared'],
            [[199, 0, 0], [0, 244, 0], [0, 0, 244]])
        self.assertEqual(slots['reference_1']['unique_counts'], [126, 144, 144])
        self.assertEqual(slots['reference_1']['pairwise_shared'][1][2], 144)
        for slot in ('reference_2', 'reference_3'):
            self.assertEqual(slots[slot]['all_zero'], [True] * 3)


if __name__ == '__main__':
    unittest.main()
