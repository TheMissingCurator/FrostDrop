"""Observed world 0x000c codec; private capture checks emit no payload data."""

import json
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from isac_protocol.agent_submission import (AgentSubmission,
    decode_agent_submission, encode_agent_submission)
from isac_protocol.character_record import decode_character_record
from isac_protocol.codec import DecodeError, WireFloat32
from isac_protocol.framing import MessageFrame, decode_outbound_envelope
from isac_protocol.registry import CLIENT_TO_SERVER, build_default_registry


class AgentSubmissionCodecTests(unittest.TestCase):
    def test_observed_shape_and_registry_roundtrip(self):
        value = AgentSubmission(bytes(range(16)),
            tuple(WireFloat32.from_float(float(i % 4)) for i in range(32)), True)
        body = encode_agent_submission(value)
        self.assertEqual(len(body), 147)
        self.assertEqual(decode_agent_submission(body), value)
        registry = build_default_registry()
        decoded = registry.decode(CLIENT_TO_SERVER, MessageFrame(0x000c, body), None)
        self.assertEqual(decoded.value, value)
        self.assertEqual(registry.encode(CLIENT_TO_SERVER, 0x000c, value, None).body, body)

    def test_reject_unobserved_or_malformed_shapes(self):
        value = AgentSubmission(bytes(range(16)), (WireFloat32(0),) * 32, True)
        body = encode_agent_submission(value)
        for altered in (body[:-1], body + b'\x00', body[:16] + b'\x01' + body[17:],
                        body[:17] + b'\x21' + body[18:], body[:-1] + b'\x02'):
            with self.subTest(length=len(altered)):
                with self.assertRaises(DecodeError):
                    decode_agent_submission(altered)

    def test_private_retail_lineage_if_available(self):
        tutorial = ROOT / ('evidence/20260927-064853-retail-tutorial-x3s3v01n/'
                           'tutorial-private/tutorial-1200.bin')
        profile = ROOT / ('evidence/20260927-195420-retail-finalization-96i4fgh9/'
                          'finalization-private/finalization-1184.jsonl')
        if not tutorial.exists() or not profile.exists():
            self.skipTest('private retail fixtures unavailable')
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        decode_profile = runpy.run_path(str(ROOT / 'tools/inspect-retail-profile.py'))['decode']
        created, submissions = None, []
        for _, kind, _, aux, payload in records(tutorial):
            if kind == 4 and aux == 0:
                created = payload
            elif kind == 2:
                submissions.extend(f.body for f in decode_outbound_envelope(payload).frames
                                   if f.type_id == 0x000c)
        self.assertEqual(len(submissions), 1)
        submission = decode_agent_submission(submissions[0])
        self.assertEqual(submission.character_id, created)
        self.assertEqual(encode_agent_submission(submission), submissions[0])
        lists = [decode_profile('profile_list', bytes.fromhex(row['data_hex']))
                 for line in profile.read_text().splitlines()
                 if (row := json.loads(line)).get('event') == 'profile_list']
        matching = [p for p in lists[-1]['profiles'] if p['identifier'] == created]
        self.assertEqual(len(matching), 1)
        self.assertTrue(matching[0]['flags_d8_to_db'][2])
        record = decode_character_record(matching[0]['blob_e0'])
        self.assertEqual(tuple(slot.bits for slot in submission.float_slots), record.float_bits_458)
        local = ROOT / ('evidence/20260927-191449-802796-sdk-adapter-linux/'
                        'transport-private/backend-0002-agent-10.bin')
        if local.exists():
            local_submission = decode_agent_submission(local.read_bytes())
            self.assertEqual(local_submission.float_slots, submission.float_slots)
            self.assertEqual(local_submission.final_flag, submission.final_flag)


if __name__ == '__main__':
    unittest.main()
