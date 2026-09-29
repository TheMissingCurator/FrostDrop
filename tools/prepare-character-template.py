#!/usr/bin/env python3
"""Extract a private, normalized 18-node character presentation template.

The node meanings are not decoded. Profile identity, appearance floats,
progress scalars, and timestamps are deliberately excluded from the output.
"""
import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.character_template import ExperimentalCharacterTemplate
from isac_protocol.agent_submission import decode_agent_submission
from isac_protocol.character_record import decode_character_record, starting_character_record
from isac_protocol.framing import decode_outbound_envelope
from isac_protocol.profile_messages import decode_profile_list


def prepare(tutorial, finalization):
    records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
    snapshot = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](tutorial)
    created = None
    submissions = []
    for _, kind, _, aux, payload in records(tutorial):
        if kind == 4 and aux == 0:
            if created is not None:
                raise ValueError('multiple tutorial characters')
            created = payload
        elif kind == 2:
            submissions.extend(decode_agent_submission(frame.body)
                for frame in decode_outbound_envelope(payload).frames
                if frame.type_id == 0x000c)
    if created is None or len(submissions) != 1 or submissions[0].character_id != created:
        raise ValueError('missing matched tutorial appearance submission')
    if finalization.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('oversized profile capture')
    matches = []
    all_ids = set()
    for line in finalization.read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get('event') != 'profile_list' or not row.get('complete'):
            continue
        listing = decode_profile_list(bytes.fromhex(row['data_hex']))
        all_ids.update(entry.identifier for entry in listing.profiles)
        matches.extend(entry for entry in listing.profiles
            if entry.identifier == created and entry.is_customized)
    if not matches or len({entry.character_blob for entry in matches}) != 1:
        raise ValueError('missing stable customized tutorial record')
    source = decode_character_record(matches[0].character_blob)
    if (len(source.nodes) != 18 or any(node.children for node in source.nodes)
            or tuple(slot.bits for slot in submissions[0].float_slots) != source.float_bits_458):
        raise ValueError('unexpected customized record lineage')
    baseline = starting_character_record()
    normalized = replace(baseline, nodes=source.nodes, float_bits_458=(0,) * 32)
    result = ExperimentalCharacterTemplate(normalized).to_bytes()
    known = (*all_ids, snapshot.world.core.core_tail.tagged_bytes_500.data,
             snapshot.world.core.bytes_2b0)
    if any(value and value in result for value in known):
        raise ValueError('retail identity present in normalized template')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tutorial_capture', type=Path)
    parser.add_argument('finalization_capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        data = prepare(args.tutorial_capture, args.finalization_capture)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        print('Prepared private normalized character template; 18 nodes are capture-derived, '
              'appearance and progress values are not copied')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Character template preparation failed: {error}\n')


if __name__ == '__main__':
    main()
