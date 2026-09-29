#!/usr/bin/env python3
"""Prepare a bounded private cover-completion experiment from marked retail evidence."""

import argparse
from dataclasses import replace
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_tutorial_cover import ExperimentalCoverCompletion
from isac_protocol.codec import ReferenceTable
from isac_protocol.framing import InboundFrameStreamDecoder, decode_outbound_envelope
from isac_protocol.type0014 import decode_type0014
from isac_protocol.type00e6 import decode_type00e6
from isac_protocol.world_messages import decode_type014d


def prepare(source):
    records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
    snapshot = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
    known = (snapshot.created, snapshot.world.core.core_tail.tagged_bytes_500.data,
             snapshot.world.core.bytes_2b0)
    if not all(known):
        raise ValueError('missing observed tutorial identity')
    decoder, table = InboundFrameStreamDecoder(maximum_frame_length=16777216), ReferenceTable()
    submitted = False
    active = None
    candidates = []
    current_tick, introduced = None, set()
    for tick, kind, _, _, payload in records(source):
        if tick != current_tick:
            current_tick, introduced = tick, set()
        if kind == 2:
            for frame in decode_outbound_envelope(payload).frames:
                if frame.type_id == 0x000c and len(frame.body) == 147 and frame.body[:16] == known[0]:
                    submitted = True
                elif frame.type_id == 0x0014 and submitted and active is not None:
                    value = decode_type0014(frame.body)
                    if (value.reference_0 == known[0]
                            and (value.signed_0, value.signed_1, value.signed_2) == (1, 0, 0)
                            and value.bytes_0_3 == (1, 0, 0, 85)):
                        candidates.append((tick, value))
        elif kind == 1:
            for frame in decoder.feed(payload):
                if frame.type_id == 0x014d:
                    update = decode_type014d(frame.body, table)
                    introduced.update(ref.value for ref in update.references if ref.value is not None)
                elif frame.type_id == 0x00e6:
                    value = decode_type00e6(frame.body, table)
                    if not submitted or len(value.rows_20) != 5:
                        continue
                    states = tuple(row.signed_0_2[2] for row in value.rows_20)
                    if states == (0, 1, 0, 0, 0) and active is None:
                        active = value
                    elif active is not None and states == (0, 4, 1, 0, 0):
                        if (replace(value, rows_20=active.rows_20) != active
                                or any(value.rows_20[i] != active.rows_20[i] for i in (0, 3, 4))
                                or replace(value.rows_20[1], signed_0_2=active.rows_20[1].signed_0_2)
                                != active.rows_20[1]
                                or len(value.rows_20[2].subrows) != 1
                                or replace(value.rows_20[2], signed_0_2=active.rows_20[2].signed_0_2,
                                           subrows=()) != active.rows_20[2]):
                            raise ValueError('unexpected first-cover completion shape')
                        subrow = value.rows_20[2].subrows[0]
                        fresh = subrow.reference_0.value
                        if (fresh is None or fresh not in introduced or fresh in known
                                or subrow.signed_0 != 0 or subrow.boolean_0):
                            raise ValueError('unbound next-objective reference')
                        matched = [(when, action) for when, action in candidates
                                   if 0 < tick - when <= 1000 and action.reference_1 not in known]
                        if len(matched) != 1:
                            raise ValueError('ambiguous retail cover-entry candidate')
                        action = matched[0][1]
                        return ExperimentalCoverCompletion(action.reference_1, action.vector_1,
                                                           fresh, subrow.vector_0)
    raise ValueError('missing first-cover completion')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        artifact = prepare(args.capture)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(artifact.to_bytes())
        print('Prepared private first-cover completion test; no later objectives or rewards')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Cover-completion preparation failed: {error}\n')


if __name__ == '__main__':
    main()
