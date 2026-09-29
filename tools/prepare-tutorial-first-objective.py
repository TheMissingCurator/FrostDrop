#!/usr/bin/env python3
"""Extract only the first active objective's new reference and position."""

import argparse
from dataclasses import replace
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_tutorial_objective import ExperimentalFirstObjective
from isac_protocol.codec import ReferenceTable
from isac_protocol.framing import InboundFrameStreamDecoder, decode_outbound_envelope
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
    initial = baseline = None
    current_tick, introduced = None, set()
    for tick, kind, _, _, payload in records(source):
        if tick != current_tick:
            current_tick, introduced = tick, set()
        if kind == 2:
            for frame in decode_outbound_envelope(payload).frames:
                if frame.type_id == 0x000c and len(frame.body) == 147 and frame.body[:16] == known[0]:
                    submitted = True
        elif kind == 1:
            for frame in decoder.feed(payload):
                if frame.type_id == 0x014d:
                    update = decode_type014d(frame.body, table)
                    introduced.update(ref.value for ref in update.references if ref.value is not None)
                elif frame.type_id == 0x00e6:
                    value = decode_type00e6(frame.body, table)
                    if not submitted:
                        continue
                    if initial is None and not value.rows_20 and value.byte_64 == 0:
                        initial = value
                    elif (initial is not None and baseline is None
                            and value.reference_0.value == initial.reference_0.value
                            and len(value.rows_20) == 5):
                        baseline = value
                        if value.byte_64 != 7 or any(row.signed_0_2[2] or row.subrows
                                                      for row in value.rows_20):
                            raise ValueError('unexpected first tutorial baseline')
                    elif (baseline is not None
                            and value.reference_0.value == baseline.reference_0.value
                            and len(value.rows_20) == 5):
                        if (replace(value, rows_20=baseline.rows_20) != baseline
                                or any(value.rows_20[index] != baseline.rows_20[index]
                                       for index in (0, 2, 3, 4))):
                            raise ValueError('first active update changes more than row 1')
                        row, old = value.rows_20[1], baseline.rows_20[1]
                        if (row.signed_0_2 != (old.signed_0_2[0], old.signed_0_2[1], 1)
                                or len(row.subrows) != 1
                                or replace(row, signed_0_2=old.signed_0_2, subrows=()) != old):
                            raise ValueError('unexpected first active row')
                        subrow = row.subrows[0]
                        reference = subrow.reference_0.value
                        if (reference is None or reference not in introduced
                                or reference in known or reference == baseline.reference_0.value
                                or subrow.signed_0 != 0 or subrow.boolean_0):
                            raise ValueError('first active subrow lacks a safe dictionary lineage')
                        return ExperimentalFirstObjective(reference, subrow.vector_0)
    raise ValueError('missing first active tutorial objective')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        value = prepare(args.capture)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value.to_bytes())
        print('Prepared private first-objective display test; no progression')
    except (OSError, ValueError) as error:
        parser.exit(1, f'First-objective preparation failed: {error}\n')


if __name__ == '__main__':
    main()
