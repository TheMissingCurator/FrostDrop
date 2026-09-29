#!/usr/bin/env python3
"""Extract only the observed first-close companions and next activity state."""

import argparse
import hashlib
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_tutorial_next import ExperimentalNextActivity, DELTA_015A_SHA256
from isac_protocol.codec import Cursor, ReferenceTable, decode_reference
from isac_protocol.framing import InboundFrameStreamDecoder
from isac_protocol.type00e6 import decode_type00e6, encode_type00e6
from isac_protocol.world_messages import decode_type014d


def prepare(source):
    records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
    snapshot = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
    if not snapshot.created:
        raise ValueError('missing observed tutorial character')
    decoder, table = InboundFrameStreamDecoder(maximum_frame_length=16777216), ReferenceTable()
    seed = None
    final = closed = close_dictionary = close_event = None
    recent_dictionary = None
    for tick, kind, _, _, payload in records(source):
        if kind != 1:
            continue
        for frame in decoder.feed(payload):
            if frame.type_id == 0x014d:
                update = decode_type014d(frame.body, table)
                if seed is None:
                    seed = set(table.entries)
                if len(update.references) in (1, 2):
                    recent_dictionary = (tick, update.references)
            elif frame.type_id == 0x0064 and final is not None and closed is None:
                cursor = Cursor(frame.body)
                reference = decode_reference(cursor, table.clone())
                tail = cursor.read(cursor.remaining)
                if len(tail) == 7 and reference.value in seed:
                    close_event = (tick, reference.value, tail)
            elif frame.type_id == 0x00e6:
                value = decode_type00e6(frame.body, table)
                states = tuple(row.signed_0_2[2] for row in value.rows_20)
                if states == (0, 4, 4, 4, 4) and len(value.rows_20) == 5:
                    final = (tick, value.reference_0.value)
                elif (final is not None and closed is None and not value.rows_20
                      and value.byte_64 == 19 and value.reference_0.value == final[1]
                      and 0 < tick - final[0] <= 2000):
                    if (recent_dictionary is None or close_event is None
                            or not 0 <= tick - recent_dictionary[0] <= 200
                            or not 0 <= tick - close_event[0] <= 200
                            or len(recent_dictionary[1]) != 1):
                        raise ValueError('missing close companion lineage')
                    close_dictionary = recent_dictionary[1][0].value
                    closed = tick
                elif (closed is not None and 0 < tick - closed <= 10000
                      and states == (1, 0, 0, 0) and value.byte_64 == 7):
                    if (recent_dictionary is None or recent_dictionary[0] != tick
                            or len(recent_dictionary[1]) != 2
                            or len(value.rows_20[0].subrows) != 1):
                        raise ValueError('next activity lacks its two-reference dictionary')
                    new = (value.reference_0.value,
                           value.rows_20[0].subrows[0].reference_0.value)
                    if new != tuple(ref.value for ref in recent_dictionary[1]):
                        raise ValueError('next activity dictionary order mismatch')
                    if snapshot.created in (*new, close_dictionary):
                        raise ValueError('next activity contains retail character')
                    if any(ref in seed for ref in new) or close_dictionary in seed:
                        raise ValueError('next activity reuses initial dictionary')
                    event_reference = (bytes(16) if close_event[1] == snapshot.created
                                       else close_event[1])
                    return ExperimentalNextActivity(close_dictionary, event_reference,
                        close_event[2], encode_type00e6(value, None))
    raise ValueError('missing bounded next-activity handoff')


def prepare_dialogue_015a(source):
    """Select one post-handoff frame by structure, timing and pinned digest.

    This is an opt-in experiment, not a decoded audio command. The returned
    private bytes are deliberately never printed or checked into source.
    """
    records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
    snapshot = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
    decoder, table = InboundFrameStreamDecoder(maximum_frame_length=16777216), ReferenceTable()
    started = None
    candidates = []
    for tick, kind, _, _, payload in records(source):
        if kind != 1:
            continue
        for frame in decoder.feed(payload):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x00e6:
                value = decode_type00e6(frame.body, table)
                if (started is None and value.byte_64 == 7
                        and tuple(row.signed_0_2[2] for row in value.rows_20) == (1, 0, 0, 0)):
                    started = tick
            elif (frame.type_id == 0x015a and started is not None
                  and 0 < tick - started <= 1000 and len(frame.body) == 35):
                candidates.append(frame.body)
    if (len(candidates) != 1 or snapshot.created in candidates[0]
            or hashlib.sha256(candidates[0]).hexdigest() != DELTA_015A_SHA256):
        raise ValueError('missing pinned post-handoff 0x015a candidate')
    return candidates[0]


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
        print('Prepared private first-close and next-activity handoff; side missions not activated')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Next-activity preparation failed: {error}\n')


if __name__ == '__main__':
    main()
