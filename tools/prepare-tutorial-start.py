#!/usr/bin/env python3
"""Prepare the first five-row tutorial activation as a private, bounded artifact."""
import argparse
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_tutorial import ExperimentalTutorialActivation
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
    initial = activation = None
    for _, kind, _, _, payload in records(source):
        if kind == 2:
            for frame in decode_outbound_envelope(payload).frames:
                if frame.type_id == 0x000c and len(frame.body) == 147 and frame.body[:16] == known[0]:
                    if submitted:
                        raise ValueError('multiple tutorial submissions')
                    submitted = True
        elif kind == 1:
            for frame in decoder.feed(payload):
                if frame.type_id == 0x014d:
                    decode_type014d(frame.body, table)
                elif frame.type_id == 0x00e6:
                    value = decode_type00e6(frame.body, table)
                    if not submitted:
                        continue
                    if initial is None and not value.rows_20 and value.byte_64 == 0:
                        initial = value
                    elif initial is not None and value.reference_0.value == initial.reference_0.value:
                        if activation is not None or len(value.rows_20) != 5:
                            raise ValueError('unexpected first tutorial activity sequence')
                        activation = frame
                        break
            if activation is not None:
                break
    if initial is None or activation is None:
        raise ValueError('missing first tutorial activity activation')
    value = decode_type00e6(activation.body, table)
    if (value.byte_64 != 7 or any(row.signed_0_2[2] != 0 or row.subrows
                                  for row in value.rows_20)):
        raise ValueError('unsupported first tutorial activity state')
    result = ExperimentalTutorialActivation(activation).to_bytes()
    if any(item in result for item in known):
        raise ValueError('retail identity appears in activation artifact')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        data = prepare(args.capture)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        print('Prepared private five-row tutorial activation; no objective completion')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Tutorial activation preparation failed: {error}\n')


if __name__ == '__main__':
    main()
