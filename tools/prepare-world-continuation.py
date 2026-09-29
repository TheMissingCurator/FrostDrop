#!/usr/bin/env python3
"""Prepare a PRIVATE, bounded tutorial burst from 0x0009 through first flush.

This is an explicitly experimental capture-derived artifact. Known character,
account and display-name occurrences are replaced before it is written.
Unclassified message fields remain private, and no gameplay simulation is
claimed.
"""

import argparse
import os
from pathlib import Path
import runpy
import secrets
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_continuation import ExperimentalWorldContinuation, _substitute
from isac_backend.world_startup import walk
from isac_protocol.codec import ReferenceTable
from isac_protocol.framing import InboundFrameStreamDecoder, decode_outbound_envelope
from isac_protocol.world_messages import decode_type014d


def prepare(source):
    modules = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))
    sample = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
    if sample.created is None or sample.created != sample.world.core.reference_4e0.value:
        raise ValueError('requires observed newly-created tutorial character')
    old_char = sample.created
    old_account = sample.world.core.core_tail.tagged_bytes_500.data
    old_name = sample.world.core.bytes_2b0
    if not 1 <= len(old_name) <= 63:
        raise ValueError('unsupported captured display name')
    decoder, table = InboundFrameStreamDecoder(maximum_frame_length=16777216), ReferenceTable()
    saw_start = saw_request = saw_gate = False
    frames = []
    for _, kind, source_id, _, payload in modules['records'](source):
        if kind == 1:
            if not source_id:
                raise ValueError('missing tutorial world source')
            for frame in decoder.feed(payload):
                if not saw_start and frame.type_id == 0x014d:
                    decode_type014d(frame.body, table)
                if frame.type_id == 7 and not saw_start:
                    expected = tuple(dict.fromkeys(r.value for r in walk(sample.world)))
                    if tuple(table.entries) != expected:
                        raise ValueError('initial dictionary order differs from typed startup')
                    saw_start = True
                if saw_request:
                    frames.append(frame)
                    if len(frames) > 512:
                        raise ValueError('first continuation exceeds frame bound')
                    if frame.type_id == 0x0012:
                        saw_gate = True
                    elif saw_gate and frame.type_id == 0x0102:
                        break
            if saw_gate and frames[-1].type_id == 0x0102:
                break
        elif kind == 2 and saw_start and not saw_request:
            envelope = decode_outbound_envelope(payload)
            if any(f.type_id == 9 and f.body == old_char for f in envelope.frames):
                saw_request = True
    if not (saw_start and saw_request and saw_gate and frames[-1].type_id == 0x0102):
        raise ValueError('incomplete tutorial 0x0009 continuation')
    if len(frames) != 322 or frames[-2].type_id != 0x0012:
        raise ValueError('unexpected observed continuation frame shape')
    for old in (old_char, old_account, old_name):
        if sum(frame.body.count(old) for frame in frames) != 2:
            raise ValueError('unexpected known identity occurrences in continuation')
    all_bodies = b''.join(frame.body for frame in frames)
    new_char = uuid.uuid4().bytes
    new_account = str(uuid.uuid4()).encode('ascii')
    alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    new_name = bytes(alphabet[secrets.randbelow(len(alphabet))] for _ in old_name)
    for value in (new_char, new_account, new_name):
        if value in all_bodies:
            raise ValueError('continuation placeholder collision')
    for old, new in ((old_char, new_char), (old_account, new_account),
                     (old_name, new_name)):
        frames = _substitute(tuple(frames), old, new)
    result = ExperimentalWorldContinuation(new_char, new_account, new_name,
                                           tuple(frames))
    encoded = result.to_bytes()
    if ExperimentalWorldContinuation.from_bytes(encoded) != result:
        raise ValueError('continuation round trip failed')
    return encoded


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
        print('Prepared private first-gate continuation: known identities replaced; '
              'unknown fields capture-derived; gameplay not implemented')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Continuation preparation failed: {error}\n')


if __name__ == '__main__':
    main()
