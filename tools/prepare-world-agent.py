#!/usr/bin/env python3
"""Prepare a PRIVATE experimental response around tutorial agent submission.

Copies the post-first-gate dictionary updates and first 500 ms of inbound
retail world frames after the single 147-byte 0x000c request. This is a
bounded replay experiment, not an inferred protocol implementation.
"""

import argparse
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_agent import ExperimentalAgentResponse
from isac_protocol.framing import InboundFrameStreamDecoder, decode_outbound_envelope


def prepare(source):
    records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
    snapshot = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
    known = (snapshot.created, snapshot.world.core.core_tail.tagged_bytes_500.data,
             snapshot.world.core.bytes_2b0)
    if known[0] is None or not all(known):
        raise ValueError('requires observed created tutorial identity')
    decoders = {}
    requested = gate_seen = first_gate_done = False
    submit_tick = None
    prelude, response = [], []
    for tick, kind, stream_id, _, payload in records(source):
        if kind == 2:
            for frame in decode_outbound_envelope(payload).frames:
                if frame.type_id == 9 and frame.body == known[0]:
                    if requested:
                        raise ValueError('duplicate first-gate request')
                    requested = True
                if frame.type_id == 0x000c:
                    if (not first_gate_done or submit_tick is not None
                            or len(frame.body) != 147 or frame.body[:16] != known[0]
                            or frame.body.count(known[0]) != 1):
                        raise ValueError('unsupported agent submission')
                    submit_tick = tick
        elif kind == 1:
            if not stream_id:
                raise ValueError('missing tutorial world source')
            decoder = decoders.setdefault(stream_id,
                InboundFrameStreamDecoder(maximum_frame_length=16777216))
            for frame in decoder.feed(payload):
                if requested and not first_gate_done:
                    if frame.type_id == 0x0012:
                        gate_seen = True
                    if gate_seen and frame.type_id == 0x0102:
                        first_gate_done = True
                    continue
                if first_gate_done and submit_tick is None:
                    if frame.type_id == 0x014d:
                        prelude.append(frame)
                elif submit_tick is not None and tick <= submit_tick + 500:
                    response.append(frame)
        if submit_tick is not None and tick > submit_tick + 500:
            break
    if (not first_gate_done or submit_tick is None
            or len(prelude) != 48 or len(response) != 142):
        raise ValueError('unexpected tutorial agent response window')
    if any(value in frame.body for frame in (*prelude, *response) for value in known):
        raise ValueError('known retail identity in agent response')
    result = ExperimentalAgentResponse(tuple(prelude), tuple(response))
    encoded = result.to_bytes()
    if ExperimentalAgentResponse.from_bytes(encoded) != result:
        raise ValueError('agent response round trip failed')
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
        print('Prepared private agent response: 48 dictionary updates and 500 ms bounded '
              'response window; unknown fields capture-derived; no gameplay simulation')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Agent response preparation failed: {error}\n')


if __name__ == '__main__':
    main()
