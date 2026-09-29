#!/usr/bin/env python3
"""Extract bounded shooting/switch tutorial transitions from private retail evidence."""

import argparse
from dataclasses import replace
import os
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_tutorial_stages import ExperimentalStageProgression, parse_shot_header
from isac_protocol.codec import ReferenceTable
from isac_protocol.framing import InboundFrameStreamDecoder, decode_outbound_envelope
from isac_protocol.type0088 import decode_type0088
from isac_protocol.type00e6 import decode_type00e6
from isac_protocol.world_messages import decode_type014d


def prepare(source):
    records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
    snapshot = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
    character = snapshot.created
    if not character:
        raise ValueError('missing retail character identity')
    decoder, table = InboundFrameStreamDecoder(maximum_frame_length=16777216), ReferenceTable()
    candidate = None
    shot_reference = shot_tick = switch_tick = switch_request = None
    switch_updates = []
    shooting = False
    prior = None
    introduced = set()
    current_tick = None
    for tick, kind, _, _, payload in records(source):
        if tick != current_tick:
            current_tick, introduced = tick, set()
        if kind == 2:
            for frame in decode_outbound_envelope(payload).frames:
                if frame.type_id == 0x0088 and shooting and len(frame.body) == 105:
                    item = decode_type0088(frame.body, None)
                    if (item.owner_reference.value == character and item.signed_0 == 1
                            and item.equipped == 0):
                        switch_tick = tick
                        switch_request = item
                        switch_updates = []
                if frame.type_id != 0x006a or shooting:
                    continue
                # Extract the one stable third reference from the three-message
                # retail opening; item reference can differ per character.
                if len(frame.body) not in (244, 338) or frame.body[:16] != character:
                    continue
                static = frame.body[32:48]
                header = parse_shot_header(frame.body, character, static)
                if header is None:
                    continue
                item, counter = header
                if counter == 31:
                    candidate = (item, static, 30)
                elif candidate is not None and (item, static, counter) == candidate:
                    if counter == 29:
                        shot_reference, shot_tick = static, tick
                    else:
                        candidate = (item, static, 29)
                else:
                    candidate = None
        elif kind == 1:
            for frame in decoder.feed(payload):
                if frame.type_id == 0x014d:
                    update = decode_type014d(frame.body, table)
                    introduced.update(ref.value for ref in update.references if ref.value is not None)
                elif frame.type_id == 0x0088 and switch_tick is not None and 0 < tick - switch_tick <= 1000:
                    switch_updates.append(decode_type0088(frame.body, table.clone()))
                elif frame.type_id == 0x00e6:
                    value = decode_type00e6(frame.body, table)
                    if len(value.rows_20) != 5:
                        continue
                    states = tuple(row.signed_0_2[2] for row in value.rows_20)
                    if states == (0, 4, 1, 0, 0):
                        prior = value
                    elif states == (0, 4, 4, 1, 0) and not shooting:
                        if (prior is None or shot_reference is None or shot_tick is None
                                or not 0 < tick - shot_tick <= 1000
                                or replace(value, rows_20=prior.rows_20) != prior
                                or any(value.rows_20[i] != prior.rows_20[i] for i in (0, 1, 4))
                                or any(replace(value.rows_20[i], signed_0_2=prior.rows_20[i].signed_0_2)
                                       != prior.rows_20[i] for i in (2, 3))):
                            raise ValueError('unexpected shooting transition')
                        prior, shooting = value, True
                    elif states == (0, 4, 4, 4, 1) and shooting:
                        if (prior is None or switch_tick is None
                                or not 0 < tick - switch_tick <= 1000
                                or replace(value, rows_20=prior.rows_20) != prior
                                or any(value.rows_20[i] != prior.rows_20[i] for i in (0, 1, 2))
                                or replace(value.rows_20[3], signed_0_2=prior.rows_20[3].signed_0_2)
                                   != prior.rows_20[3]
                                or len(value.rows_20[4].subrows) != 1
                                or replace(value.rows_20[4], signed_0_2=prior.rows_20[4].signed_0_2,
                                           subrows=()) != prior.rows_20[4]):
                            raise ValueError('unexpected switch transition')
                        subrow = value.rows_20[4].subrows[0]
                        reference = subrow.reference_0.value
                        if (reference is None or reference not in introduced
                                or reference == shot_reference or subrow.signed_0 != 0
                                or subrow.boolean_0):
                            raise ValueError('unbound final objective reference')
                        if (switch_request is None or len(switch_updates) != 2
                                or sorted(reply.equipped for reply in switch_updates) != [0, 1]):
                            raise ValueError('missing paired retail equipment updates')
                        replies = {reply.equipped: reply for reply in switch_updates}
                        if (any(reply.signed_0 != 0 or reply.owner_reference.value != character
                                or len(reply.item.children) or len(reply.item.auxiliary)
                                for reply in switch_updates)
                                or replies[0].item.reference_0.value != switch_request.item.reference_0.value
                                or replies[0].item.reference_1.value != switch_request.item.reference_1.value):
                            raise ValueError('retail switch replies do not match request')
                        indices = []
                        for equipped in (1, 0):
                            reply_item = replies[equipped].item
                            matching = [i for i, startup_item in enumerate(snapshot.world.core.items_4d0)
                                        if replace(startup_item, signed_5=reply_item.signed_5,
                                                   signed_6=reply_item.signed_6) == reply_item]
                            if len(matching) != 1:
                                raise ValueError('ambiguous retail equipment item lineage')
                            indices.append(matching[0])
                        return ExperimentalStageProgression(shot_reference, reference,
                            subrow.vector_0, indices[0], indices[1],
                            replies[1].item.reference_1.value,
                            replies[0].item.reference_1.value,
                            replies[1].item.signed_5, replies[1].item.signed_6,
                            replies[0].item.signed_5, replies[0].item.signed_6)
    raise ValueError('missing paired tutorial stage transitions')


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
        print('Prepared private shooting/switch transition test; no completion or rewards')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Stage-progression preparation failed: {error}\n')


if __name__ == '__main__':
    main()
