#!/usr/bin/env python3
"""Decode private tutorial world structures; emit no payloads or identifiers."""
import argparse
from collections import Counter
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_protocol.codec import DecodeError, ReferenceTable
from isac_protocol.framing import InboundFrameStreamDecoder
from isac_protocol.registry import SERVER_TO_CLIENT, build_default_registry
from isac_protocol.world_messages import decode_type0007_prefix
from isac_protocol.world_start import decode_world_start

INSPECTOR = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))
RECORDS = INSPECTOR['records']
VALID_MARKERS = INSPECTOR['LABELS']


def analyze(path):
    registry = build_default_registry()
    table, framer = ReferenceTable(), InboundFrameStreamDecoder(maximum_frame_length=16777216)
    counts, errors = Counter(), Counter()
    skipped = Counter()
    prefixes, startups, rewards, stats, activities, notices = [], [], [], [], [], []
    selected = None
    created = None
    request_tick = None
    sync_body = parsed_body = None
    seed_rows = first_rows = 0
    markers = []
    metadata = path.with_suffix('.jsonl')
    if metadata.exists():
        if metadata.stat().st_size > 1048576:
            raise ValueError('oversized tutorial metadata')
        rows = []
        for line in metadata.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                notices.append('partial metadata line')
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('invalid metadata row')
            if row.get('event') == 'marker':
                tick, key = row.get('tick_ms'), row.get('key')
                if type(tick) is not int or tick < 0 or type(key) is not int or key not in VALID_MARKERS:
                    raise ValueError('invalid marker')
                markers.append((tick, key))
        if not any(row.get('event') == 'end' for row in rows):
            notices.append('no clean observer shutdown record')
        coverage = [row for row in rows if row.get('event') == 'coverage']
        if coverage and coverage[-1].get('failures'):
            notices.append('thread-arming failures recorded; coverage is not exhaustive')
        if any(row.get('event') == 'tutorial_end' and (row.get('gaps') or row.get('core_failed')) for row in rows):
            notices.append('observer gap/limit/read failure')
        if any(row.get('resume_failures') for row in rows):
            notices.append('thread resume failure')
        if any(row.get('event') == 'refused' for row in rows):
            notices.append('observer refused')
    else:
        notices.append('observer metadata absent')
    message_count = 0
    for tick, kind, source, aux, payload in RECORDS(path):
        if kind == 4 and aux == 0:
            if len(payload) != 16:
                raise ValueError('invalid successful create reply')
            created = payload
        elif kind == 5:
            if request_tick is not None:
                raise ValueError('multiple world requests')
            request_tick = tick
        elif kind == 3:
            if len(payload) != 17 or payload[16] > 1:
                raise ValueError('invalid reconstructed connect reply')
            parsed_body = payload
        elif kind == 6:
            notices.append('observer field error')
        if kind != 1:
            continue
        if not source:
            raise ValueError('missing world source')
        if selected is None:
            selected = source
        if source != selected:
            raise ValueError('multiple world streams require independent dictionaries')
        for frame in framer.feed(payload):
            message_count += 1
            if message_count > 200000:
                raise ValueError('message analysis limit')
            relative = tick - request_tick if request_tick is not None else None
            if sync_body is None and frame.type_id == 2 and len(frame.body) == 17:
                sync_body = frame.body
            if frame.type_id == 7:
                value = decode_type0007_prefix(frame.body, table)
                prefixes.append({'request_relative_ms': relative,
                    'consumed_bytes': value.consumed_bytes,
                    'remaining_bytes': value.remaining_bytes,
                    'reference_matches_created_character': bool(created and value.reference_20.value == created),
                    'unsigned_30': value.unsigned_30, 'signed_34': value.signed_34,
                    'signed_38': value.signed_38, 'fixed_signed_array_lengths': [len(a) for a in value.signed_arrays_3c_64_8c],
                    'fixed_nested_rows': len(value.fixed_rows_b4),
                    'vector_290_finite': all(abs(v.value) < float('inf') for v in value.vector_290),
                    'bounded_string_lengths': [len(value.bytes_2b0), len(value.bytes_3b8)],
                    'collection_count_4d0': value.collection_count_4d0,
                    'decoded_item_structures': len(value.items_4d0),
                    'item_children': sum(len(item.children) for item in value.items_4d0),
                    'item_auxiliary_rows': sum(len(item.auxiliary) for item in value.items_4d0),
                    'core_tail_start': value.core_tail_start,
                    'core_tail_bytes': value.consumed_bytes - value.core_tail_start,
                    'core_tail_byte_identical_round_trip': value.core_tail_round_trip,
                    'fixed_block_width': len(value.core_tail.fixed_bytes_4f0),
                    'tagged_text_tag': value.core_tail.tagged_bytes_500.tag,
                    'tagged_text_length': len(value.core_tail.tagged_bytes_500.data),
                    'core_tail_collection_counts': {
                        f'0x{col.parent_offset:03x}': len(col.rows)
                        for col in value.core_tail.collections}})
                try:
                    startup = decode_world_start(frame.body, table)
                except DecodeError:
                    # Retain the partial result for unimplemented variants;
                    # neither decoder commits a partially read dictionary.
                    errors[7] += 1
                else:
                    startups.append({'request_relative_ms': relative,
                        'body_bytes': len(frame.body), 'remaining_bytes': 0,
                        'byte_identical_round_trip': True,
                        'fixed_block_matches_created_character': bool(created and
                            startup.core.core_tail.fixed_bytes_4f0 == created),
                        'byte_float_rows_710': len(startup.byte_float_rows_710),
                        'groups_720': len(startup.groups_720),
                        'reference_float_rows_730': len(startup.reference_float_rows_730),
                        'empty_dynamic_groups_740': len(startup.empty_group_signed_740),
                        'references_758': len(startup.references_758)})
                    counts[7] += 1
                    continue
            if frame.type_id not in registry.type_ids(SERVER_TO_CLIENT) or frame.type_id in (2, 3, 6):
                skipped[frame.type_id] += 1
                continue  # Early control codecs use a DIFFERENT namespace/schema.
            before, working = table.clone(), table.clone()
            try:
                value = registry.decode(SERVER_TO_CLIENT, frame, working).value
                reencoded = registry.encode(SERVER_TO_CLIENT, frame.type_id, value, before)
                if reencoded.body != frame.body or before.entries != working.entries:
                    raise DecodeError('nonidentical round trip or table state')
                if frame.type_id == 0x014d:
                    # Unknown messages might introduce references. Only claim a
                    # complete observed dictionary when every seed is sequential.
                    count_before = len(table.entries)
                    for ref in value.references:
                        if ref.index is not None and ref.index >= count_before:
                            if ref.index != count_before:
                                raise DecodeError('dictionary index gap')
                            count_before += 1
                    if not counts[0x014d]:
                        first_rows = len(value.references)
                    seed_rows += len(value.references)
                table.entries[:] = working.entries
                counts[frame.type_id] += 1
            except DecodeError:
                errors[frame.type_id] += 1
                if frame.type_id == 0x014d:
                    raise ValueError('dictionary decoding failed; stop resolving later references')
                continue
            if frame.type_id == 0x0157:
                completion = [(tick - when, i + 1) for i, (when, key) in enumerate(markers) if key == 3]
                nearest = min(completion, key=lambda item: abs(item[0])) if completion else None
                rewards.append((tick, value, {'request_relative_ms': relative,
                    'body_bytes': len(frame.body), 'byte_30': value.byte_30,
                    'byte_signed_rows_48': list(value.byte_signed_rows_48),
                    'reference_signed_values_58': [v for _, v in value.reference_signed_rows_58],
                    'mixed_rows_270': len(value.mixed_rows_270),
                    'nested_rows_318': len(value.nested_rows_318),
                    'nearest_completion_marker': nearest[1] if nearest else None,
                    'offset_from_completion_ms': nearest[0] if nearest else None}))
            elif frame.type_id == 0x002a:
                stats.append((tick, value))
            elif frame.type_id == 0x00e6:
                # Dictionary indices are capture-local labels, not raw IDs.
                # These fields are structural objective-state candidates only.
                activities.append({
                    'request_relative_ms': relative,
                    'reference_index': value.reference_0.index,
                    'byte_64': value.byte_64,
                    'row_signed_2': [row.signed_0_2[2] for row in value.rows_20],
                    'row_subrow_counts': [len(row.subrows) for row in value.rows_20],
                })
    # Compare scalar changes for the SAME resolved owner/stat reference, not
    # just any coincidental 1500 nearby. This is a candidate correlation only.
    linked = []
    previous = {}
    for tick, value in stats:
        key = (value.reference_0.value, value.reference_1.value)
        if None in key:
            continue
        old = previous.get(key)
        if old is not None and value.signed_1 - old == value.signed_0:
            for reward_tick, reward, _ in rewards:
                amounts = [v for _, v in reward.byte_signed_rows_48]
                if abs(tick - reward_tick) <= 1000 and value.signed_0 in amounts and value.signed_0 > 0:
                    linked.append({'request_relative_ms': tick - request_tick if request_tick is not None else None,
                        'delta': value.signed_0, 'previous_signed_1': old,
                        'new_signed_1': value.signed_1,
                        'owner_matches_created_character': bool(created and value.reference_0.value == created),
                        'stat_matches_candidate_reference_20': value.reference_1.value == reward.reference_20.value})
        previous[key] = value.signed_1
    if sync_body is None or parsed_body is None or sync_body != parsed_body:
        notices.append('world stream not correlated with parsed connect reply')
    if framer.buffered_bytes:
        notices.append('incomplete frame tail')
    return {'inbound_frames': message_count, 'pending_bytes': framer.buffered_bytes,
        'connect_reply_correlated': bool(sync_body is not None and sync_body == parsed_body),
        'first_dictionary_rows': first_rows, 'dictionary_wire_rows': seed_rows,
        'dictionary_entries': len(table.entries),
        'byte_identical_round_trips': {f'0x{k:04x}': v for k, v in sorted(counts.items())},
        'unsupported_or_failed_bodies': {f'0x{k:04x}': v for k, v in sorted(errors.items())},
        'skipped_full_decode_types': {f'0x{k:04x}': v for k, v in sorted(skipped.items())},
        # Preserve the legacy prefix diagnostic key for existing consumers.
        'type0007_prefixes_only': prefixes, 'type0007_complete_observed_shape': startups,
        'reward_candidates': [r for _, _, r in rewards],
        'type00e6_activity_candidates': activities,
        'same_owner_stat_delta_candidates': linked,
        'marker_counts': dict(sorted(Counter(key for _, key in markers).items())),
        'notes': list(dict.fromkeys(notices))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    files = sorted((args.capture / 'tutorial-private').glob('tutorial-*.bin')) if args.capture.is_dir() else [args.capture]
    if not files:
        parser.error('no tutorial payload files')
    try:
        for path in files:
            print(path.name)
            print(json.dumps(analyze(path), indent=2))
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
