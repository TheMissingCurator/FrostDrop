#!/usr/bin/env python3
"""Compare decoded initial worlds without printing identities or captured text.

Equality is evidence of observed stability, NOT permission to use a field as
a default. Reference comparisons ignore capture-local dictionary indices.
"""
import argparse
from dataclasses import dataclass, field, fields, is_dataclass
import json
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_protocol.codec import CompactReference, ReferenceTable, WireFloat32
from isac_protocol.framing import InboundFrameStreamDecoder
from isac_protocol.world_messages import decode_type014d
from isac_protocol.world_start import decode_world_start, encode_world_start


@dataclass
class Snapshot:
    world: object = field(repr=False)
    body_bytes: int
    dictionary_entries: int
    created: bytes | None = field(default=None, repr=False)


def load_snapshot(path):
    with path.open('rb') as source:
        magic = source.read(8)
    created = None
    if magic == b'ISACTUT1':
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        def payloads():
            nonlocal created
            selected = None
            for _, kind, source, aux, payload in records(path):
                if kind == 4 and aux == 0:
                    if len(payload) != 16:
                        raise ValueError('invalid created identifier length')
                    created = payload
                if kind == 1:
                    if not source or selected not in (None, source):
                        raise ValueError('ambiguous world stream')
                    selected = source
                    yield payload
        chunks = payloads()
    elif magic == b'ISACWBS1':
        decode = runpy.run_path(str(ROOT / 'tools/inspect-world-bootstrap.py'))['decode_capture']
        chunks = (span.data for span in decode(path.read_bytes())[2])
    else:
        raise ValueError('unsupported capture magic')
    table, stream = ReferenceTable(), InboundFrameStreamDecoder()
    for chunk in chunks:
        for frame in stream.feed(chunk):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 7:
                before = table.clone()
                value = decode_world_start(frame.body, table)
                if encode_world_start(value, before) != frame.body or before.entries != table.entries:
                    raise ValueError('world round-trip mismatch')
                return Snapshot(value, len(frame.body), len(table.entries), created)
    raise ValueError('initial world not found')


def semantic(value):
    """Internal comparison key, never serialized into the report."""
    if isinstance(value, CompactReference):
        if value.value is None:
            raise ValueError('unresolved reference cannot be compared across captures')
        return ('reference', value.value)
    if isinstance(value, WireFloat32):
        return ('float-bits', value.bits)
    if is_dataclass(value):
        return tuple((f.name, semantic(getattr(value, f.name))) for f in fields(value))
    if isinstance(value, tuple):
        return tuple(semantic(v) for v in value)
    return value


def leaves(value):
    if isinstance(value, (CompactReference, WireFloat32, bytes, int, bool)):
        yield value
    elif is_dataclass(value):
        for f in fields(value):
            yield from leaves(getattr(value, f.name))
    elif isinstance(value, tuple):
        for child in value:
            yield from leaves(child)


def field_map(world):
    result = {}
    diagnostics = {'core_tail_start', 'core_tail_round_trip', 'consumed_bytes', 'remaining_bytes'}
    for f in fields(world.core):
        if f.name not in diagnostics | {'core_tail'}:
            result['core.' + f.name] = getattr(world.core, f.name)
    for f in fields(world.core.core_tail):
        if f.name != 'collections':
            result['tail.' + f.name] = getattr(world.core.core_tail, f.name)
    for col in world.core.core_tail.collections:
        result[f'tail.collection_{col.parent_offset:03x}'] = col.rows
    for f in fields(world):
        if f.name != 'core':
            result[f.name] = getattr(world, f.name)
    return result


def equivalence(values):
    keys, groups = [], []
    for value in values:
        key = semantic(value)
        if key not in keys:
            keys.append(key)
        groups.append(keys.index(key))
    return groups


def describe(value):
    if isinstance(value, CompactReference):
        return {'kind': 'reference', 'zero': value.value == bytes(16)}
    if isinstance(value, bytes):
        return {'kind': 'bytes', 'length': len(value), 'zero': not any(value)}
    if isinstance(value, WireFloat32):
        return {'kind': 'float', 'value': value.value}
    if isinstance(value, (bool, int)):
        return {'kind': 'scalar', 'value': value}
    atoms = list(leaves(value))
    return {'kind': 'collection' if isinstance(value, tuple) else 'structure',
        'length': len(value) if isinstance(value, tuple) else len(fields(value)),
        'reference_leaves': sum(isinstance(v, CompactReference) for v in atoms),
        'byte_lengths': sorted({len(v) for v in atoms if isinstance(v, bytes)}),
        'numeric_leaves': sum(isinstance(v, (int, WireFloat32)) for v in atoms)}


def compare(snapshots):
    if len(snapshots) < 2:
        raise ValueError('at least two snapshots required')
    maps = [field_map(s.world) for s in snapshots]
    rows = {}
    for key in maps[0]:
        values = [m[key] for m in maps]
        groups = equivalence(values)
        rows[key] = {'equal_groups': groups, 'observed_equal': len(set(groups)) == 1,
            'samples': [describe(v) for v in values]}
    refsets = [{v.value for v in leaves(s.world) if isinstance(v, CompactReference)
        and v.value is not None and any(v.value)} for s in snapshots]
    item_slots = {}
    for slot in range(4):
        sets = [{getattr(item, f'reference_{slot}').value
            for item in s.world.core.items_4d0} for s in snapshots]
        item_slots[f'reference_{slot}'] = {
            'unique_counts': [len(values) for values in sets],
            'all_zero': [bool(values) and values == {bytes(16)} for values in sets],
            'pairwise_shared': [[len(a & b) for b in sets] for a in sets]}
    return {'snapshot_count': len(snapshots),
        'body_bytes': [s.body_bytes for s in snapshots],
        'dictionary_entries': [s.dictionary_entries for s in snapshots],
        'created_id_matches_4f0': [None if s.created is None else
            s.created == s.world.core.core_tail.fixed_bytes_4f0 for s in snapshots],
        'created_id_matches_4e0': [None if s.created is None else
            s.created == s.world.core.reference_4e0.value for s in snapshots],
        'character_fields_agree': [s.world.core.reference_4e0.value ==
            s.world.core.core_tail.fixed_bytes_4f0 for s in snapshots],
        'item_reference_slots': item_slots,
        'nonzero_reference_counts': [len(v) for v in refsets],
        'pairwise_shared_references': [[len(a & b) for b in refsets] for a in refsets],
        'fields': rows,
        'warning': 'Observed equality is not proof of a reusable default or field meaning.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('captures', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(compare([load_snapshot(path) for path in args.captures]), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f'Comparison failed: {error}\n')


if __name__ == '__main__':
    main()
