#!/usr/bin/env python3
"""Map a retail message ordinal to its static vtable/reader/writer RVAs.

This uses the verified runtime snapshots for this one analyzed build. Runtime
type IDs can be randomized, so captured ordinals must be corroborated; this
is not a portable mapping and does not assign business semantics.
"""

import argparse
import hashlib
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
TEXT = ROOT / 'private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin'
RDATA = ROOT / 'private/startup-leads-jcoCPbG7/static-rdata.bin'
TEXT_HASH = 'dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74'
RDATA_RVA = 0x2901000
RDATA_BYTES = 0x152CC8A
INIT_TABLE_RVA = 0x2907C98
IMAGE_BASE = 0x140000000


def load_snapshots():
    text = TEXT.read_bytes()
    if hashlib.sha256(text).hexdigest() != TEXT_HASH:
        raise ValueError('text snapshot does not match analyzed build')
    snapshot = RDATA.read_bytes()
    if len(snapshot) != RDATA_BYTES + 16 or struct.unpack_from('<8sII', snapshot) != (b'ISACRD01', RDATA_RVA, RDATA_BYTES):
        raise ValueError('rdata snapshot does not match analyzed build')
    return text, snapshot[16:]


def initializer_globals(text):
    result = {}
    for match in re.finditer(rb'\x48\x8d\x0d....\xe9....', text, re.S):
        offset = match.start()
        rva = offset + 0x1000
        jump = rva + 12 + struct.unpack_from('<i', text, offset + 8)[0]
        if jump == 0x1160B60:
            result[rva] = rva + 7 + struct.unpack_from('<i', text, offset + 3)[0]
    if len(result) != 450:
        raise ValueError('initializer count differs from analyzed build')
    return result


def map_type(type_id, text, rdata, initializers):
    if not 0 <= type_id < 450:
        raise ValueError('type ordinal outside analyzed initializer sequence')
    offset = INIT_TABLE_RVA - RDATA_RVA + type_id * 8
    initializer = struct.unpack_from('<Q', rdata, offset)[0] - IMAGE_BASE
    if initializer not in initializers:
        raise ValueError('initializer pointer does not match analyzed build')
    global_rva = initializers[initializer]
    getters = []
    for match in re.finditer(rb'\x0f\xb7\x05....\xc3', text, re.S):
        off = match.start()
        rva = off + 0x1000
        if rva + 7 + struct.unpack_from('<i', text, off + 3)[0] == global_rva:
            getters.append(rva)
    candidates = []
    for getter in getters:
        needle = struct.pack('<Q', IMAGE_BASE + getter)
        start = 0
        while (found := rdata.find(needle, start)) >= 0:
            start = found + 1
            if found < 0x18 or found + 0x28 > len(rdata):
                continue
            vtable = RDATA_RVA + found - 0x18
            writer = struct.unpack_from('<Q', rdata, found + 0x18)[0] - IMAGE_BASE
            reader = struct.unpack_from('<Q', rdata, found + 0x20)[0] - IMAGE_BASE
            if 0x1000 <= writer < len(text) + 0x1000 and 0x1000 <= reader < len(text) + 0x1000:
                candidates.append((vtable, writer, reader))
    if len(candidates) != 1:
        raise ValueError('type does not resolve to one static vtable')
    return initializer, global_rva, getters, candidates[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('type_id', type=lambda text: int(text, 0))
    args = parser.parse_args()
    try:
        text, rdata = load_snapshots()
        initializers = initializer_globals(text)
        for known, expected in ((0x014D, 0x17939E0), (0x0157, 0xC4A690)):
            if map_type(known, text, rdata, initializers)[3][2] != expected:
                raise ValueError('known type mapping does not match analyzed build')
        initializer, global_rva, getters, (vtable, writer, reader) = map_type(args.type_id, text, rdata, initializers)
        print(f'type={args.type_id:#06x} initializer_rva={initializer:#x} id_global_rva={global_rva:#x}')
        print(f'getter_rvas={[hex(value) for value in getters]} vtable_rva={vtable:#x}')
        print(f'writer_rva={writer:#x} reader_rva={reader:#x}')
        print('Mapping is build-specific; runtime randomization may change numeric type IDs.')
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f'Static mapping failed: {error}\n')


if __name__ == '__main__':
    main()
