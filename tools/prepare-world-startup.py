#!/usr/bin/env python3
"""Build a PRIVATE opt-in typed startup template, not a full world replay.

Known retail character/name/account and instance identifiers are replaced
with local placeholders. Unclassified values remain capture-derived; this
file is NOT safe to publish and NOT a capture-independent world generator.
"""
import argparse
import os
from pathlib import Path
import runpy
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_startup import ExperimentalWorldTemplate


def prepare(source):
    load = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot']
    sample = load(source)
    if (sample.created is None or sample.created != sample.world.core.reference_4e0.value
            or sample.created != sample.world.core.core_tail.fixed_bytes_4f0
            or sample.world.core.flag_4c8):
        raise ValueError('requires the observed newly-created tutorial startup shape')
    template = ExperimentalWorldTemplate(sample.world)
    # Do not retain the known retail identities even in the private template.
    local = template.bind(uuid.uuid4().bytes, str(uuid.uuid4()), 'ISAC Template')
    return ExperimentalWorldTemplate(local).to_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        data = prepare(args.capture)
        # Exclusive create: never overwrite evidence or an existing template.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        print(f'Prepared private experimental template: bytes={len(data)}; '
              'known_identities=replaced unknown_fields=capture-derived gameplay=not-implemented')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Template preparation failed: {error}\n')


if __name__ == '__main__':
    main()
