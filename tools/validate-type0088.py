#!/usr/bin/env python3
"""Round-trip type 0x0088 bodies reconstructed from schema-field evidence."""

from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    DecodeError,
    ReferenceTable,
    decode_type0088,
    encode_type0088,
)


TYPE_ID = 0x0088
FIRST_CALLER_RVA = 0x0EB572D


def reconstruct_bodies(records: list[object]) -> list[bytes]:
    selected = [record for record in records if record.type_id == TYPE_ID]
    bodies: list[bytes] = []
    current = bytearray()
    previous_after: int | None = None
    for record in selected:
        if record.return_rva == FIRST_CALLER_RVA:
            if current:
                bodies.append(bytes(current))
            current.clear()
            previous_after = None
        if not current and record.return_rva != FIRST_CALLER_RVA:
            raise ValueError("type 0x0088 field trace starts mid-message")
        exact = record.exact_wire
        if exact is None:
            raise ValueError(f"field sequence {record.sequence} has truncated wire data")
        if previous_after is not None and record.before_absolute != previous_after:
            raise ValueError(
                f"non-contiguous fields before sequence {record.sequence}: "
                f"{previous_after} -> {record.before_absolute}"
            )
        current.extend(exact)
        previous_after = record.after_absolute
    if current:
        bodies.append(bytes(current))
    return bodies


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="project-isac-dispatch-probe.log")
    args = parser.parse_args()

    analyzer = runpy.run_path(str(PROJECT_DIR / "tools/analyze-schema-fields.py"))
    miner = runpy.run_path(str(PROJECT_DIR / "tools/analyze-schema-miner.py"))
    try:
        records, _counts, errors = analyzer["parse_log"](args.log)
        if errors:
            raise ValueError(f"capture contains {len(errors)} schema errors")
        messages, _message_counts, message_errors = miner["parse_message_log"](
            args.log
        )
        if message_errors:
            raise ValueError(
                f"capture contains {len(message_errors)} schema-miner errors"
            )
        message_bodies = [
            message.data
            for message in messages
            if message.type_id == TYPE_ID and message.complete
        ]
        source = "schema-message"
        if message_bodies:
            bodies = message_bodies
        else:
            bodies = reconstruct_bodies(records)
            source = "schema-field reconstruction"
        if not bodies:
            raise ValueError("capture contains no type 0x0088 bodies")
        child_counts: list[int] = []
        auxiliary_counts: list[int] = []
        subitem_counts: list[int] = []
        equipped_values: list[int] = []
        for index, body in enumerate(bodies, 1):
            decode_table = ReferenceTable(assume_existing=True)
            message = decode_type0088(body, decode_table)
            encoded = encode_type0088(
                message,
                ReferenceTable(assume_existing=True),
            )
            if encoded != body:
                raise ValueError(f"body {index} did not round-trip byte-identically")
            equipped_values.append(message.equipped)
            child_counts.append(len(message.item.children))
            auxiliary_counts.append(len(message.item.auxiliary))
            subitem_counts.extend(
                len(child.subitems) for child in message.item.children
            )
    except (OSError, ValueError, DecodeError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Body source: {source}")
    print(f"Type 0x0088 bodies: {len(bodies)}")
    print(f"Byte-identical round trips: {len(bodies)}")
    print(f"Body lengths: {min(map(len, bodies))}-{max(map(len, bodies))}")
    print(f"Equipped values: {sorted(set(equipped_values))}")
    print(f"Child counts: {sorted(set(child_counts))}")
    print(f"Auxiliary counts: {sorted(set(auxiliary_counts))}")
    print(f"Child subitem counts: {sorted(set(subitem_counts)) or [0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
