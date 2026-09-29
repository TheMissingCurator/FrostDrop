#!/usr/bin/env python3
"""Byte-round-trip type 0x002a against broad schema-miner evidence."""

from __future__ import annotations

import argparse
import runpy
import sys
from collections import Counter
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    ReferenceTable,
    decode_type002a,
    encode_type002a,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="project-isac-dispatch-probe.log")
    args = parser.parse_args()
    miner = runpy.run_path(str(PROJECT_DIR / "tools/analyze-schema-miner.py"))

    try:
        messages, _counts, errors = miner["parse_message_log"](args.log)
        if errors:
            raise ValueError(f"capture contains {len(errors)} schema-miner errors")
        selected = [
            message
            for message in messages
            if message.complete and message.type_id == 0x002A
        ]
        if not selected:
            raise ValueError("capture contains no complete type 0x002a bodies")

        lengths: Counter[int] = Counter()
        tail_count = 0
        for message in selected:
            decoded = decode_type002a(
                message.data,
                ReferenceTable(assume_existing=True),
            )
            encoded = encode_type002a(
                decoded,
                ReferenceTable(assume_existing=True),
            )
            if encoded != message.data:
                raise ValueError(
                    f"message sequence {message.message_sequence} did not round-trip"
                )
            lengths[message.length] += 1
            tail_count += decoded.tail is not None
    except (OSError, ValueError) as error:
        parser.error(str(error))

    length_text = ",".join(
        f"{length}:{count}" for length, count in sorted(lengths.items())
    )
    print(f"Log: {args.log}")
    print(f"Complete type 0x002a bodies: {len(selected)}")
    print(f"Byte-identical round trips: {len(selected)}")
    print(f"Conditional-tail bodies: {tail_count}")
    print(f"Lengths: {length_text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
