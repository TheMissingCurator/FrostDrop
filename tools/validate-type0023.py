#!/usr/bin/env python3
"""Byte-round-trip type 0x0023 against broad schema-miner evidence."""

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
    decode_type0023,
    encode_type0023,
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
            if message.complete and message.type_id == 0x0023
        ]
        if not selected:
            raise ValueError("capture contains no complete type 0x0023 bodies")

        shapes: Counter[tuple[int, int, int]] = Counter()
        for message in selected:
            decoded = decode_type0023(
                message.data,
                ReferenceTable(assume_existing=True),
            )
            encoded = encode_type0023(
                decoded,
                ReferenceTable(assume_existing=True),
            )
            if encoded != message.data:
                raise ValueError(
                    f"message sequence {message.message_sequence} did not round-trip"
                )
            shapes[(decoded.byte_0, decoded.discriminator, message.length)] += 1
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Complete type 0x0023 bodies: {len(selected)}")
    print(f"Byte-identical round trips: {len(selected)}")
    print("Observed shapes:")
    for (byte_0, discriminator, length), count in sorted(shapes.items()):
        print(
            f"  byte_0={byte_0} discriminator={discriminator} "
            f"length={length} bodies={count}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
