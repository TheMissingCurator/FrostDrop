#!/usr/bin/env python3
"""Byte-round-trip simple message codecs against broad schema-miner evidence."""

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
    decode_type0020,
    decode_type0024,
    decode_type002d,
    decode_type0067,
    decode_type019d,
    encode_type0020,
    encode_type0024,
    encode_type002d,
    encode_type0067,
    encode_type019d,
)


CODECS = {
    0x0020: (decode_type0020, encode_type0020),
    0x0024: (decode_type0024, encode_type0024),
    0x002D: (decode_type002d, encode_type002d),
    0x0067: (decode_type0067, encode_type0067),
    0x019D: (decode_type019d, encode_type019d),
}


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
            if message.complete and message.type_id in CODECS
        ]
        if not selected:
            raise ValueError("capture contains no complete supported message bodies")
        counts: Counter[int] = Counter()
        lengths: dict[int, Counter[int]] = {
            type_id: Counter() for type_id in CODECS
        }
        for message in selected:
            decoder, encoder = CODECS[message.type_id]
            decoded = decoder(
                message.data,
                ReferenceTable(assume_existing=True),
            )
            encoded = encoder(
                decoded,
                ReferenceTable(assume_existing=True),
            )
            if encoded != message.data:
                raise ValueError(
                    f"type {message.type_id:#06x} message sequence "
                    f"{message.message_sequence} did not round-trip"
                )
            counts[message.type_id] += 1
            lengths[message.type_id][message.length] += 1
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Supported complete bodies: {sum(counts.values())}")
    print(f"Byte-identical round trips: {sum(counts.values())}")
    for type_id in sorted(CODECS):
        length_text = ",".join(
            f"{length}:{count}" for length, count in sorted(lengths[type_id].items())
        )
        print(
            f"  type={type_id:#06x} bodies={counts[type_id]} "
            f"lengths={length_text or '-'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
