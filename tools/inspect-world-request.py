#!/usr/bin/env python3
"""Inspect a private post-Continue request without printing payload bytes."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import decode_outbound_envelope  # noqa: E402


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def describe_capture(wire: bytes) -> list[str]:
    envelope = decode_outbound_envelope(wire)
    lines = [
        f"envelope: marker={envelope.marker} channel={envelope.channel} "
        f"wire_length={len(wire)} frames={len(envelope.frames)}",
        f"envelope: sha256={hashlib.sha256(wire).hexdigest()}",
    ]
    for index, frame in enumerate(envelope.frames):
        lines.append(
            f"frame[{index}]: type={frame.type_id:#06x} "
            f"body_length={len(frame.body)} "
            f"body_sha256_16={fingerprint(frame.body)}"
        )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    try:
        for line in describe_capture(args.capture.read_bytes()):
            print(line)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
