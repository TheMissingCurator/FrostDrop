#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_DIR / "tools" / "inspect-world-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("inspect_world_bootstrap", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

from isac_protocol import MessageFrame, encode_length_prefixed_frame  # noqa: E402


def main() -> None:
    private_value = b"private-world-value"
    stream = (
        encode_length_prefixed_frame(MessageFrame(0x0002, b"login"))
        + encode_length_prefixed_frame(MessageFrame(0x0102, b""))
        + encode_length_prefixed_frame(MessageFrame(0x0012, private_value))
    )
    split = 7
    wire = struct.pack("<8sIIQII", b"ISACWBS1", 1, 32, 1234, 1, 0)
    wire += struct.pack("<QII", 100, split, 0x07) + stream[:split]
    wire += struct.pack("<QII", 200, len(stream) - split, 0x0E) + stream[split:]
    lines = MODULE.describe_capture(wire)
    output = "\n".join(lines)
    assert "records=2" in output
    assert "frames=3" in output
    assert "first_type_0x0012_frame=3" in output
    assert "delta_ms=200" in output
    assert "post_gate: frames=0 types=none" in output
    assert "capture_status=incomplete" not in output
    assert "private-world-value" not in output


if __name__ == "__main__":
    main()
