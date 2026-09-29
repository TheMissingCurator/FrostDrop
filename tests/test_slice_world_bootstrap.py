#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_DIR / "tools" / "slice-world-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("slice_world_bootstrap", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

from isac_backend import WorldReplay  # noqa: E402
from isac_protocol import MessageFrame, encode_length_prefixed_frame  # noqa: E402


def main() -> None:
    initial = (
        encode_length_prefixed_frame(MessageFrame(0x0002, b"sync"))
        + encode_length_prefixed_frame(MessageFrame(0x0012, b"gate"))
    )
    later = encode_length_prefixed_frame(MessageFrame(0x0048, b"later"))
    split = len(later) // 2
    wire = struct.pack("<8sIIQII", b"ISACWBS1", 1, 32, 99, 1, 0)
    wire += struct.pack("<QII", 10, len(initial), 0x0F) + initial
    wire += struct.pack("<QII", 20, split, 0x02) + later[:split]
    wire += struct.pack("<QII", 30, len(later) - split, 0x04) + later[split:]

    sliced, selected_delta, frame_count = MODULE.slice_capture(wire, 25)
    replay = WorldReplay.from_bytes(sliced)
    assert selected_delta == 10
    assert frame_count == 2
    assert replay.duration_ms == 10
    assert replay.frame_count == 2

    complete, selected_delta, frame_count = MODULE.slice_capture(wire, 30)
    replay = WorldReplay.from_bytes(complete)
    assert selected_delta == 30
    assert frame_count == 3
    assert replay.frame_count == 3


if __name__ == "__main__":
    main()
