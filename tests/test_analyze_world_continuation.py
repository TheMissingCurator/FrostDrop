#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import struct
import tempfile
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_DIR / "tools" / "analyze-world-continuation.py"
SPEC = importlib.util.spec_from_file_location("analyze_world_continuation", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

from isac_protocol import MessageFrame, encode_length_prefixed_frame  # noqa: E402


def main() -> None:
    stream = (
        encode_length_prefixed_frame(MessageFrame(0x0002, b"sync"))
        + encode_length_prefixed_frame(MessageFrame(0x0012, b"gate"))
        + encode_length_prefixed_frame(MessageFrame(0x0048, b"region"))
    )
    capture = struct.pack("<8sIIQII", b"ISACWBS1", 1, 32, 1000, 1, 0)
    capture += struct.pack("<QII", 100, len(stream), 0x0F) + stream
    markers = (
        "label\tobserved_at\tprobe_tick_ms\tworld_delta_ms\n"
        "begin_region\t2026-01-01T00:00:00Z\t1050\t50\n"
        "end_region\t2026-01-01T00:00:01Z\t1150\t150\n"
    )
    plaintext = (
        "BOOTSTRAP_RECORD sequence=1 tick_ms=1075 process=1 thread=2 "
        "direction=outbound stream_id=3 length=8 framing=envelope "
        "marker=0x03 channel=0x09 frame_count=1 listed_frames=1 "
        "frame_types=0x0076 frame_lengths=4\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        capture_path = root / "capture.bin"
        marker_path = root / "markers.tsv"
        plaintext_path = root / "plaintext.log"
        capture_path.write_bytes(capture)
        marker_path.write_text(markers)
        plaintext_path.write_text(plaintext)
        output = "\n".join(
            MODULE.analyze(capture_path, marker_path, plaintext_path, 10)
        )
    assert "window=action:region" in output
    assert "inbound_types=0x0002=1,0x0012=1,0x0048=1" in output
    assert "outbound_types=0x0076=1" in output
    assert "outbound_channels=0x09=1" in output


if __name__ == "__main__":
    main()
