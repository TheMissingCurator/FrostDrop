#!/usr/bin/env python3
"""Slice a private ISACWBS1 capture at a labeled complete-frame boundary."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import os
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_backend import WorldReplay  # noqa: E402
from isac_protocol import DecodeError, InboundFrameStreamDecoder  # noqa: E402


INSPECTOR_PATH = PROJECT_DIR / "tools" / "inspect-world-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("inspect_world_bootstrap", INSPECTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
INSPECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECTOR)


def marker_delta(path: Path, label: str) -> int:
    matches: list[int] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            if row.get("label") != label:
                continue
            value = row.get("world_delta_ms", "-")
            if not value.isdigit():
                raise ValueError(f"marker {label!r} has no world-relative timestamp")
            matches.append(int(value))
    if not matches:
        raise ValueError(f"marker {label!r} was not found")
    if len(matches) != 1:
        raise ValueError(f"marker {label!r} is not unique")
    return matches[0]


def encode_capture(request_tick: int, format_flags: int, spans: tuple[object, ...]) -> bytes:
    wire = bytearray(
        INSPECTOR.HEADER.pack(
            INSPECTOR.MAGIC,
            1,
            INSPECTOR.HEADER.size,
            request_tick,
            format_flags,
            0,
        )
    )
    for span in spans:
        wire.extend(INSPECTOR.RECORD.pack(span.delta_ms, len(span.data), span.flags))
        wire.extend(span.data)
    return bytes(wire)


def slice_capture(wire: bytes, target_delta_ms: int) -> tuple[bytes, int, int]:
    request_tick, format_flags, spans = INSPECTOR.decode_capture(wire)
    decoder = InboundFrameStreamDecoder(maximum_frame_length=16_777_216)
    safe_span_count = 0
    safe_frame_count = 0
    frame_count = 0
    try:
        for index, span in enumerate(spans):
            if span.delta_ms > target_delta_ms:
                break
            frame_count += len(decoder.feed(span.data))
            if decoder.buffered_bytes == 0:
                safe_span_count = index + 1
                safe_frame_count = frame_count
    except DecodeError as error:
        raise ValueError(f"capture stream is invalid: {error}") from error
    if safe_span_count == 0:
        raise ValueError("no complete-frame boundary exists at or before the marker")
    selected = spans[:safe_span_count]
    result = encode_capture(request_tick, format_flags, selected)
    WorldReplay.from_bytes(result)
    return result, selected[-1].delta_ms, safe_frame_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("markers", type=Path)
    parser.add_argument("label")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        target = marker_delta(args.markers, args.label)
        sliced, selected_delta, frame_count = slice_capture(
            args.capture.read_bytes(),
            target,
        )
        descriptor = os.open(
            args.output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(sliced)
        except BaseException:
            args.output.unlink(missing_ok=True)
            raise
    except (OSError, ValueError) as error:
        parser.error(str(error))
    replay = WorldReplay.from_bytes(sliced)
    print(
        f"slice complete label={args.label} target_ms={target} "
        f"selected_ms={selected_delta} marker_gap_ms={target - selected_delta} "
        f"records={len(replay.spans)} frames={frame_count} "
        f"payload_bytes={replay.payload_bytes} output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
