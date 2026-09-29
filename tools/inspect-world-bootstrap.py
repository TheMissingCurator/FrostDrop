#!/usr/bin/env python3
"""Inspect a private timed world-bootstrap capture without printing bytes."""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import InboundFrameStreamDecoder  # noqa: E402


MAGIC = b"ISACWBS1"
HEADER = struct.Struct("<8sIIQII")
RECORD = struct.Struct("<QII")
FLAG_SYNC = 0x01
FLAG_DELIVERY_START = 0x02
FLAG_DELIVERY_END = 0x04
FLAG_GATE_COMPLETE = 0x08


class TimedSpan(NamedTuple):
    delta_ms: int
    flags: int
    data: bytes


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def decode_capture(wire: bytes) -> tuple[int, int, tuple[TimedSpan, ...]]:
    if len(wire) < HEADER.size:
        raise ValueError("capture is shorter than its header")
    magic, version, header_size, request_tick, format_flags, reserved = HEADER.unpack_from(
        wire
    )
    if magic != MAGIC:
        raise ValueError("capture magic is not ISACWBS1")
    if version != 1 or header_size != HEADER.size:
        raise ValueError("unsupported world-bootstrap capture version")
    if format_flags != 1 or reserved != 0:
        raise ValueError("unsupported world-bootstrap capture flags")
    spans: list[TimedSpan] = []
    offset = header_size
    while offset < len(wire):
        if len(wire) - offset < RECORD.size:
            raise ValueError("truncated timed-span header")
        delta_ms, length, flags = RECORD.unpack_from(wire, offset)
        offset += RECORD.size
        end = offset + length
        if end > len(wire):
            raise ValueError("truncated timed-span payload")
        spans.append(TimedSpan(delta_ms, flags, wire[offset:end]))
        offset = end
    return request_tick, format_flags, tuple(spans)


def describe_capture(wire: bytes) -> list[str]:
    request_tick, _, spans = decode_capture(wire)
    decoder = InboundFrameStreamDecoder(maximum_frame_length=16_777_216)
    frames: list[tuple[int, object]] = []
    stream_hash = hashlib.sha256()
    gate_flag_records = 0
    for span in spans:
        stream_hash.update(span.data)
        gate_flag_records += bool(span.flags & FLAG_GATE_COMPLETE)
        frames.extend((span.delta_ms, frame) for frame in decoder.feed(span.data))

    gate_index = next(
        (index for index, (_, frame) in enumerate(frames) if frame.type_id == 0x0012),
        None,
    )
    counts = Counter(frame.type_id for _, frame in frames)
    lines = [
        f"capture: format=ISACWBS1 request_tick_ms={request_tick} "
        f"records={len(spans)} payload_bytes={sum(len(span.data) for span in spans)}",
        f"capture: duration_ms={spans[-1].delta_ms if spans else 0} "
        f"sha256={hashlib.sha256(wire).hexdigest()}",
        f"stream: sha256={stream_hash.hexdigest()} frames={len(frames)} "
        f"unique_types={len(counts)} buffered_bytes={decoder.buffered_bytes}",
        f"records: sync={sum(bool(span.flags & FLAG_SYNC) for span in spans)} "
        f"delivery_starts={sum(bool(span.flags & FLAG_DELIVERY_START) for span in spans)} "
        f"delivery_ends={sum(bool(span.flags & FLAG_DELIVERY_END) for span in spans)} "
        f"gate_complete={gate_flag_records}",
    ]
    if gate_index is None:
        lines.append("gate: first_type_0x0012=absent capture_status=incomplete")
        before_gate = frames
    else:
        gate_delta, gate_frame = frames[gate_index]
        lines.append(
            f"gate: first_type_0x0012_frame={gate_index + 1} "
            f"delta_ms={gate_delta} body_length={len(gate_frame.body)} "
            f"body_sha256_16={fingerprint(gate_frame.body)}"
        )
        before_gate = frames[:gate_index]
        after_gate = frames[gate_index + 1 :]
        after_counts = Counter(frame.type_id for _, frame in after_gate)
        if len(after_gate) <= 32:
            lines.append(
                "post_gate: "
                f"frames={len(after_gate)} types="
                + (
                    ",".join(f"{frame.type_id:#06x}" for _, frame in after_gate)
                    if after_gate
                    else "none"
                )
            )
        else:
            lines.append(
                "post_gate: "
                f"frames={len(after_gate)} unique_types={len(after_counts)} "
                f"body_bytes={sum(len(frame.body) for _, frame in after_gate)} "
                f"duration_ms={spans[-1].delta_ms - gate_delta}"
            )
            lines.append(
                "post_gate_type_counts: "
                + ",".join(
                    f"{type_id:#06x}={count}"
                    for type_id, count in sorted(after_counts.items())
                )
            )
    before_counts = Counter(frame.type_id for _, frame in before_gate)
    lines.append(
        "pre_gate: "
        f"frames={len(before_gate)} unique_types={len(before_counts)} "
        f"body_bytes={sum(len(frame.body) for _, frame in before_gate)} "
        f"type_0x0102={before_counts[0x0102]} "
        f"type_0x0100={before_counts[0x0100]}"
    )
    significant = [
        (delta, frame)
        for delta, frame in before_gate
        if frame.type_id not in (0x0100, 0x0102)
    ]
    for index, (delta, frame) in enumerate(significant[:16], start=1):
        lines.append(
            f"significant[{index}]: delta_ms={delta} type={frame.type_id:#06x} "
            f"body_length={len(frame.body)} "
            f"body_sha256_16={fingerprint(frame.body)}"
        )
    lines.append(
        "type_counts: "
        + ",".join(f"{type_id:#06x}={count}" for type_id, count in sorted(counts.items()))
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
