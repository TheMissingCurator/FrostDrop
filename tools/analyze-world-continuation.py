#!/usr/bin/env python3
"""Correlate a private world continuation with payload-free action markers."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, NamedTuple


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import InboundFrameStreamDecoder  # noqa: E402


INSPECTOR_PATH = PROJECT_DIR / "tools" / "inspect-world-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("inspect_world_bootstrap", INSPECTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
INSPECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECTOR)

KEY_VALUE = re.compile(r"(?:^| )([a-z_]+)=([^ ]*)")


class Marker(NamedTuple):
    label: str
    delta_ms: int


class MetadataRecord(NamedTuple):
    delta_ms: int
    direction: str
    stream_id: str
    channel: str
    types: tuple[int, ...]


def parse_markers(path: Path) -> tuple[Marker, ...]:
    markers: list[Marker] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            value = row.get("world_delta_ms", "-")
            if value == "-" or not value.isdigit():
                continue
            markers.append(Marker(row["label"], int(value)))
    return tuple(markers)


def parse_metadata(path: Path, request_tick: int) -> tuple[MetadataRecord, ...]:
    records: list[MetadataRecord] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("BOOTSTRAP_RECORD "):
            continue
        fields = dict(KEY_VALUE.findall(line))
        tick = fields.get("tick_ms", "")
        if not tick.isdigit():
            continue
        types = tuple(
            int(value, 16)
            for value in fields.get("frame_types", "-").split(",")
            if value.startswith("0x")
        )
        records.append(
            MetadataRecord(
                delta_ms=int(tick) - request_tick,
                direction=fields.get("direction", "unknown"),
                stream_id=fields.get("stream_id", "-"),
                channel=fields.get("channel", "-"),
                types=types,
            )
        )
    return tuple(records)


def summarize_counts(values: Iterable[int]) -> str:
    counts = Counter(values)
    return ",".join(
        f"{type_id:#06x}={count}" for type_id, count in sorted(counts.items())
    ) or "none"


def describe_window(
    label: str,
    start_ms: int,
    end_ms: int,
    inbound: tuple[tuple[int, int], ...],
    metadata: tuple[MetadataRecord, ...],
) -> str:
    inbound_types = [
        type_id for delta, type_id in inbound if start_ms <= delta <= end_ms
    ]
    selected = [record for record in metadata if start_ms <= record.delta_ms <= end_ms]
    outbound_types = [
        type_id
        for record in selected
        if record.direction == "outbound"
        for type_id in record.types
    ]
    inbound_metadata_types = [
        type_id
        for record in selected
        if record.direction == "inbound"
        for type_id in record.types
    ]
    channels = Counter(
        record.channel
        for record in selected
        if record.direction == "outbound" and record.channel != "-"
    )
    streams = Counter(record.stream_id for record in selected)
    return (
        f"window={label} start_ms={start_ms} end_ms={end_ms} "
        f"inbound_frames={len(inbound_types)} "
        f"inbound_types={summarize_counts(inbound_types)} "
        f"outbound_frames={len(outbound_types)} "
        f"outbound_types={summarize_counts(outbound_types)} "
        f"metadata_inbound_types={summarize_counts(inbound_metadata_types)} "
        f"outbound_channels="
        + (",".join(f"{key}={value}" for key, value in sorted(channels.items())) or "none")
        + " streams="
        + (",".join(f"{key}={value}" for key, value in sorted(streams.items())) or "none")
    )


def analyze(
    capture_path: Path,
    markers_path: Path,
    plaintext_path: Path,
    radius_ms: int,
) -> list[str]:
    request_tick, _, spans = INSPECTOR.decode_capture(capture_path.read_bytes())
    decoder = InboundFrameStreamDecoder(maximum_frame_length=16_777_216)
    inbound: list[tuple[int, int]] = []
    for span in spans:
        inbound.extend((span.delta_ms, frame.type_id) for frame in decoder.feed(span.data))
    markers = parse_markers(markers_path)
    metadata = parse_metadata(plaintext_path, request_tick)
    lines = [
        f"continuation: markers={len(markers)} inbound_frames={len(inbound)} "
        f"metadata_records={len(metadata)} buffered_bytes={decoder.buffered_bytes}"
    ]
    gate_delta = next(
        (delta for delta, type_id in inbound if type_id == 0x0012),
        None,
    )
    if markers and gate_delta is not None and gate_delta <= markers[0].delta_ms:
        lines.append(
            describe_window(
                f"startup_to:{markers[0].label}",
                gate_delta,
                markers[0].delta_ms,
                tuple(inbound),
                metadata,
            )
        )
    for marker in markers:
        lines.append(
            describe_window(
                f"around:{marker.label}",
                max(0, marker.delta_ms - radius_ms),
                marker.delta_ms + radius_ms,
                tuple(inbound),
                metadata,
            )
        )
    open_windows: dict[str, Marker] = {}
    for marker in markers:
        if marker.label.startswith("begin_"):
            open_windows[marker.label[6:]] = marker
        elif marker.label.startswith("end_"):
            name = marker.label[4:]
            start = open_windows.pop(name, None)
            if start is not None and start.delta_ms <= marker.delta_ms:
                lines.append(
                    describe_window(
                        f"action:{name}",
                        start.delta_ms,
                        marker.delta_ms,
                        tuple(inbound),
                        metadata,
                    )
                )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("markers", type=Path)
    parser.add_argument("plaintext_log", type=Path)
    parser.add_argument("--radius-ms", type=int, default=3000)
    args = parser.parse_args()
    if args.radius_ms < 0:
        parser.error("--radius-ms must be non-negative")
    try:
        for line in analyze(
            args.capture,
            args.markers,
            args.plaintext_log,
            args.radius_ms,
        ):
            print(line)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
