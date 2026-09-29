#!/usr/bin/env python3
"""Summarize redacted pre-world bootstrap records and socket activity."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


RECORD_PATTERN = re.compile(
    r"^BOOTSTRAP_RECORD sequence=(?P<sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"direction=(?P<direction>inbound|outbound) stream_id=(?P<stream>\d+) "
    r"length=(?P<length>\d+) framing=(?P<framing>[a-z-]+) "
    r"marker=(?P<marker>-|0x[0-9a-fA-F]+) "
    r"channel=(?P<channel>-|0x[0-9a-fA-F]+) "
    r"frame_count=(?P<frame_count>\d+) listed_frames=(?P<listed>\d+) "
    r"frame_types=(?P<types>-|(?:0x[0-9a-fA-F]+)(?:,0x[0-9a-fA-F]+)*) "
    r"frame_lengths=(?P<lengths>-|(?:\d+)(?:,\d+)*)$"
)
SOCKET_PATTERN = re.compile(
    r"^BOOTSTRAP_SOCKET sequence=(?P<sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"direction=(?P<direction>send|recv) socket_id=(?P<socket>\d+) "
    r"peer_port=(?P<port>\d+)$"
)


@dataclass(frozen=True)
class BootstrapRecord:
    sequence: int
    tick: int
    direction: str
    stream_id: int
    length: int
    framing: str
    marker: int | None
    channel: int | None
    frame_count: int
    frame_types: tuple[int, ...]
    frame_lengths: tuple[int, ...]


@dataclass(frozen=True)
class SocketEvent:
    sequence: int
    tick: int
    direction: str
    socket_id: int
    peer_port: int


def _parse_int_list(value: str, base: int) -> tuple[int, ...]:
    if value == "-":
        return ()
    return tuple(int(item, base) for item in value.split(","))


def parse_log(
    path: Path,
) -> tuple[list[BootstrapRecord], list[SocketEvent], Counter[str], list[str]]:
    records: list[BootstrapRecord] = []
    sockets: list[SocketEvent] = []
    events: Counter[str] = Counter()
    errors: list[str] = []

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line:
            continue
        event = line.split(maxsplit=1)[0]
        events[event] += 1
        if event in {"PLAINTEXT_PROBE_ERROR", "DISPATCH_PROBE_ERROR"}:
            errors.append(line)
            continue
        if event == "BOOTSTRAP_RECORD":
            match = RECORD_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed bootstrap record on line {line_number}")
            frame_types = _parse_int_list(match["types"], 16)
            frame_lengths = _parse_int_list(match["lengths"], 10)
            listed = int(match["listed"])
            if len(frame_types) != listed or len(frame_lengths) != listed:
                raise ValueError(
                    f"listed-frame mismatch on line {line_number}"
                )
            frame_count = int(match["frame_count"])
            if listed > frame_count:
                raise ValueError(f"frame-count mismatch on line {line_number}")
            records.append(
                BootstrapRecord(
                    sequence=int(match["sequence"]),
                    tick=int(match["tick"]),
                    direction=match["direction"],
                    stream_id=int(match["stream"]),
                    length=int(match["length"]),
                    framing=match["framing"],
                    marker=(
                        None if match["marker"] == "-" else int(match["marker"], 16)
                    ),
                    channel=(
                        None
                        if match["channel"] == "-"
                        else int(match["channel"], 16)
                    ),
                    frame_count=frame_count,
                    frame_types=frame_types,
                    frame_lengths=frame_lengths,
                )
            )
        elif event == "BOOTSTRAP_SOCKET":
            match = SOCKET_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed socket event on line {line_number}")
            sockets.append(
                SocketEvent(
                    sequence=int(match["sequence"]),
                    tick=int(match["tick"]),
                    direction=match["direction"],
                    socket_id=int(match["socket"]),
                    peer_port=int(match["port"]),
                )
            )
    return records, sockets, events, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize redacted Division bootstrap framing metadata."
    )
    parser.add_argument("log", type=Path, help="project-isac-plaintext-probe.log")
    parser.add_argument(
        "--timeline",
        action="store_true",
        help="show socket and application records in timestamp order",
    )
    args = parser.parse_args()

    try:
        records, sockets, events, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Armed events: {events['BOOTSTRAP_PROBE_ARMED']}")
    print(f"Ready events: {events['BOOTSTRAP_PROBE_READY']}")
    print(f"World transitions: {events['BOOTSTRAP_PHASE']}")
    print(f"Bootstrap records: {len(records)}")
    print(f"Socket events: {len(sockets)}")
    print(f"Distinct sockets: {len({event.socket_id for event in sockets})}")
    print(
        "Distinct directional streams: "
        f"{len({(record.direction, record.stream_id) for record in records})}"
    )
    print(
        "Framing: "
        + ", ".join(
            f"{name}={count}"
            for name, count in sorted(Counter(r.framing for r in records).items())
        )
    )
    type_counts = Counter(
        (record.direction, type_id)
        for record in records
        for type_id in record.frame_types
    )
    print("Message types:")
    for (direction, type_id), count in sorted(type_counts.items()):
        print(f"  {direction} type={type_id:#06x} count={count}")
    for error in errors:
        print(f"WARNING: {error}")

    if args.timeline:
        timeline = [
            (
                event.tick,
                event.sequence,
                f"socket direction={event.direction} socket={event.socket_id} "
                f"port={event.peer_port}",
            )
            for event in sockets
        ]
        timeline.extend(
            (
                record.tick,
                record.sequence,
                f"record direction={record.direction} stream={record.stream_id} "
                f"length={record.length} framing={record.framing} "
                "types="
                + (
                    ",".join(f"{type_id:#06x}" for type_id in record.frame_types)
                    or "-"
                ),
            )
            for record in records
        )
        print("Timeline:")
        for tick, _, detail in sorted(timeline):
            print(f"  tick_ms={tick} {detail}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
