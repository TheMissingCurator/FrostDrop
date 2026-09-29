#!/usr/bin/env python3
"""Summarize bounded serialized records from the plaintext probe."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


RECORD_PATTERN = re.compile(
    r"^PLAINTEXT_(?P<direction>OUT|IN) "
    r"sequence=(?P<sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class PlaintextRecord:
    direction: str
    sequence: int
    tick: int
    process: int
    thread: int
    data: bytes


@dataclass(frozen=True)
class NestedFrame:
    data: bytes
    leading_value: int | None


@dataclass(frozen=True)
class RecordEnvelope:
    marker: int
    channel: int
    body_length: int
    frames: tuple[NestedFrame, ...]


def decode_varuint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    for index in range(offset, min(len(data), offset + 10)):
        byte = data[index]
        value |= (byte & 0x7f) << shift
        if byte & 0x80 == 0:
            return value, index + 1
        shift += 7
    return None


def decode_envelope(data: bytes) -> RecordEnvelope | None:
    if len(data) < 4:
        return None
    decoded_length = decode_varuint(data, 2)
    if decoded_length is None:
        return None
    body_length, body_offset = decoded_length
    if body_offset + body_length != len(data):
        return None
    frames: list[NestedFrame] = []
    offset = body_offset
    while offset < len(data):
        decoded_frame_length = decode_varuint(data, offset)
        if decoded_frame_length is None:
            return None
        encoded_frame_length, frame_offset = decoded_frame_length
        if encoded_frame_length & 1:
            return None
        frame_length = encoded_frame_length >> 1
        frame_end = frame_offset + frame_length
        if frame_end > len(data):
            return None
        frame_data = data[frame_offset:frame_end]
        decoded_leading_value = decode_varuint(frame_data, 0)
        frames.append(
            NestedFrame(
                data=frame_data,
                leading_value=(
                    decoded_leading_value[0]
                    if decoded_leading_value is not None
                    else None
                ),
            )
        )
        offset = frame_end
    return RecordEnvelope(
        marker=data[0],
        channel=data[1],
        body_length=body_length,
        frames=tuple(frames),
    )


def decode_frame(data: bytes) -> NestedFrame | None:
    decoded_length = decode_varuint(data, 0)
    if decoded_length is None:
        return None
    encoded_length, frame_offset = decoded_length
    if encoded_length & 1:
        return None
    frame_length = encoded_length >> 1
    if frame_offset + frame_length != len(data):
        return None
    frame_data = data[frame_offset:]
    decoded_leading_value = decode_varuint(frame_data, 0)
    return NestedFrame(
        data=frame_data,
        leading_value=(
            decoded_leading_value[0]
            if decoded_leading_value is not None
            else None
        ),
    )


def parse_log(path: Path) -> tuple[list[PlaintextRecord], Counter[str], list[str]]:
    records: list[PlaintextRecord] = []
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
        if event == "PLAINTEXT_PROBE_ERROR":
            errors.append(line)
            continue
        if event not in {"PLAINTEXT_OUT", "PLAINTEXT_IN"}:
            continue
        match = RECORD_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed plaintext record on line {line_number}")
        data = bytes.fromhex(match["bytes"])
        if len(data) != int(match["length"]):
            raise ValueError(f"byte-count mismatch on line {line_number}")
        records.append(
            PlaintextRecord(
                direction=(
                    "outbound" if match["direction"] == "OUT" else "inbound"
                ),
                sequence=int(match["sequence"]),
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                data=data,
            )
        )
    return records, events, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize bounded serialized gameplay records."
    )
    parser.add_argument("log", type=Path, help="project-isac-plaintext-probe.log")
    parser.add_argument(
        "--hex-limit",
        type=int,
        default=0,
        help="show at most this many leading bytes per record (default: hidden)",
    )
    parser.add_argument(
        "--families",
        action="store_true",
        help="summarize decoded channel and nested-frame structural families",
    )
    parser.add_argument(
        "--timeline",
        action="store_true",
        help="show the decoded envelope timeline without payload bytes",
    )
    args = parser.parse_args()
    if args.hex_limit < 0:
        parser.error("--hex-limit must not be negative")

    try:
        records, events, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    total_bytes = sum(len(record.data) for record in records)
    printable_bytes = sum(
        byte in {9, 10, 13} or 32 <= byte <= 126
        for record in records
        for byte in record.data
    )
    print(f"Log: {args.log}")
    print(f"Ready events: {events['PLAINTEXT_PROBE_READY']}")
    print(f"Active events: {events['PLAINTEXT_PROBE_ACTIVE']}")
    print(f"Error events: {events['PLAINTEXT_PROBE_ERROR']}")
    print(f"Limit events: {events['PLAINTEXT_PROBE_LIMIT']}")
    print(
        "Outbound records: "
        f"{sum(record.direction == 'outbound' for record in records)}"
    )
    print(
        "Inbound records: "
        f"{sum(record.direction == 'inbound' for record in records)}"
    )
    print(f"Captured bytes: {total_bytes}")
    if records:
        lengths = Counter(len(record.data) for record in records)
        print(f"Minimum record length: {min(lengths)}")
        print(f"Maximum record length: {max(lengths)}")
        print(f"Unique record lengths: {len(lengths)}")
        print(f"Printable-byte ratio: {printable_bytes / total_bytes:.3f}")
    for error in errors:
        print(f"WARNING: {error}")
    envelopes = [
        (
            record,
            decode_envelope(record.data)
            if record.direction == "outbound"
            else None,
        )
        for record in records
    ]
    inbound_frames = [
        (record, decode_frame(record.data))
        for record in records
        if record.direction == "inbound"
    ]
    decoded_count = sum(envelope is not None for _, envelope in envelopes)
    inbound_frame_count = sum(frame is not None for _, frame in inbound_frames)
    outbound_count = sum(record.direction == "outbound" for record in records)
    print(f"Envelope records: {decoded_count}")
    print(f"Undecoded envelope records: {outbound_count - decoded_count}")
    print(f"Inbound frame records: {inbound_frame_count}")
    print(
        "Undecoded inbound frame records: "
        f"{len(inbound_frames) - inbound_frame_count}"
    )
    if args.families:
        families = Counter(
            (
                record.direction,
                envelope.marker,
                envelope.channel,
                tuple(
                    (len(frame.data), frame.leading_value)
                    for frame in envelope.frames
                ),
            )
            for record, envelope in envelopes
            if envelope is not None
        )
        print("Envelope families:")
        for (
            direction,
            marker,
            channel,
            frame_shape,
        ), count in families.most_common():
            frames = ",".join(
                f"{length}:"
                + (
                    f"0x{leading_value:04x}"
                    if leading_value is not None
                    else "none"
                )
                for length, leading_value in frame_shape
            )
            print(
                f"  direction={direction} marker=0x{marker:02x} "
                f"channel=0x{channel:02x} "
                f"frames={frames or 'none'} count={count}"
            )
        frame_families = Counter(
            (len(frame.data), frame.leading_value)
            for _, frame in inbound_frames
            if frame is not None
        )
        print("Inbound frame families:")
        for (length, leading_value), count in frame_families.most_common():
            print(
                f"  length={length} leading="
                + (
                    f"0x{leading_value:04x}"
                    if leading_value is not None
                    else "none"
                )
                + f" count={count}"
            )
    if args.timeline and records:
        first_tick = records[0].tick
        print("Envelope timeline:")
        for record, envelope in envelopes:
            if record.direction == "inbound":
                frame = decode_frame(record.data)
                print(
                    f"  sequence={record.sequence} "
                    f"elapsed-ms={record.tick - first_tick} "
                    "direction=inbound "
                    + (
                        f"frame={len(frame.data)}:"
                        + (
                            f"0x{frame.leading_value:04x}"
                            if frame.leading_value is not None
                            else "none"
                        )
                        if frame is not None
                        else "undecoded"
                    )
                    + f" length={len(record.data)}"
                )
                continue
            if envelope is None:
                print(
                    f"  sequence={record.sequence} "
                    f"elapsed-ms={record.tick - first_tick} undecoded "
                    f"length={len(record.data)}"
                )
                continue
            print(
                f"  sequence={record.sequence} "
                f"elapsed-ms={record.tick - first_tick} "
                f"direction={record.direction} "
                f"channel=0x{envelope.channel:02x} "
                "frames="
                + ",".join(
                    f"{len(frame.data)}:"
                    + (
                        f"0x{frame.leading_value:04x}"
                        if frame.leading_value is not None
                        else "none"
                    )
                    for frame in envelope.frames
                )
                + " "
                f"length={len(record.data)}"
            )
    if args.hex_limit:
        for record in records:
            prefix = record.data[: args.hex_limit].hex()
            suffix = "..." if len(record.data) > args.hex_limit else ""
            print(
                f"{record.direction} sequence={record.sequence} "
                f"tick={record.tick} "
                f"pid={record.process} tid={record.thread} "
                f"length={len(record.data)} bytes={prefix}{suffix}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
