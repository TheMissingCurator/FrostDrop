#!/usr/bin/env python3
"""Summarize Project ISAC's address-only port-55000 stack log."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


STACK_PATTERN = re.compile(
    r"^STACK "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"direction=(?P<direction>send|recv) "
    r"socket=(?P<socket>0x[0-9a-fA-F]+) "
    r"frame_count=(?P<frame_count>\d+) "
    r"rvas=(?P<rvas>0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*)$"
)


@dataclass(frozen=True)
class StackRecord:
    tick: int
    process: int
    thread: int
    direction: str
    socket: str
    rvas: tuple[int, ...]


def parse_log(path: Path) -> tuple[list[StackRecord], Counter[str], list[str]]:
    records: list[StackRecord] = []
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
        if event == "STACK_PROBE_ERROR":
            errors.append(line)
            continue
        if event != "STACK":
            continue

        match = STACK_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed STACK record on line {line_number}")
        rvas = tuple(int(value, 16) for value in match["rvas"].split(","))
        if len(rvas) != int(match["frame_count"]):
            raise ValueError(f"frame-count mismatch on line {line_number}")
        records.append(
            StackRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                direction=match["direction"],
                socket=match["socket"].lower(),
                rvas=rvas,
            )
        )
    return records, events, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize an address-only Project ISAC stack-probe log."
    )
    parser.add_argument("log", type=Path, help="project-isac-stack-probe.log")
    args = parser.parse_args()

    try:
        records, events, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Ready events: {events['STACK_PROBE_READY']}")
    print(f"Error events: {events['STACK_PROBE_ERROR']}")
    print(f"Limit events: {events['STACK_PROBE_LIMIT']}")
    print(f"Unique stack records: {len(records)}")

    for direction in ("send", "recv"):
        selected = [record for record in records if record.direction == direction]
        sockets = sorted({record.socket for record in selected})
        threads = sorted({record.thread for record in selected})
        print(
            f"{direction.title()}: {len(selected)} stacks; "
            f"{len(sockets)} sockets; {len(threads)} threads"
        )

    for error in errors:
        print(f"ERROR: {error}")

    for index, record in enumerate(records, 1):
        rvas = " -> ".join(f"0x{rva:x}" for rva in record.rvas)
        print(
            f"[{index:03d}] {record.direction} tick={record.tick} "
            f"pid={record.process} tid={record.thread} "
            f"socket={record.socket}: {rvas}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
