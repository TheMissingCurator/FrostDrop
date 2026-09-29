#!/usr/bin/env python3
"""Summarize read-only TCTD validation-state writes."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


WRITE_PATTERN = re.compile(
    r"^TCTD_STATE_WRITE "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"detail=sequence=(?P<sequence>\d+),"
    r"value-after=(?P<value>zero|nonzero),"
    r"resume-rva=(?P<scope>set|outside-game)"
    r"(?:,resume=(?P<resume>0x[0-9a-fA-F]+))?,"
    r"caller-count=(?P<count>\d+),"
    r"caller-rvas=(?P<callers>none|0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*),"
    r"mutation=disabled,payloads=disabled$"
)


@dataclass(frozen=True)
class StateWrite:
    sequence: int
    value: str
    resume: int | None
    callers: tuple[int, ...]


def parse_log(path: Path) -> tuple[list[StateWrite], Counter[str], list[str]]:
    writes: list[StateWrite] = []
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
        if event == "TCTD_STATE_WATCH_ERROR":
            errors.append(line)
            continue
        if event != "TCTD_STATE_WRITE":
            continue
        match = WRITE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed TCTD_STATE_WRITE on line {line_number}")
        callers = () if match["callers"] == "none" else tuple(
            int(value, 16) for value in match["callers"].split(",")
        )
        if len(callers) != int(match["count"]):
            raise ValueError(f"caller-count mismatch on line {line_number}")
        resume = int(match["resume"], 16) if match["resume"] else None
        if (match["scope"] == "set") != (resume is not None):
            raise ValueError(f"resume scope mismatch on line {line_number}")
        writes.append(
            StateWrite(
                sequence=int(match["sequence"]),
                value=match["value"],
                resume=resume,
                callers=callers,
            )
        )
    return writes, events, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        writes, events, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    sites = Counter((item.resume, item.value) for item in writes)
    chains = Counter((item.resume, item.callers) for item in writes)
    print(f"Log: {args.log}")
    print(f"Probe ready events: {events['TCTD_STATE_WATCH_READY']}")
    print(f"Decision armed events: {events['TCTD_STATE_WATCH_ARMED']}")
    print(f"Watch-target events: {events['TCTD_STATE_WATCH_TARGET']}")
    print(f"State-write events: {len(writes)}")
    print(f"Watch-limit events: {events['TCTD_STATE_WATCH_LIMIT']}")
    print(f"Probe errors: {len(errors)}")
    for error in errors:
        print(f"ERROR: {error}")
    for (resume, value), count in sites.most_common():
        location = f"0x{resume:x}" if resume is not None else "outside-game"
        print(f"WRITE resume={location} value-after={value} hits={count}")
    for (resume, callers), count in chains.most_common():
        location = f"0x{resume:x}" if resume is not None else "outside-game"
        chain = " -> ".join(f"0x{rva:x}" for rva in callers) or "none"
        print(f"CALLERS resume={location} hits={count} {chain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
