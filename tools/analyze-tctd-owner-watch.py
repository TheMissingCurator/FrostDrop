#!/usr/bin/env python3
"""Summarize the read-only TCTD decision-owner lifecycle probe."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


WRITE_PATTERN = re.compile(
    r"^TCTD_OWNER_(?P<kind>FIELD|STATE)_WRITE .*?"
    r"detail=sequence=(?P<sequence>\d+),.*?"
    r"resume-rva=(?P<scope>set|outside-game)"
    r"(?:,resume=(?P<resume>0x[0-9a-fA-F]+))?,"
    r"caller-count=(?P<count>\d+),"
    r"caller-rvas=(?P<callers>none|0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*),"
    r"mutation=disabled,payloads=disabled$"
)


@dataclass(frozen=True)
class OwnerWrite:
    kind: str
    sequence: int
    resume: int | None
    callers: tuple[int, ...]


def parse_log(path: Path) -> tuple[list[OwnerWrite], Counter[str], list[str]]:
    writes: list[OwnerWrite] = []
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
        if event == "TCTD_OWNER_WATCH_ERROR":
            errors.append(line)
            continue
        if event not in {"TCTD_OWNER_FIELD_WRITE", "TCTD_OWNER_STATE_WRITE"}:
            continue
        match = WRITE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed {event} on line {line_number}")
        callers = () if match["callers"] == "none" else tuple(
            int(value, 16) for value in match["callers"].split(",")
        )
        if len(callers) != int(match["count"]):
            raise ValueError(f"caller-count mismatch on line {line_number}")
        resume = int(match["resume"], 16) if match["resume"] else None
        if (match["scope"] == "set") != (resume is not None):
            raise ValueError(f"resume scope mismatch on line {line_number}")
        writes.append(
            OwnerWrite(
                kind=match["kind"].lower(),
                sequence=int(match["sequence"]),
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

    sites = Counter((item.kind, item.resume) for item in writes)
    chains = Counter((item.kind, item.resume, item.callers) for item in writes)
    print(f"Log: {args.log}")
    print(f"Probe ready events: {events['TCTD_OWNER_WATCH_READY']}")
    print(f"Decision armed events: {events['TCTD_OWNER_WATCH_ARMED']}")
    print(f"Decision events: {events['TCTD_OWNER_DECISION']}")
    print(f"Owner-field writes: {events['TCTD_OWNER_FIELD_WRITE']}")
    print(f"State writes: {events['TCTD_OWNER_STATE_WRITE']}")
    print(f"Limit events: {events['TCTD_OWNER_WATCH_LIMIT']}")
    print(f"Probe errors: {len(errors)}")
    for error in errors:
        print(f"ERROR: {error}")
    for (kind, resume), count in sites.most_common():
        location = f"0x{resume:x}" if resume is not None else "outside-game"
        print(f"WRITE kind={kind} resume={location} hits={count}")
    for (kind, resume, callers), count in chains.most_common():
        location = f"0x{resume:x}" if resume is not None else "outside-game"
        chain = " -> ".join(f"0x{rva:x}" for rva in callers) or "none"
        print(
            f"CALLERS kind={kind} resume={location} hits={count} {chain}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
