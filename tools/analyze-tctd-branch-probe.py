#!/usr/bin/env python3
"""Summarize the four-gate TCTD certificate completion branch probe."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


CHECKPOINT_PATTERN = re.compile(
    r"^TCTD_BRANCH_CHECKPOINT .*?"
    r"detail=sequence=(?P<sequence>\d+),"
    r"checkpoint=(?P<checkpoint>[a-z0-9-]+),"
    r"result=(?P<result>zero|nonzero),"
    r"value-low16=(?P<value>0x[0-9a-fA-F]{4}),"
    r"caller-count=(?P<count>\d+),"
    r"caller-rvas=(?P<callers>none|0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*),"
    r"mutation=disabled,payloads=disabled$"
)


@dataclass(frozen=True)
class Checkpoint:
    sequence: int
    name: str
    result: str
    value: int
    callers: tuple[int, ...]


def parse_log(path: Path) -> tuple[list[Checkpoint], Counter[str], list[str]]:
    checkpoints: list[Checkpoint] = []
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
        if event == "TCTD_BRANCH_PROBE_ERROR":
            errors.append(line)
            continue
        if event != "TCTD_BRANCH_CHECKPOINT":
            continue
        match = CHECKPOINT_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(
                f"malformed TCTD_BRANCH_CHECKPOINT on line {line_number}"
            )
        callers = () if match["callers"] == "none" else tuple(
            int(value, 16) for value in match["callers"].split(",")
        )
        if len(callers) != int(match["count"]):
            raise ValueError(f"caller-count mismatch on line {line_number}")
        checkpoints.append(
            Checkpoint(
                sequence=int(match["sequence"]),
                name=match["checkpoint"],
                result=match["result"],
                value=int(match["value"], 16),
                callers=callers,
            )
        )
    return checkpoints, events, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        checkpoints, events, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    states = Counter(
        (item.name, item.result, item.value) for item in checkpoints
    )
    chains = Counter((item.name, item.callers) for item in checkpoints)
    print(f"Log: {args.log}")
    print(f"Probe ready events: {events['TCTD_BRANCH_PROBE_READY']}")
    print(f"Probe armed events: {events['TCTD_BRANCH_PROBE_ARMED']}")
    print(f"Branch checkpoints: {len(checkpoints)}")
    for name in ("operation-ready", "status-ready", "tls-status", "final-helper"):
        print(f"{name} hits: {sum(item.name == name for item in checkpoints)}")
    print(f"Complete events: {events['TCTD_BRANCH_COMPLETE']}")
    print(f"Limit events: {events['TCTD_BRANCH_LIMIT']}")
    print(f"Probe errors: {len(errors)}")
    for error in errors:
        print(f"ERROR: {error}")
    for (name, result, value), count in states.most_common():
        print(
            f"STATE {name} hits={count} result={result} "
            f"value-low16=0x{value:04x}"
        )
    for (name, callers), count in chains.most_common():
        chain = " -> ".join(f"0x{rva:x}" for rva in callers) or "none"
        print(f"CALLERS {name} hits={count} {chain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
