#!/usr/bin/env python3
"""Summarize payload-free port-27015 certificate-read events."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


READ_PATTERN = re.compile(
    r"^TCTD_CERT_READ "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"detail=sequence=(?P<sequence>\d+),"
    r"instruction-rva=(?P<scope>set|outside-game)"
    r"(?:,instruction=(?P<instruction>0x[0-9a-fA-F]+))?,"
    r"caller-count=(?P<count>\d+),"
    r"caller-rvas=(?P<callers>none|0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*),"
    r"payloads=disabled$"
)


@dataclass(frozen=True)
class CertRead:
    tick: int
    process: int
    thread: int
    sequence: int
    instruction: int | None
    callers: tuple[int, ...]


def parse_log(path: Path) -> tuple[list[CertRead], Counter[str], list[str]]:
    reads: list[CertRead] = []
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
        if event == "TCTD_CERT_PROBE_ERROR":
            errors.append(line)
            continue
        if event != "TCTD_CERT_READ":
            continue
        match = READ_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed TCTD_CERT_READ on line {line_number}")
        callers = () if match["callers"] == "none" else tuple(
            int(value, 16) for value in match["callers"].split(",")
        )
        if len(callers) != int(match["count"]):
            raise ValueError(f"caller-count mismatch on line {line_number}")
        instruction = (
            int(match["instruction"], 16)
            if match["instruction"] is not None
            else None
        )
        if (match["scope"] == "set") != (instruction is not None):
            raise ValueError(f"instruction scope mismatch on line {line_number}")
        reads.append(
            CertRead(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                sequence=int(match["sequence"]),
                instruction=instruction,
                callers=callers,
            )
        )
    return reads, events, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        reads, events, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    instructions = Counter(
        read.instruction for read in reads if read.instruction is not None
    )
    caller_chains = Counter(read.callers for read in reads if read.callers)
    print(f"Log: {args.log}")
    print(f"Probe ready events: {events['TCTD_CERT_PROBE_READY']}")
    print(f"Watch armed events: {events['TCTD_CERT_WATCH_ARMED']}")
    print(f"Certificate read events: {len(reads)}")
    print(f"Read-limit events: {events['TCTD_CERT_READ_LIMIT']}")
    print(f"Probe errors: {events['TCTD_CERT_PROBE_ERROR']}")
    print(f"Unique in-game instructions: {len(instructions)}")
    print(f"Unique game caller chains: {len(caller_chains)}")
    for error in errors:
        print(f"ERROR: {error}")
    for instruction, count in instructions.most_common():
        print(f"INSTRUCTION 0x{instruction:x} hits={count}")
    for callers, count in caller_chains.most_common():
        chain = " -> ".join(f"0x{rva:x}" for rva in callers)
        print(f"CALLERS hits={count} {chain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
