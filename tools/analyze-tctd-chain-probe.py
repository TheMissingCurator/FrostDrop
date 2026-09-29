#!/usr/bin/env python3
"""Summarize the staged TCTD certificate-processing return chain."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


CHECKPOINT_PATTERN = re.compile(
    r"^TCTD_CHAIN_CHECKPOINT "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"detail=sequence=(?P<sequence>\d+),"
    r"checkpoint=(?P<checkpoint>[a-z0-9-]+),"
    r"rax-class=(?P<rax_class>zero|u8|u16|u32|wide),"
    r"rax-low32=(?P<rax_low32>0x[0-9a-fA-F]{8}),"
    r"zf=(?P<zf>[01]),cf=(?P<cf>[01]),sf=(?P<sf>[01]),"
    r"caller-count=(?P<count>\d+),"
    r"caller-rvas=(?P<callers>none|0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*),"
    r"mutation=disabled,payloads=disabled$"
)
CODE_PATTERN = re.compile(
    r"^CODE .* label=(?P<label>tctd-chain-[a-z0-9-]+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class Checkpoint:
    sequence: int
    name: str
    rax_class: str
    rax_low32: int
    zf: int
    cf: int
    sf: int
    callers: tuple[int, ...]


def parse_stack_log(path: Path) -> tuple[list[Checkpoint], Counter[str], list[str]]:
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
        if event in {"TCTD_CHAIN_PROBE_ERROR", "TCTD_CERT_PROBE_ERROR"}:
            errors.append(line)
            continue
        if event != "TCTD_CHAIN_CHECKPOINT":
            continue
        match = CHECKPOINT_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(
                f"malformed TCTD_CHAIN_CHECKPOINT on line {line_number}"
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
                rax_class=match["rax_class"],
                rax_low32=int(match["rax_low32"], 16),
                zf=int(match["zf"]),
                cf=int(match["cf"]),
                sf=int(match["sf"]),
                callers=callers,
            )
        )
    return checkpoints, events, errors


def parse_code_log(path: Path | None) -> dict[str, tuple[int, int, int]]:
    windows: dict[str, tuple[int, int, int]] = {}
    if path is None or not path.exists():
        return windows
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if " label=tctd-chain-" not in line:
            continue
        match = CODE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed chain CODE window on line {line_number}")
        length = int(match["length"])
        if len(match["bytes"]) // 2 != length:
            raise ValueError(f"code-window length mismatch on line {line_number}")
        windows[match["label"]] = (
            int(match["target"], 16),
            int(match["start"], 16),
            length,
        )
    return windows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stack_log", type=Path)
    parser.add_argument("--code-log", type=Path)
    args = parser.parse_args()
    try:
        checkpoints, events, errors = parse_stack_log(args.stack_log)
        windows = parse_code_log(args.code_log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    states = Counter(
        (event.name, event.rax_class, event.rax_low32, event.zf, event.cf, event.sf)
        for event in checkpoints
    )
    chains = Counter((event.name, event.callers) for event in checkpoints)
    print(f"Stack log: {args.stack_log}")
    print(f"Code log: {args.code_log if args.code_log else 'not supplied'}")
    print(f"Probe ready events: {events['TCTD_CHAIN_PROBE_READY']}")
    print(f"Code-captured events: {events['TCTD_CHAIN_CODE_CAPTURED']}")
    print(f"Certificate watch events: {events['TCTD_CERT_WATCH_ARMED']}")
    print(f"Chain checkpoints: {len(checkpoints)}")
    print(f"Chain-stage events: {events['TCTD_CHAIN_STAGE']}")
    print(f"Chain-complete events: {events['TCTD_CHAIN_COMPLETE']}")
    print(f"Chain-limit events: {events['TCTD_CHAIN_LIMIT']}")
    print(f"Probe errors: {len(errors)}")
    print(f"Code windows: {len(windows)}")
    for error in errors:
        print(f"ERROR: {error}")
    for label, (target, start, length) in sorted(windows.items()):
        print(f"CODE {label} target=0x{target:x} start=0x{start:x} length={length}")
    for (name, rax_class, low32, zf, cf, sf), count in states.most_common():
        print(
            f"STATE {name} hits={count} rax={rax_class}/0x{low32:08x} "
            f"zf={zf} cf={cf} sf={sf}"
        )
    for (name, callers), count in chains.most_common():
        chain = " -> ".join(f"0x{rva:x}" for rva in callers) or "none"
        print(f"CALLERS {name} hits={count} {chain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
