#!/usr/bin/env python3
"""Summarize the bounded TCTD asynchronous completion-path probe."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


CHECKPOINT_PATTERN = re.compile(
    r"^TCTD_COMPLETION_CHECKPOINT .*?"
    r"detail=sequence=(?P<sequence>\d+),"
    r"checkpoint=(?P<checkpoint>[a-z0-9-]+),"
    r"state=(?P<state>null|readable|unreadable),"
    r"state-byte=(?P<state_byte>zero|nonzero|unreadable),"
    r"rax-class=(?P<rax_class>zero|u8|u16|u32|wide),"
    r"rax-low32=(?P<rax_low32>0x[0-9a-fA-F]{8}),"
    r"zf=(?P<zf>[01]),cf=(?P<cf>[01]),sf=(?P<sf>[01]),"
    r"caller-count=(?P<count>\d+),"
    r"caller-rvas=(?P<callers>none|0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*),"
    r"mutation=disabled,payloads=disabled$"
)
CODE_PATTERN = re.compile(
    r"^CODE .* label=(?P<label>tctd-completion-region-\d+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class Checkpoint:
    sequence: int
    name: str
    state: str
    state_byte: str
    rax_class: str
    rax_low32: int
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
        if event == "TCTD_COMPLETION_PROBE_ERROR":
            errors.append(line)
            continue
        if event != "TCTD_COMPLETION_CHECKPOINT":
            continue
        match = CHECKPOINT_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(
                f"malformed TCTD_COMPLETION_CHECKPOINT on line {line_number}"
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
                state=match["state"],
                state_byte=match["state_byte"],
                rax_class=match["rax_class"],
                rax_low32=int(match["rax_low32"], 16),
                callers=callers,
            )
        )
    return checkpoints, events, errors


def parse_code_log(path: Path | None) -> list[tuple[str, int, bytes]]:
    windows: list[tuple[str, int, bytes]] = []
    if path is None or not path.exists():
        return windows
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if " label=tctd-completion-region-" not in line:
            continue
        match = CODE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(
                f"malformed completion CODE window on line {line_number}"
            )
        data = bytes.fromhex(match["bytes"])
        if len(data) != int(match["length"]):
            raise ValueError(f"code-window length mismatch on line {line_number}")
        windows.append((match["label"], int(match["start"], 16), data))
    return sorted(windows, key=lambda item: item[1])


def reconstruct(windows: list[tuple[str, int, bytes]]) -> tuple[int, bytes]:
    if not windows:
        raise ValueError("no completion code windows found")
    origin = windows[0][1]
    cursor = origin
    chunks: list[bytes] = []
    for _label, start, data in windows:
        if start != cursor:
            raise ValueError("completion code windows are not contiguous")
        chunks.append(data)
        cursor += len(data)
    return origin, b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stack_log", type=Path)
    parser.add_argument("--code-log", type=Path)
    parser.add_argument("--output-bin", type=Path)
    args = parser.parse_args()
    try:
        checkpoints, events, errors = parse_stack_log(args.stack_log)
        windows = parse_code_log(args.code_log)
        reconstructed = reconstruct(windows) if windows else None
        if args.output_bin is not None:
            if reconstructed is None:
                raise ValueError("cannot write output without code windows")
            args.output_bin.write_bytes(reconstructed[1])
    except (OSError, ValueError) as error:
        parser.error(str(error))

    states = Counter(
        (item.name, item.state, item.state_byte, item.rax_class, item.rax_low32)
        for item in checkpoints
    )
    chains = Counter((item.name, item.callers) for item in checkpoints)
    print(f"Stack log: {args.stack_log}")
    print(f"Code log: {args.code_log if args.code_log else 'not supplied'}")
    print(f"Probe ready events: {events['TCTD_COMPLETION_PROBE_READY']}")
    print(f"Probe armed events: {events['TCTD_COMPLETION_PROBE_ARMED']}")
    print(f"Code-captured events: {events['TCTD_COMPLETION_CODE_CAPTURED']}")
    print(f"Completion checkpoints: {len(checkpoints)}")
    print(f"Worker-entry hits: {sum(item.name == 'worker-entry' for item in checkpoints)}")
    print(
        "Completion-setter hits: "
        f"{sum(item.name == 'completion-setter' for item in checkpoints)}"
    )
    print(f"Shared-return hits: {sum(item.name == 'shared-return' for item in checkpoints)}")
    print(f"Complete events: {events['TCTD_COMPLETION_COMPLETE']}")
    print(f"Limit events: {events['TCTD_COMPLETION_LIMIT']}")
    print(f"Probe errors: {len(errors)}")
    print(f"Code windows: {len(windows)}")
    if reconstructed is not None:
        print(
            f"Code region: origin=0x{reconstructed[0]:x} "
            f"length={len(reconstructed[1])}"
        )
    if args.output_bin is not None and reconstructed is not None:
        print(f"Reconstructed binary: {args.output_bin}")
    for error in errors:
        print(f"ERROR: {error}")
    for (name, state, state_byte, rax_class, low32), count in states.most_common():
        print(
            f"STATE {name} hits={count} object={state}/{state_byte} "
            f"rax={rax_class}/0x{low32:08x}"
        )
    for (name, callers), count in chains.most_common():
        chain = " -> ".join(f"0x{rva:x}" for rva in callers) or "none"
        print(f"CALLERS {name} hits={count} {chain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
