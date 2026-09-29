#!/usr/bin/env python3
"""Summarize the payload-free, copy-following TCTD certificate flow."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


FLOW_PATTERN = re.compile(
    r"^TCTD_CERT_FLOW "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"detail=sequence=(?P<sequence>\d+),generation=(?P<generation>\d+),"
    r"instruction-rva=(?P<scope>set|outside-game)"
    r"(?:,instruction=(?P<instruction>0x[0-9a-fA-F]+))?,"
    r"access=(?P<access>copy-source|copy-destination|consumer),"
    r"action=(?P<action>followed|retained),"
    r"copy-relative-offset=(?P<relative>none|\d+),"
    r"copy-length=(?P<length>none|\d+),"
    r"consumer-rva=(?P<consumer>none|0x[0-9a-fA-F]+),"
    r"caller-count=(?P<count>\d+),"
    r"caller-rvas=(?P<callers>none|0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*),"
    r"payloads=disabled$"
)
CODE_PATTERN = re.compile(
    r"^CODE .* label=tctd-cert-flow-consumer-(?P<index>\d+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
DECISION_CODE_PATTERN = re.compile(
    r"^CODE .* label=(?P<label>tctd-flow-[a-z0-9-]+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class FlowEvent:
    tick: int
    process: int
    thread: int
    sequence: int
    generation: int
    instruction: int | None
    access: str
    action: str
    relative_offset: int | None
    copy_length: int | None
    consumer: int | None
    callers: tuple[int, ...]


def parse_log(path: Path) -> tuple[list[FlowEvent], Counter[str], list[str]]:
    flows: list[FlowEvent] = []
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
        if event in {"TCTD_CERT_FLOW_ERROR", "TCTD_CERT_PROBE_ERROR"}:
            errors.append(line)
            continue
        if event != "TCTD_CERT_FLOW":
            continue
        match = FLOW_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed TCTD_CERT_FLOW on line {line_number}")
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
        relative = None if match["relative"] == "none" else int(match["relative"])
        length = None if match["length"] == "none" else int(match["length"])
        consumer = None if match["consumer"] == "none" else int(match["consumer"], 16)
        if match["access"] == "consumer" and (relative is not None or length is not None):
            raise ValueError(f"consumer has copy metadata on line {line_number}")
        if match["access"] != "consumer" and (relative is None or length is None):
            raise ValueError(f"copy event lacks copy metadata on line {line_number}")
        flows.append(
            FlowEvent(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                sequence=int(match["sequence"]),
                generation=int(match["generation"]),
                instruction=instruction,
                access=match["access"],
                action=match["action"],
                relative_offset=relative,
                copy_length=length,
                consumer=consumer,
                callers=callers,
            )
        )
    return flows, events, errors


def parse_code_log(path: Path) -> list[tuple[int, int, int, int]]:
    windows: list[tuple[int, int, int, int]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = CODE_PATTERN.fullmatch(raw_line.strip())
        if match is None:
            continue
        data = bytes.fromhex(match["bytes"])
        length = int(match["length"])
        if len(data) != length:
            raise ValueError("certificate-flow code-window length mismatch")
        windows.append(
            (
                int(match["index"]),
                int(match["target"], 16),
                int(match["start"], 16),
                length,
            )
        )
    return windows


def parse_decision_code_log(path: Path) -> list[tuple[str, int, int, int]]:
    windows: list[tuple[str, int, int, int]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = DECISION_CODE_PATTERN.fullmatch(raw_line.strip())
        if match is None:
            continue
        data = bytes.fromhex(match["bytes"])
        length = int(match["length"])
        if len(data) != length:
            raise ValueError("certificate-flow decision-window length mismatch")
        windows.append(
            (
                match["label"],
                int(match["target"], 16),
                int(match["start"], 16),
                length,
            )
        )
    return windows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--code-log", type=Path)
    args = parser.parse_args()
    try:
        flows, events, errors = parse_log(args.log)
        windows = parse_code_log(args.code_log) if args.code_log else []
        decision_windows = (
            parse_decision_code_log(args.code_log) if args.code_log else []
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    consumers = Counter(flow.consumer for flow in flows if flow.consumer is not None)
    instructions = Counter(flow.instruction for flow in flows if flow.instruction is not None)
    caller_chains = Counter(flow.callers for flow in flows if flow.callers)
    print(f"Log: {args.log}")
    print(f"Flow ready events: {events['TCTD_CERT_FLOW_READY']}")
    print(f"Watch armed events: {events['TCTD_CERT_WATCH_ARMED']}")
    print(f"Flow events: {len(flows)}")
    print(f"Copy-source events: {sum(flow.access == 'copy-source' for flow in flows)}")
    print(f"Follow hops: {sum(flow.action == 'followed' for flow in flows)}")
    print(f"Consumer events: {sum(flow.access == 'consumer' for flow in flows)}")
    print(f"Unique consumer functions: {len(consumers)}")
    print(f"Consumer code windows: {len(windows)}")
    print(f"Decision code windows: {len(decision_windows)}")
    print(f"Unique in-game instructions: {len(instructions)}")
    print(f"Unique caller chains: {len(caller_chains)}")
    print(f"Flow-limit events: {events['TCTD_CERT_FLOW_LIMIT']}")
    print(f"Probe errors: {len(errors)}")
    for error in errors:
        print(f"ERROR: {error}")
    for consumer, count in consumers.most_common():
        print(f"CONSUMER 0x{consumer:x} hits={count}")
    for index, target, start, length in windows:
        print(
            f"CODE index={index} target=0x{target:x} "
            f"start=0x{start:x} length={length}"
        )
    for label, target, start, length in decision_windows:
        print(
            f"DECISION_CODE label={label} target=0x{target:x} "
            f"start=0x{start:x} length={length}"
        )
    for flow in flows:
        instruction = "outside-game" if flow.instruction is None else f"0x{flow.instruction:x}"
        consumer = "none" if flow.consumer is None else f"0x{flow.consumer:x}"
        callers = "none" if not flow.callers else " -> ".join(
            f"0x{rva:x}" for rva in flow.callers
        )
        print(
            f"FLOW seq={flow.sequence} generation={flow.generation} "
            f"instruction={instruction} access={flow.access} "
            f"action={flow.action} consumer={consumer} callers={callers}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
