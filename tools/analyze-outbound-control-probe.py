#!/usr/bin/env python3
"""Summarize code-only outbound bootstrap paths for types 0x0002 and 0x0005."""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


PATH_PATTERN = re.compile(
    r"^OUTBOUND_CONTROL_PATH sequence=(?P<sequence>\d+) tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"type_id=(?P<type>0x[0-9a-fA-F]+) envelope_length=(?P<length>\d+) "
    r"marker=(?P<marker>0x[0-9a-fA-F]+) channel=(?P<channel>0x[0-9a-fA-F]+) "
    r"boundary_function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"boundary_function_end_rva=(?P<end>0x[0-9a-fA-F]+) "
    r"frame_count=(?P<count>\d+) rvas=(?P<rvas>(?:0x[0-9a-fA-F]+"
    r"(?:,0x[0-9a-fA-F]+)*)?)$"
)
CODE_PATTERN = re.compile(
    r"^OUTBOUND_CONTROL_CODE tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"type_id=(?P<type>0x[0-9a-fA-F]+) "
    r"caller_rva=(?P<caller>0x[0-9a-fA-F]+) "
    r"function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"function_end_rva=(?P<end>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) exact_range=(?P<exact>[01]) "
    r"truncated=(?P<truncated>[01]) bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
CORRELATION_PATTERN = re.compile(
    r"^CONTROL_CORRELATION sequence=(?P<sequence>\d+) tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"direction=(?P<direction>outbound|inbound) stream_id=(?P<stream>-?\d+) "
    r"type_id=(?P<type>0x[0-9a-fA-F]+) frame_length=(?P<length>\d+) "
    r"marker=(?P<marker>-|0x[0-9a-fA-F]+|other) "
    r"channel=(?P<channel>-|0x[0-9a-fA-F]+|other) "
    r"first_uvar=(?P<value>\d+) encoded_bytes=(?P<encoded>\d+)$"
)


@dataclass(frozen=True)
class OutboundControlPath:
    sequence: int
    tick: int
    process: int
    thread: int
    type_id: int
    envelope_length: int
    marker: int
    channel: int
    boundary_function_rva: int
    boundary_function_end_rva: int
    rvas: tuple[int, ...]


@dataclass(frozen=True)
class OutboundControlCode:
    type_id: int
    caller_rva: int
    function_rva: int
    function_end_rva: int
    exact_range: bool
    truncated: bool
    data: bytes


@dataclass(frozen=True)
class ControlCorrelation:
    sequence: int
    tick: int
    process: int
    thread: int
    direction: str
    stream_id: int
    type_id: int
    frame_length: int
    first_uvar: int
    encoded_bytes: int


def parse_correlations(path: Path) -> list[ControlCorrelation]:
    correlations: list[ControlCorrelation] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line.startswith("CONTROL_CORRELATION "):
            continue
        match = CORRELATION_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(
                f"malformed control correlation on line {line_number}"
            )
        type_id = int(match["type"], 16)
        direction = match["direction"]
        expected = {0x0002, 0x0005} if direction == "outbound" else {
            0x0002,
            0x0006,
        }
        if type_id not in expected:
            raise ValueError(
                f"unexpected {direction} correlation type on line {line_number}"
            )
        correlations.append(
            ControlCorrelation(
                sequence=int(match["sequence"]),
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                direction=direction,
                stream_id=int(match["stream"]),
                type_id=type_id,
                frame_length=int(match["length"]),
                first_uvar=int(match["value"]),
                encoded_bytes=int(match["encoded"]),
            )
        )
    return correlations


def parse_log(
    path: Path,
) -> tuple[
    list[OutboundControlPath],
    dict[int, OutboundControlCode],
    Counter[str],
    list[str],
]:
    paths: list[OutboundControlPath] = []
    code: dict[int, OutboundControlCode] = {}
    counts: Counter[str] = Counter()
    errors: list[str] = []

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line:
            continue
        event = line.split(maxsplit=1)[0]
        counts[event] += 1
        if event in {
            "OUTBOUND_CONTROL_CODE_ERROR",
            "OUTBOUND_CONTROL_PATH_ERROR",
        }:
            errors.append(line)
            continue
        if event == "OUTBOUND_CONTROL_PATH":
            match = PATH_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed outbound control path on line {line_number}"
                )
            rvas = tuple(
                int(value, 16) for value in match["rvas"].split(",") if value
            )
            if len(rvas) != int(match["count"]):
                raise ValueError(f"frame-count mismatch on line {line_number}")
            type_id = int(match["type"], 16)
            if type_id not in {0x0002, 0x0005}:
                raise ValueError(
                    f"unexpected outbound control type on line {line_number}"
                )
            paths.append(
                OutboundControlPath(
                    sequence=int(match["sequence"]),
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    type_id=type_id,
                    envelope_length=int(match["length"]),
                    marker=int(match["marker"], 16),
                    channel=int(match["channel"], 16),
                    boundary_function_rva=int(match["function"], 16),
                    boundary_function_end_rva=int(match["end"], 16),
                    rvas=rvas,
                )
            )
        elif event == "OUTBOUND_CONTROL_CODE":
            match = CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed outbound control code on line {line_number}"
                )
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            function_rva = int(match["function"], 16)
            function_end_rva = int(match["end"], 16)
            if function_end_rva - function_rva < len(data):
                raise ValueError(f"function-range mismatch on line {line_number}")
            record = OutboundControlCode(
                type_id=int(match["type"], 16),
                caller_rva=int(match["caller"], 16),
                function_rva=function_rva,
                function_end_rva=function_end_rva,
                exact_range=match["exact"] == "1",
                truncated=match["truncated"] == "1",
                data=data,
            )
            if function_rva in code and code[function_rva].data != data:
                raise ValueError(
                    f"conflicting function code on line {line_number}"
                )
            code[function_rva] = record
    return paths, code, counts, errors


def disassemble(record: OutboundControlCode, objdump: str) -> str:
    with tempfile.NamedTemporaryFile(
        prefix="isac-outbound-control-", suffix=".bin"
    ) as binary:
        binary.write(record.data)
        binary.flush()
        result = subprocess.run(
            [
                objdump,
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                f"--adjust-vma={record.function_rva:#x}",
                binary.name,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize the code-only outbound bootstrap path probe."
    )
    parser.add_argument("log", type=Path, help="project-isac-dispatch-probe.log")
    parser.add_argument("--disassemble", action="store_true")
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    try:
        paths, code, counts, errors = parse_log(args.log)
        correlations = parse_correlations(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Armed events: {counts['OUTBOUND_CONTROL_PROBE_ARMED']}")
    print(f"Ready events: {counts['OUTBOUND_CONTROL_PROBE_READY']}")
    print(f"Path events: {len(paths)}")
    print(f"Code functions: {len(code)}")
    print(f"Path limit events: {counts['OUTBOUND_CONTROL_PATH_LIMIT']}")
    print(f"Code limit events: {counts['OUTBOUND_CONTROL_CODE_LIMIT']}")
    print(f"Errors: {len(errors)}")
    print(f"Correlation candidates: {len(correlations)}")
    for record in correlations:
        print(
            f"correlation sequence={record.sequence} tick_ms={record.tick} "
            f"direction={record.direction} type={record.type_id:#06x} "
            f"frame_length={record.frame_length} "
            f"first_uvar={record.first_uvar} "
            f"encoded_bytes={record.encoded_bytes}"
        )
    signatures = Counter((path.type_id, path.rvas) for path in paths)
    for (type_id, rvas), count in sorted(signatures.items()):
        matching = [
            path
            for path in paths
            if path.type_id == type_id and path.rvas == rvas
        ]
        lengths = sorted({path.envelope_length for path in matching})
        channels = sorted({path.channel for path in matching})
        print(
            f"outbound-control-path type={type_id:#06x} count={count} "
            f"envelope_lengths={','.join(map(str, lengths))} "
            f"channels={','.join(f'{channel:#04x}' for channel in channels)} "
            f"rvas={','.join(f'{rva:#x}' for rva in rvas) or '-'}"
        )
    for function_rva, record in sorted(code.items()):
        print(
            f"outbound-control-code function_rva={function_rva:#x} "
            f"function_end_rva={record.function_end_rva:#x} "
            f"caller_rva={record.caller_rva:#x} bytes={len(record.data)} "
            f"exact={int(record.exact_range)} "
            f"truncated={int(record.truncated)}"
        )
        if args.disassemble:
            print(disassemble(record, args.objdump))
    for error in errors:
        print(f"WARNING: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
