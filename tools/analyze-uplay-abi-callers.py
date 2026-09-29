#!/usr/bin/env python3
"""Disassemble bounded Division call sites captured by the Uplay ABI probe."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


CODE_PATTERN = re.compile(
    r"^UPLAY_ABI_CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"function=(?P<function>[A-Za-z0-9_]+) "
    r"return_rva=(?P<return>0x[0-9a-fA-F]+) "
    r"function_start_rva=(?P<function_start>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"exact_start=(?P<exact>yes|no) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class CallerWindow:
    tick: int
    process: int
    thread: int
    function: str
    return_rva: int
    function_start_rva: int
    start_rva: int
    exact_start: bool
    data: bytes


def parse_log(path: Path) -> list[CallerWindow]:
    records: list[CallerWindow] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line.startswith("UPLAY_ABI_CODE "):
            continue
        match = CODE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed UPLAY_ABI_CODE on line {line_number}")
        data = bytes.fromhex(match["bytes"])
        if len(data) != int(match["length"]):
            raise ValueError(f"byte-count mismatch on line {line_number}")
        start_rva = int(match["start"], 16)
        return_rva = int(match["return"], 16)
        if not start_rva < return_rva <= start_rva + len(data):
            raise ValueError(f"return RVA outside window on line {line_number}")
        records.append(
            CallerWindow(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                function=match["function"],
                return_rva=return_rva,
                function_start_rva=int(match["function_start"], 16),
                start_rva=start_rva,
                exact_start=match["exact"] == "yes",
                data=data,
            )
        )
    return records


def preceding_call(record: CallerWindow) -> str | None:
    """Describe common x86-64 call encodings ending at the return RVA."""
    end = record.return_rva - record.start_rva
    data = record.data
    if end >= 5 and data[end - 5] == 0xE8:
        displacement = int.from_bytes(data[end - 4 : end], "little", signed=True)
        return f"direct {record.return_rva + displacement:#x}"
    if end >= 6 and data[end - 6 : end - 4] == b"\xff\x15":
        displacement = int.from_bytes(data[end - 4 : end], "little", signed=True)
        return f"rip-indirect slot={record.return_rva + displacement:#x}"
    register_names = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")
    if end >= 2 and data[end - 2] == 0xFF and 0xD0 <= data[end - 1] <= 0xD7:
        return f"register {register_names[data[end - 1] - 0xD0]}"
    if (
        end >= 3
        and data[end - 3] == 0x41
        and data[end - 2] == 0xFF
        and 0xD0 <= data[end - 1] <= 0xD7
    ):
        return f"register r{8 + data[end - 1] - 0xD0}"
    return None


def disassemble(record: CallerWindow, objdump: str) -> str:
    with tempfile.NamedTemporaryFile(prefix="isac-uplay-abi-", suffix=".bin") as file:
        file.write(record.data)
        file.flush()
        result = subprocess.run(
            [
                objdump,
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                f"--adjust-vma={record.start_rva:#x}",
                file.name,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    lines = result.stdout.splitlines()
    return "\n".join(line for line in lines if not line.startswith(file.name))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument(
        "--objdump", default=shutil.which("objdump"), help="objdump executable"
    )
    parser.add_argument(
        "--function",
        action="append",
        help="show only this export; may be supplied more than once",
    )
    args = parser.parse_args()
    if args.objdump is None:
        parser.error("objdump was not found")
    try:
        records = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    selected = [
        record
        for record in records
        if args.function is None or record.function in args.function
    ]
    print(f"Log: {args.log}")
    print(f"Captured caller windows: {len(records)}")
    print(f"Selected caller windows: {len(selected)}")
    for record in selected:
        print()
        print(
            f"=== {record.function} return={record.return_rva:#x} "
            f"pid={record.process} tid={record.thread} "
            f"exact_start={'yes' if record.exact_start else 'no'} ==="
        )
        call = preceding_call(record)
        print(f"Preceding call: {call or 'unrecognized'}")
        try:
            print(disassemble(record, args.objdump))
        except subprocess.CalledProcessError as error:
            parser.error(error.stderr.strip() or "objdump failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
