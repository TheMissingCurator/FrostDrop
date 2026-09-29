#!/usr/bin/env python3
"""Disassemble bounded code windows from Project ISAC's code probe."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


CODE_PATTERN = re.compile(
    r"^CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"label=(?P<label>[a-z0-9-]+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class CodeRecord:
    tick: int
    process: int
    thread: int
    label: str
    target_rva: int
    start_rva: int
    data: bytes


def parse_log(path: Path) -> tuple[list[CodeRecord], list[str]]:
    records: list[CodeRecord] = []
    statuses: list[str] = []

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line:
            continue
        if not line.startswith("CODE "):
            statuses.append(line)
            continue
        match = CODE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed CODE record on line {line_number}")
        data = bytes.fromhex(match["bytes"])
        if len(data) != int(match["length"]):
            raise ValueError(f"byte-count mismatch on line {line_number}")
        start_rva = int(match["start"], 16)
        target_rva = int(match["target"], 16)
        if not start_rva <= target_rva < start_rva + len(data):
            raise ValueError(f"target outside window on line {line_number}")
        records.append(
            CodeRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                label=match["label"],
                target_rva=target_rva,
                start_rva=start_rva,
                data=data,
            )
        )
    return records, statuses


def disassemble_forward(record: CodeRecord, objdump: str) -> str:
    target_offset = record.target_rva - record.start_rva
    forward = record.data[target_offset:]
    with tempfile.NamedTemporaryFile(prefix="isac-code-", suffix=".bin") as file:
        file.write(forward)
        file.flush()
        result = subprocess.run(
            [
                objdump,
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                f"--adjust-vma={record.target_rva:#x}",
                file.name,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    lines = result.stdout.splitlines()
    return "\n".join(line for line in lines if not line.startswith(file.name))


def infer_preceding_direct_call(record: CodeRecord) -> int | None:
    """Return an E8 call target when the captured target is its return RVA."""
    target_offset = record.target_rva - record.start_rva
    if target_offset < 5 or record.data[target_offset - 5] != 0xE8:
        return None
    displacement = int.from_bytes(
        record.data[target_offset - 4 : target_offset],
        "little",
        signed=True,
    )
    return record.target_rva + displacement


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Disassemble bounded Project ISAC code-probe windows."
    )
    parser.add_argument("log", type=Path, help="project-isac-code-probe.log")
    parser.add_argument(
        "--objdump",
        default=shutil.which("objdump"),
        help="objdump-compatible executable",
    )
    parser.add_argument(
        "--label",
        action="append",
        help="show only this label; may be supplied more than once",
    )
    args = parser.parse_args()
    if args.objdump is None:
        parser.error("objdump was not found")

    try:
        records, statuses = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Captured windows: {len(records)}")
    for status in statuses:
        print(status)

    selected_records = [
        record
        for record in records
        if args.label is None or record.label in args.label
    ]
    for record in selected_records:
        target_offset = record.target_rva - record.start_rva
        preceding = record.data[:target_offset].hex(" ")
        print()
        print(
            f"=== {record.label} target={record.target_rva:#x} "
            f"tick={record.tick} pid={record.process} tid={record.thread} ==="
        )
        print(f"Preceding bytes ({target_offset}): {preceding}")
        call_target = infer_preceding_direct_call(record)
        if call_target is not None:
            print(
                f"Preceding direct call: {record.target_rva - 5:#x} "
                f"-> {call_target:#x}"
            )
        try:
            print(disassemble_forward(record, args.objdump))
        except subprocess.CalledProcessError as error:
            parser.error(error.stderr.strip() or "objdump failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
