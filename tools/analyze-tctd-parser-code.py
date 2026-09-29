#!/usr/bin/env python3
"""Validate and reconstruct the dynamically selected TCTD TLS parser body."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


CAPTURE_PATTERN = re.compile(
    r"^TCTD_PARSER_CODE_CAPTURED .* "
    r"detail=target-rva=(?P<target>0x[0-9a-fA-F]+),"
    r"begin-rva=(?P<begin>0x[0-9a-fA-F]+),"
    r"end-rva=(?P<end>0x[0-9a-fA-F]+),"
    r"length=(?P<length>\d+),windows=(?P<windows>\d+),"
    r"mutation=disabled,payloads=disabled$"
)
CODE_PATTERN = re.compile(
    r"^CODE .* label=tctd-parser-body-(?P<index>\d+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class Capture:
    target: int
    begin: int
    end: int
    windows: tuple[tuple[int, bytes], ...]

    @property
    def body(self) -> bytes:
        return b"".join(data for _, data in self.windows)


def parse_capture(stack_log: Path, code_log: Path) -> Capture:
    metadata = None
    errors: list[str] = []
    for raw_line in stack_log.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = raw_line.strip()
        if line.startswith("TCTD_PARSER_CODE_ERROR "):
            errors.append(line)
        match = CAPTURE_PATTERN.fullmatch(line)
        if match is not None:
            metadata = match
    if errors:
        raise ValueError(errors[0])
    if metadata is None:
        raise ValueError("TCTD_PARSER_CODE_CAPTURED is missing")

    chunks: dict[int, tuple[int, bytes]] = {}
    for line_number, raw_line in enumerate(
        code_log.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if "label=tctd-parser-body-" not in line:
            continue
        match = CODE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed parser CODE window on line {line_number}")
        index = int(match["index"])
        start = int(match["start"], 16)
        target = int(match["target"], 16)
        data = bytes.fromhex(match["bytes"])
        if start != target:
            raise ValueError(f"window target/start mismatch on line {line_number}")
        if len(data) != int(match["length"]):
            raise ValueError(f"window length mismatch on line {line_number}")
        chunk = (start, data)
        if index in chunks:
            if chunks[index] != chunk:
                raise ValueError(f"conflicting duplicate window index {index}")
            continue
        chunks[index] = chunk

    expected_windows = int(metadata["windows"])
    if sorted(chunks) != list(range(expected_windows)):
        raise ValueError("parser window sequence is incomplete")
    ordered = tuple(chunks[index] for index in range(expected_windows))
    begin = int(metadata["begin"], 16)
    end = int(metadata["end"], 16)
    cursor = begin
    for start, data in ordered:
        if start != cursor:
            raise ValueError("parser windows are not contiguous")
        cursor += len(data)
    if cursor != end or end - begin != int(metadata["length"]):
        raise ValueError("parser metadata length mismatch")
    target = int(metadata["target"], 16)
    if not begin <= target < end:
        raise ValueError("parser target is outside captured function")
    return Capture(target=target, begin=begin, end=end, windows=ordered)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stack_log", type=Path)
    parser.add_argument("code_log", type=Path)
    parser.add_argument("--output-bin", type=Path)
    args = parser.parse_args()
    try:
        capture = parse_capture(args.stack_log, args.code_log)
        if args.output_bin is not None:
            args.output_bin.write_bytes(capture.body)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Stack log: {args.stack_log}")
    print(f"Code log: {args.code_log}")
    print(f"Selected parser RVA: 0x{capture.target:x}")
    print(f"Function begin RVA: 0x{capture.begin:x}")
    print(f"Function end RVA: 0x{capture.end:x}")
    print(f"Function bytes: {len(capture.body)}")
    print(f"Code windows: {len(capture.windows)}")
    if args.output_bin is not None:
        print(f"Reconstructed binary: {args.output_bin}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
