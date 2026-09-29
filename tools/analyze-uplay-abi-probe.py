#!/usr/bin/env python3
"""Summarize metadata-only Uplay ABI call and return observations."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FunctionSummary:
    calls: int = 0
    returns: int = 0
    callers: Counter[str] = field(default_factory=Counter)
    arguments: dict[int, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    rax: Counter[str] = field(default_factory=Counter)
    rdx: Counter[str] = field(default_factory=Counter)
    mutations: dict[int, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    direct_lengths: dict[int, Counter[int]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    nested_lengths: dict[int, Counter[int]] = field(
        default_factory=lambda: defaultdict(Counter)
    )


def fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for token in line.split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        result[key] = value
    return result


def parse_log(
    path: Path,
) -> tuple[dict[str, FunctionSummary], Counter[str], list[str]]:
    summaries: dict[str, FunctionSummary] = defaultdict(FunctionSummary)
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
        if event == "UPLAY_ABI_ERROR":
            errors.append(line)
            continue
        if event not in {"UPLAY_ABI_CALL", "UPLAY_ABI_RETURN"}:
            continue
        values = fields(line)
        function = values.get("function")
        if function is None:
            raise ValueError(f"missing function on line {line_number}")
        summary = summaries[function]
        if event == "UPLAY_ABI_CALL":
            summary.calls += 1
            summary.callers[values.get("caller", "unknown")] += 1
            for key, value in values.items():
                if key.startswith("arg") and key[3:].isdigit():
                    summary.arguments[int(key[3:])][value] += 1
        else:
            summary.returns += 1
            summary.rax[values.get("rax", "unknown")] += 1
            summary.rdx[values.get("rdx", "unknown")] += 1
            for key, value in values.items():
                if not key.startswith("arg"):
                    continue
                suffix = key[3:]
                if "_" not in suffix:
                    continue
                index_text, property_name = suffix.split("_", 1)
                if not index_text.isdigit():
                    continue
                index = int(index_text)
                if property_name == "word_changed":
                    parts = value.split(",")
                    summary.mutations[index][parts[0]] += 1
                    for part in parts[1:]:
                        if part.startswith("direct_utf8_length="):
                            summary.direct_lengths[index][
                                int(part.split("=", 1)[1])
                            ] += 1
                        elif part.startswith("nested_utf8_length="):
                            summary.nested_lengths[index][
                                int(part.split("=", 1)[1])
                            ] += 1
    return dict(summaries), events, errors


def format_counter(counter: Counter[object]) -> str:
    return ",".join(
        f"{value}={count}"
        for value, count in sorted(counter.items(), key=lambda item: str(item[0]))
    ) or "-"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        summaries, events, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Ready events: {events['UPLAY_ABI_READY']}")
    print(f"Call records: {events['UPLAY_ABI_CALL']}")
    print(f"Return records: {events['UPLAY_ABI_RETURN']}")
    print(f"Caller-code windows: {events['UPLAY_ABI_CODE']}")
    print(f"Error events: {events['UPLAY_ABI_ERROR']}")
    for function in sorted(summaries):
        summary = summaries[function]
        print(f"{function}: calls={summary.calls} returns={summary.returns}")
        print(f"  callers={format_counter(summary.callers)}")
        for index in sorted(summary.arguments):
            print(
                f"  arg{index}={format_counter(summary.arguments[index])}"
            )
        print(f"  rax={format_counter(summary.rax)}")
        print(f"  rdx={format_counter(summary.rdx)}")
        for index in sorted(summary.mutations):
            detail = f"  arg{index}_word_changed={format_counter(summary.mutations[index])}"
            if summary.direct_lengths[index]:
                detail += (
                    ";direct_utf8_lengths="
                    f"{format_counter(summary.direct_lengths[index])}"
                )
            if summary.nested_lengths[index]:
                detail += (
                    ";nested_utf8_lengths="
                    f"{format_counter(summary.nested_lengths[index])}"
                )
            print(detail)
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
