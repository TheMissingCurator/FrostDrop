#!/usr/bin/env python3
"""Rank and summarize complete bodies plus field traces from schema-miner runs."""

from __future__ import annotations

import argparse
import runpy
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
MESSAGE_PATTERN_TEXT = (
    r"^SCHEMA_MESSAGE sequence=(?P<sequence>\d+) "
    r"message_sequence=(?P<message_sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"type_id=(?P<type>0x[0-9a-fA-F]+) "
    r"deserializer_rva=(?P<deserialize>0x[0-9a-fA-F]+) "
    r"start_absolute=(?P<start>\d+) end_absolute=(?P<end>\d+) "
    r"length=(?P<length>\d+) captured=(?P<captured>\d+) "
    r"complete=(?P<complete>[01]) bytes=(?P<bytes>[0-9a-fA-F]*)$"
)


import re


MESSAGE_PATTERN = re.compile(MESSAGE_PATTERN_TEXT)

HELPER_NAMES = {
    0x223D530: "bool",
    0x223D5D0: "fixed-bytes",
    0x223D5F0: "float32",
    0x223D640: "destination-sized-bytes",
    0x223D690: "sint16",
    0x223D6A0: "sint32",
    0x223D6B0: "sint64",
    0x223D6C0: "sint8",
    0x223D6D0: "compressed-vector",
    0x223D860: "bounded-bytes",
    0x223DA10: "bounded-string",
    0x223DAC0: "uint16",
    0x223DAD0: "uint32",
    0x223DAE0: "uint64",
    0x223DAF0: "uint8",
    0x223DC30: "vec2f",
    0x223DCC0: "vec3f",
    0x0F841E0: "string",
    0x0F7F5F0: "compact-reference",
}


@dataclass(frozen=True)
class SchemaMessage:
    sequence: int
    message_sequence: int
    tick: int
    process: int
    thread: int
    type_id: int
    deserializer_rva: int
    start_absolute: int
    end_absolute: int
    length: int
    complete: bool
    data: bytes


@dataclass(frozen=True)
class MessageCoverage:
    message: SchemaMessage
    field_count: int
    covered_bytes: int
    ranges: tuple[tuple[int, int], ...]
    shape: tuple[tuple[int, int, int, int], ...]

    @property
    def fully_accounted(self) -> bool:
        return self.message.complete and self.covered_bytes == self.message.length

    @property
    def ratio(self) -> float:
        if not self.message.complete:
            return 0.0
        if self.message.length == 0:
            return 1.0
        return self.covered_bytes / self.message.length


@dataclass(frozen=True)
class TypeSummary:
    type_id: int
    messages: tuple[MessageCoverage, ...]

    @property
    def complete_count(self) -> int:
        return sum(item.message.complete for item in self.messages)

    @property
    def fully_accounted_count(self) -> int:
        return sum(item.fully_accounted for item in self.messages)

    @property
    def best_ratio(self) -> float:
        return max((item.ratio for item in self.messages), default=0.0)


def parse_message_log(
    path: Path,
) -> tuple[list[SchemaMessage], Counter[str], list[str]]:
    messages: list[SchemaMessage] = []
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
            "SCHEMA_MESSAGE_ERROR",
            "SCHEMA_FIELD_ERROR",
            "SCHEMA_EVENT_ERROR",
        }:
            errors.append(line)
            continue
        if event != "SCHEMA_MESSAGE":
            continue
        match = MESSAGE_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed SCHEMA_MESSAGE on line {line_number}")
        data = bytes.fromhex(match["bytes"])
        captured = int(match["captured"])
        length = int(match["length"])
        start = int(match["start"])
        end = int(match["end"])
        complete = match["complete"] == "1"
        if len(data) != captured:
            raise ValueError(f"message byte-count mismatch on line {line_number}")
        if end - start != length:
            raise ValueError(f"message cursor-range mismatch on line {line_number}")
        if complete and captured != length:
            raise ValueError(f"complete message is truncated on line {line_number}")
        messages.append(
            SchemaMessage(
                sequence=int(match["sequence"]),
                message_sequence=int(match["message_sequence"]),
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                type_id=int(match["type"], 16),
                deserializer_rva=int(match["deserialize"], 16),
                start_absolute=start,
                end_absolute=end,
                length=length,
                complete=complete,
                data=data,
            )
        )
    return messages, counts, errors


def _merge_ranges(ranges: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if start >= end:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def correlate(
    messages: list[SchemaMessage],
    fields: list[object],
) -> tuple[list[MessageCoverage], list[object]]:
    fields_by_message: dict[int, list[object]] = defaultdict(list)
    uncorrelated: list[object] = []
    message_ids = {message.message_sequence for message in messages}
    for field in fields:
        if field.message_sequence is None or field.message_sequence not in message_ids:
            uncorrelated.append(field)
            continue
        fields_by_message[field.message_sequence].append(field)

    results: list[MessageCoverage] = []
    for message in messages:
        selected = sorted(
            fields_by_message.get(message.message_sequence, ()),
            key=lambda field: field.sequence,
        )
        ranges: list[tuple[int, int]] = []
        shape: list[tuple[int, int, int, int]] = []
        for field in selected:
            relative_start = field.before_absolute - message.start_absolute
            relative_end = field.after_absolute - message.start_absolute
            if relative_end <= 0 or relative_start >= message.length:
                continue
            start = max(0, relative_start)
            end = min(message.length, relative_end)
            ranges.append((start, end))
            shape.append(
                (
                    field.helper_rva,
                    field.return_rva if field.return_rva is not None else -1,
                    relative_start,
                    field.consumed,
                )
            )
        merged = _merge_ranges(ranges)
        results.append(
            MessageCoverage(
                message=message,
                field_count=len(selected),
                covered_bytes=sum(end - start for start, end in merged),
                ranges=merged,
                shape=tuple(shape),
            )
        )
    return results, uncorrelated


def summarize_types(coverage: list[MessageCoverage]) -> list[TypeSummary]:
    grouped: dict[int, list[MessageCoverage]] = defaultdict(list)
    for item in coverage:
        grouped[item.message.type_id].append(item)
    return [
        TypeSummary(type_id, tuple(messages))
        for type_id, messages in grouped.items()
    ]


def _counter_text(counter: Counter[int]) -> str:
    return ",".join(f"{value}:{count}" for value, count in sorted(counter.items()))


def _unexplained_ranges(item: MessageCoverage) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    cursor = 0
    for start, end in item.ranges:
        if cursor < start:
            result.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < item.message.length:
        result.append((cursor, item.message.length))
    return tuple(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="project-isac-dispatch-probe.log")
    parser.add_argument("--type", type=lambda value: int(value, 0))
    parser.add_argument("--top", type=int, default=30)
    parser.add_argument("--timeline", action="store_true")
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top must be positive")

    field_analyzer = runpy.run_path(
        str(PROJECT_DIR / "tools/analyze-schema-fields.py")
    )
    try:
        messages, counts, message_errors = parse_message_log(args.log)
        fields, _field_counts, field_errors = field_analyzer["parse_log"](args.log)
        coverage, uncorrelated = correlate(messages, fields)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    summaries = summarize_types(coverage)
    summaries.sort(
        key=lambda item: (
            -item.fully_accounted_count,
            -item.best_ratio,
            -item.complete_count,
            -len(item.messages),
            item.type_id,
        )
    )
    if args.type is not None:
        summaries = [item for item in summaries if item.type_id == args.type]

    print(f"Log: {args.log}")
    print(f"Schema messages: {len(messages)}")
    print(f"Complete bodies: {sum(message.complete for message in messages)}")
    print(f"Incomplete bodies: {sum(not message.complete for message in messages)}")
    print(f"Message types: {len({message.type_id for message in messages})}")
    print(f"Field records: {len(fields)}")
    print(f"Uncorrelated field records: {len(uncorrelated)}")
    print(f"Probe errors: {len(message_errors) + len(field_errors)}")
    print(f"Message limit records: {counts['SCHEMA_MESSAGE_LIMIT']}")
    for error in message_errors + field_errors:
        print(f"WARNING: {error}")

    print("Ranked schema candidates:")
    for summary in summaries[: args.top]:
        complete_items = [item for item in summary.messages if item.message.complete]
        lengths = Counter(item.message.length for item in complete_items)
        shapes = {item.shape for item in complete_items if item.shape}
        helper_count = len(
            {
                helper
                for item in complete_items
                for helper, _caller, _offset, _length in item.shape
            }
        )
        field_count = sum(item.field_count for item in summary.messages)
        print(
            f"  type={summary.type_id:#06x} messages={len(summary.messages)} "
            f"complete={summary.complete_count} "
            f"fully-accounted={summary.fully_accounted_count} "
            f"best-coverage={summary.best_ratio:.1%} fields={field_count} "
            f"helpers={helper_count} shapes={len(shapes)} "
            f"lengths={_counter_text(lengths) or '-'}"
        )

    if args.type is not None and summaries:
        summary = summaries[0]
        message_by_id = {
            item.message.message_sequence: item.message for item in summary.messages
        }
        selected_fields = [
            field
            for field in fields
            if field.type_id == args.type
            and field.message_sequence in message_by_id
        ]
        caller_groups: dict[tuple[int, int | None], list[object]] = defaultdict(list)
        for field in selected_fields:
            caller_groups[(field.helper_rva, field.return_rva)].append(field)
        print("Provisional field map:")
        for (helper, caller), group in sorted(
            caller_groups.items(),
            key=lambda pair: min(field.sequence for field in pair[1]),
        ):
            offsets = Counter(
                field.before_absolute
                - message_by_id[field.message_sequence].start_absolute
                for field in group
                if field.message_sequence in message_by_id
            )
            consumed = Counter(field.consumed for field in group)
            caller_text = f"{caller:#x}" if caller is not None else "-"
            print(
                f"  helper={HELPER_NAMES.get(helper, f'unknown-{helper:#x}')} "
                f"caller={caller_text} occurrences={len(group)} "
                f"offsets={_counter_text(offsets)} "
                f"consumed={_counter_text(consumed)}"
            )
        best = max(summary.messages, key=lambda item: item.ratio)
        unexplained = _unexplained_ranges(best)
        print(
            "Best unexplained ranges: "
            + (
                ",".join(f"{start}:{end}" for start, end in unexplained)
                or "none"
            )
        )

    if args.timeline and coverage:
        first_tick = coverage[0].message.tick
        print("Schema miner timeline:")
        for item in coverage:
            if args.type is not None and item.message.type_id != args.type:
                continue
            print(
                f"  elapsed-ms={item.message.tick - first_tick} "
                f"message-sequence={item.message.message_sequence} "
                f"type={item.message.type_id:#06x} length={item.message.length} "
                f"complete={int(item.message.complete)} "
                f"coverage={item.ratio:.1%} fields={item.field_count}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
