#!/usr/bin/env python3
"""Summarize exact wire consumption captured by the schema field probe."""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


FIELD_PATTERN = re.compile(
    r"^SCHEMA_FIELD sequence=(?P<sequence>\d+) "
    r"(?:message_sequence=(?P<message_sequence>\d+) )?"
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"type_id=(?P<type>0x[0-9a-fA-F]+) "
    r"deserializer_rva=(?P<deserialize>0x[0-9a-fA-F]+) "
    r"helper_rva=(?P<helper>0x[0-9a-fA-F]+) "
    r"(?:return_rva=(?P<return_rva>0x[0-9a-fA-F]+) )?"
    r"destination_offset=(?P<destination>-?\d+) "
    r"argument_r8=(?P<r8>0x[0-9a-fA-F]+) "
    r"argument_r9=(?P<r9>0x[0-9a-fA-F]+) "
    r"before_absolute=(?P<before_absolute>\d+) "
    r"after_absolute=(?P<after_absolute>\d+) consumed=(?P<consumed>\d+) "
    r"return_value=(?P<return>0x[0-9a-fA-F]+) "
    r"wire_captured=(?P<wire_captured>\d+) wire=(?P<wire>[0-9a-fA-F]*) "
    r"before=(?P<before>[0-9a-fA-F]*) after=(?P<after>[0-9a-fA-F]*)$"
)


@dataclass(frozen=True)
class FieldRecord:
    sequence: int
    message_sequence: int | None
    tick: int
    process: int
    thread: int
    type_id: int
    deserializer_rva: int
    helper_rva: int
    return_rva: int | None
    destination_offset: int
    argument_r8: int
    argument_r9: int
    before_absolute: int
    after_absolute: int
    consumed: int
    return_value: int
    wire: bytes
    before: bytes
    after: bytes

    @property
    def exact_wire(self) -> bytes | None:
        if self.consumed <= len(self.wire):
            return self.wire[: self.consumed]
        return None

    @property
    def changed_offsets(self) -> tuple[int, ...]:
        return tuple(
            index
            for index, (before, after) in enumerate(zip(self.before, self.after))
            if before != after
        )


def parse_log(path: Path) -> tuple[list[FieldRecord], Counter[str], list[str]]:
    records: list[FieldRecord] = []
    counts: Counter[str] = Counter()
    errors: list[str] = []

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line:
            continue
        event_name = line.split(maxsplit=1)[0]
        counts[event_name] += 1
        if event_name in {"SCHEMA_FIELD_ERROR", "SCHEMA_EVENT_ERROR"}:
            errors.append(line)
            continue
        if event_name != "SCHEMA_FIELD":
            continue
        match = FIELD_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed SCHEMA_FIELD on line {line_number}")
        wire = bytes.fromhex(match["wire"])
        before = bytes.fromhex(match["before"])
        after = bytes.fromhex(match["after"])
        if len(wire) != int(match["wire_captured"]):
            raise ValueError(f"wire byte-count mismatch on line {line_number}")
        records.append(
            FieldRecord(
                sequence=int(match["sequence"]),
                message_sequence=(
                    int(match["message_sequence"])
                    if match["message_sequence"] is not None
                    else None
                ),
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                type_id=int(match["type"], 16),
                deserializer_rva=int(match["deserialize"], 16),
                helper_rva=int(match["helper"], 16),
                return_rva=(
                    int(match["return_rva"], 16)
                    if match["return_rva"] is not None
                    else None
                ),
                destination_offset=int(match["destination"]),
                argument_r8=int(match["r8"], 16),
                argument_r9=int(match["r9"], 16),
                before_absolute=int(match["before_absolute"]),
                after_absolute=int(match["after_absolute"]),
                consumed=int(match["consumed"]),
                return_value=int(match["return"], 16),
                wire=wire,
                before=before,
                after=after,
            )
        )
    return records, counts, errors


def format_counter(values: Counter[int], *, hexadecimal: bool = False) -> str:
    if hexadecimal:
        return ",".join(f"{value:#x}:{count}" for value, count in sorted(values.items()))
    return ",".join(f"{value}:{count}" for value, count in sorted(values.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="project-isac-dispatch-probe.log")
    parser.add_argument("--type", type=lambda value: int(value, 0))
    parser.add_argument("--timeline", action="store_true")
    parser.add_argument("--examples", type=int, default=3)
    args = parser.parse_args()
    if args.examples < 0:
        parser.error("--examples must be non-negative")

    try:
        records, counts, errors = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    selected = [
        record
        for record in records
        if args.type is None or record.type_id == args.type
    ]
    print(f"Log: {args.log}")
    print(f"Schema field records: {len(records)}")
    print(f"Selected records: {len(selected)}")
    print(f"Message types: {len({record.type_id for record in records})}")
    print(f"Reader helpers: {len({record.helper_rva for record in records})}")
    print(f"Exact wire records: {sum(record.exact_wire is not None for record in records)}")
    print(f"Field errors: {len(errors)}")
    print(f"Field limit records: {counts['SCHEMA_FIELD_LIMIT']}")
    for error in errors:
        print(f"WARNING: {error}")

    groups: dict[tuple[int, int, int | None, int], list[FieldRecord]] = defaultdict(list)
    for record in selected:
        groups[
            (
                record.type_id,
                record.helper_rva,
                record.return_rva,
                record.destination_offset,
            )
        ].append(record)
    for key, group in sorted(groups.items()):
        type_id, helper_rva, return_rva, destination_offset = key
        consumed = Counter(record.consumed for record in group)
        arguments = Counter(record.argument_r8 for record in group)
        changed = sorted({offset for record in group for offset in record.changed_offsets})
        exact_examples: list[str] = []
        seen: set[bytes] = set()
        for record in group:
            if args.examples == 0:
                break
            exact = record.exact_wire
            if exact is None or exact in seen:
                continue
            seen.add(exact)
            exact_examples.append(exact.hex())
            if len(exact_examples) >= args.examples:
                break
        caller = f"{return_rva:#x}" if return_rva is not None else "-"
        print(
            f"field type={type_id:#06x} helper={helper_rva:#x} "
            f"caller={caller} "
            f"destination={destination_offset:+#x} count={len(group)} "
            f"consumed={format_counter(consumed)} "
            f"r8={format_counter(arguments, hexadecimal=True)} "
            f"changed={','.join(f'{offset:#x}' for offset in changed) or '-'} "
            f"examples={','.join(exact_examples) or '-'}"
        )

    if args.timeline and selected:
        first_tick = selected[0].tick
        print("Schema field timeline:")
        for record in selected:
            exact = record.exact_wire
            caller = f"{record.return_rva:#x}" if record.return_rva is not None else "-"
            print(
                f"  sequence={record.sequence} elapsed-ms={record.tick - first_tick} "
                f"type={record.type_id:#06x} helper={record.helper_rva:#x} "
                f"caller={caller} "
                f"destination={record.destination_offset:+#x} "
                f"consumed={record.consumed} "
                f"wire={exact.hex() if exact is not None else '<truncated>'}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
