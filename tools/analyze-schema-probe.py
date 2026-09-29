#!/usr/bin/env python3
"""Analyze inbound message type-to-deserializer schema probe records."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


EVENT_PATTERN = re.compile(
    r"^SCHEMA_EVENT sequence=(?P<sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"type_id=(?P<type>0x[0-9a-fA-F]+) "
    r"vtable_rva=(?P<vtable>0x[0-9a-fA-F]+) "
    r"deserialize_rva=(?P<deserialize>0x[0-9a-fA-F]+) "
    r"slot08_rva=(?P<slot08>0x[0-9a-fA-F]+) "
    r"slot28_rva=(?P<slot28>0x[0-9a-fA-F]+) "
    r"has_cursor=(?P<has_cursor>[01]) "
    r"absolute_cursor=(?P<absolute>\d+) "
    r"local_cursor=(?P<local>\d+) buffer_length=(?P<buffer_length>\d+)$"
)
TARGET_PATTERN = re.compile(
    r"^SCHEMA_TARGET tick_ms=(?P<tick>\d+) process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) type_id=(?P<type>0x[0-9a-fA-F]+) "
    r"vtable_rva=(?P<vtable>0x[0-9a-fA-F]+) "
    r"deserialize_rva=(?P<deserialize>0x[0-9a-fA-F]+) "
    r"slot08_rva=(?P<slot08>0x[0-9a-fA-F]+) "
    r"slot28_rva=(?P<slot28>0x[0-9a-fA-F]+)$"
)
CODE_PATTERN = re.compile(
    r"^SCHEMA_CODE tick_ms=(?P<tick>\d+) process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) type_id=(?P<type>0x[0-9a-fA-F]+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"function_end_rva=(?P<function_end>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) truncated=(?P<truncated>[01]) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
RESOLUTION_PATTERN = re.compile(
    r"^SCHEMA_RESOLUTION tick_ms=(?P<tick>\d+) process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) type_id=(?P<type>0x[0-9a-fA-F]+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"resolved_rva=(?P<resolved>0x[0-9a-fA-F]+) "
    r"object_adjustment=(?P<adjustment>-?\d+) steps=(?P<steps>\d+)$"
)
HELPER_CODE_PATTERN = re.compile(
    r"^SCHEMA_HELPER_CODE tick_ms=(?P<tick>\d+) process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"(?:resolved_rva=(?P<resolved>0x[0-9a-fA-F]+) "
    r"object_adjustment=(?P<adjustment>-?\d+) steps=(?P<steps>\d+) )?"
    r"function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"function_end_rva=(?P<function_end>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) truncated=(?P<truncated>[01]) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
NESTED_CODE_PATTERN = re.compile(
    r"^SCHEMA_NESTED_CODE tick_ms=(?P<tick>\d+) process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) root_rva=(?P<root>0x[0-9a-fA-F]+) "
    r"depth=(?P<depth>\d+) target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"function_end_rva=(?P<function_end>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) truncated=(?P<truncated>[01]) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
NESTED_FORWARD_CODE_PATTERN = re.compile(
    r"^SCHEMA_NESTED_FORWARD_CODE tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) thread=(?P<thread>\d+) "
    r"root_rva=(?P<root>0x[0-9a-fA-F]+) "
    r"window_start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"window_end_rva=(?P<end>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
CALL_PATTERN = re.compile(
    r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+call\s+0x(?P<target>[0-9a-f]+)\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class SchemaEvent:
    sequence: int
    tick: int
    process: int
    thread: int
    type_id: int
    vtable_rva: int
    deserialize_rva: int
    has_cursor: bool
    absolute_cursor: int
    local_cursor: int
    buffer_length: int


@dataclass(frozen=True)
class SchemaTarget:
    tick: int
    process: int
    thread: int
    type_id: int
    vtable_rva: int
    deserialize_rva: int
    slot08_rva: int
    slot28_rva: int


@dataclass(frozen=True)
class SchemaCode:
    type_id: int
    target_rva: int
    function_rva: int
    function_end_rva: int
    truncated: bool
    data: bytes


@dataclass(frozen=True)
class SchemaResolution:
    type_id: int
    target_rva: int
    resolved_rva: int
    object_adjustment: int
    steps: int


@dataclass(frozen=True)
class SchemaHelperCode:
    target_rva: int
    resolved_rva: int | None
    object_adjustment: int | None
    resolution_steps: int | None
    function_rva: int
    function_end_rva: int
    truncated: bool
    data: bytes


@dataclass(frozen=True)
class SchemaNestedCode:
    root_rva: int
    depth: int
    target_rva: int
    function_rva: int
    function_end_rva: int
    truncated: bool
    data: bytes


@dataclass(frozen=True)
class SchemaNestedForwardCode:
    root_rva: int
    window_start_rva: int
    window_end_rva: int
    data: bytes

    @property
    def function_rva(self) -> int:
        """Provide the load address expected by the shared disassembler."""
        return self.window_start_rva


def parse_log(
    path: Path,
) -> tuple[
    list[SchemaEvent],
    dict[tuple[int, int], SchemaTarget],
    dict[tuple[int, int], SchemaCode],
    Counter[str],
    list[str],
]:
    events: list[SchemaEvent] = []
    targets: dict[tuple[int, int], SchemaTarget] = {}
    code: dict[tuple[int, int], SchemaCode] = {}
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
        if event_name in {"SCHEMA_EVENT_ERROR", "SCHEMA_CODE_ERROR"}:
            errors.append(line)
            continue
        if event_name == "SCHEMA_EVENT":
            match = EVENT_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed SCHEMA_EVENT on line {line_number}")
            events.append(
                SchemaEvent(
                    sequence=int(match["sequence"]),
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    type_id=int(match["type"], 16),
                    vtable_rva=int(match["vtable"], 16),
                    deserialize_rva=int(match["deserialize"], 16),
                    has_cursor=match["has_cursor"] == "1",
                    absolute_cursor=int(match["absolute"]),
                    local_cursor=int(match["local"]),
                    buffer_length=int(match["buffer_length"]),
                )
            )
        elif event_name == "SCHEMA_TARGET":
            match = TARGET_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed SCHEMA_TARGET on line {line_number}")
            record = SchemaTarget(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                type_id=int(match["type"], 16),
                vtable_rva=int(match["vtable"], 16),
                deserialize_rva=int(match["deserialize"], 16),
                slot08_rva=int(match["slot08"], 16),
                slot28_rva=int(match["slot28"], 16),
            )
            key = (record.type_id, record.deserialize_rva)
            previous = targets.get(key)
            if previous is not None and previous != record:
                raise ValueError(f"conflicting SCHEMA_TARGET on line {line_number}")
            targets[key] = record
        elif event_name == "SCHEMA_CODE":
            match = CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed SCHEMA_CODE on line {line_number}")
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            record = SchemaCode(
                type_id=int(match["type"], 16),
                target_rva=int(match["target"], 16),
                function_rva=int(match["function"], 16),
                function_end_rva=int(match["function_end"], 16),
                truncated=match["truncated"] == "1",
                data=data,
            )
            key = (record.type_id, record.target_rva)
            previous = code.get(key)
            if previous is not None and previous != record:
                raise ValueError(f"conflicting SCHEMA_CODE on line {line_number}")
            code[key] = record
    return events, targets, code, counts, errors


def parse_extended_log(
    path: Path,
) -> tuple[
    dict[tuple[int, int], SchemaResolution],
    dict[int, SchemaHelperCode],
    dict[tuple[int, int, int], SchemaNestedCode],
    dict[int, SchemaNestedForwardCode],
]:
    resolutions: dict[tuple[int, int], SchemaResolution] = {}
    helpers: dict[int, SchemaHelperCode] = {}
    nested: dict[tuple[int, int, int], SchemaNestedCode] = {}
    nested_forward: dict[int, SchemaNestedForwardCode] = {}

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line:
            continue
        event_name = line.split(maxsplit=1)[0]
        if event_name == "SCHEMA_RESOLUTION":
            match = RESOLUTION_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed SCHEMA_RESOLUTION on line {line_number}")
            record = SchemaResolution(
                type_id=int(match["type"], 16),
                target_rva=int(match["target"], 16),
                resolved_rva=int(match["resolved"], 16),
                object_adjustment=int(match["adjustment"]),
                steps=int(match["steps"]),
            )
            key = (record.type_id, record.target_rva)
            previous = resolutions.get(key)
            if previous is not None and previous != record:
                raise ValueError(f"conflicting SCHEMA_RESOLUTION on line {line_number}")
            resolutions[key] = record
        elif event_name == "SCHEMA_HELPER_CODE":
            match = HELPER_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed SCHEMA_HELPER_CODE on line {line_number}")
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"helper byte-count mismatch on line {line_number}")
            record = SchemaHelperCode(
                target_rva=int(match["target"], 16),
                resolved_rva=(
                    int(match["resolved"], 16)
                    if match["resolved"] is not None
                    else None
                ),
                object_adjustment=(
                    int(match["adjustment"])
                    if match["adjustment"] is not None
                    else None
                ),
                resolution_steps=(
                    int(match["steps"])
                    if match["steps"] is not None
                    else None
                ),
                function_rva=int(match["function"], 16),
                function_end_rva=int(match["function_end"], 16),
                truncated=match["truncated"] == "1",
                data=data,
            )
            previous = helpers.get(record.target_rva)
            if previous is not None and previous != record:
                raise ValueError(f"conflicting SCHEMA_HELPER_CODE on line {line_number}")
            helpers[record.target_rva] = record
        elif event_name == "SCHEMA_NESTED_CODE":
            match = NESTED_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed SCHEMA_NESTED_CODE on line {line_number}")
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"nested byte-count mismatch on line {line_number}")
            record = SchemaNestedCode(
                root_rva=int(match["root"], 16),
                depth=int(match["depth"]),
                target_rva=int(match["target"], 16),
                function_rva=int(match["function"], 16),
                function_end_rva=int(match["function_end"], 16),
                truncated=match["truncated"] == "1",
                data=data,
            )
            key = (record.root_rva, record.depth, record.target_rva)
            previous = nested.get(key)
            if previous is not None and previous != record:
                raise ValueError(f"conflicting SCHEMA_NESTED_CODE on line {line_number}")
            nested[key] = record
        elif event_name == "SCHEMA_NESTED_FORWARD_CODE":
            match = NESTED_FORWARD_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed SCHEMA_NESTED_FORWARD_CODE on line {line_number}"
                )
            data = bytes.fromhex(match["bytes"])
            length = int(match["length"])
            if len(data) != length:
                raise ValueError(
                    f"nested forward byte-count mismatch on line {line_number}"
                )
            record = SchemaNestedForwardCode(
                root_rva=int(match["root"], 16),
                window_start_rva=int(match["start"], 16),
                window_end_rva=int(match["end"], 16),
                data=data,
            )
            if record.window_end_rva - record.window_start_rva != length:
                raise ValueError(
                    f"nested forward range mismatch on line {line_number}"
                )
            previous = nested_forward.get(record.root_rva)
            if previous is not None and previous != record:
                raise ValueError(
                    f"conflicting SCHEMA_NESTED_FORWARD_CODE on line {line_number}"
                )
            nested_forward[record.root_rva] = record
    return resolutions, helpers, nested, nested_forward


def disassemble(record: SchemaCode, objdump: str) -> str:
    with tempfile.NamedTemporaryFile(prefix="isac-schema-", suffix=".bin") as file:
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
                f"--adjust-vma={record.function_rva:#x}",
                file.name,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="project-isac-dispatch-probe.log")
    parser.add_argument("--timeline", action="store_true")
    parser.add_argument("--disassemble", action="store_true")
    parser.add_argument(
        "--calls",
        action="store_true",
        help="summarize direct call targets from captured deserializers",
    )
    parser.add_argument(
        "--helpers",
        action="store_true",
        help="show captured primitive-reader helper implementations",
    )
    parser.add_argument(
        "--nested",
        action="store_true",
        help="show the focused nested-parser graph",
    )
    parser.add_argument("--type", type=lambda value: int(value, 0))
    parser.add_argument("--objdump", default=shutil.which("objdump"))
    args = parser.parse_args()
    if (args.disassemble or args.calls) and args.objdump is None:
        parser.error("objdump was not found")

    try:
        events, targets, code, counts, errors = parse_log(args.log)
        resolutions, helpers, nested, nested_forward = parse_extended_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    selected_targets = [
        record
        for record in targets.values()
        if args.type is None or record.type_id == args.type
    ]
    print(f"Log: {args.log}")
    print(f"Schema events: {len(events)}")
    print(f"Unique type/deserializer pairs: {len(targets)}")
    print(f"Unique message types: {len({record.type_id for record in targets.values()})}")
    print(f"Code windows: {len(code)}")
    print(f"Resolved deserializer thunks: {len(resolutions)}")
    print(f"Helper code windows: {len(helpers)}")
    print(f"Nested code windows: {len(nested)}")
    print(f"Nested forward windows: {len(nested_forward)}")
    print(f"Truncated code windows: {sum(record.truncated for record in code.values())}")
    print(f"Truncated helper windows: {sum(record.truncated for record in helpers.values())}")
    print(f"Truncated nested windows: {sum(record.truncated for record in nested.values())}")
    print(f"Events without cursor metadata: {sum(not record.has_cursor for record in events)}")
    print(f"Schema errors: {len(errors)}")
    print(f"Event limit records: {counts['SCHEMA_EVENT_LIMIT']}")
    print(f"Target limit records: {counts['SCHEMA_TARGET_LIMIT']}")
    for error in errors:
        print(f"WARNING: {error}")

    type_counts = Counter(record.type_id for record in events)
    for target in sorted(
        selected_targets,
        key=lambda record: (record.type_id, record.deserialize_rva),
    ):
        record = code.get((target.type_id, target.deserialize_rva))
        resolution = resolutions.get((target.type_id, target.deserialize_rva))
        resolved_rva = (
            f"{resolution.resolved_rva:#x}" if resolution is not None else "-"
        )
        object_adjustment = (
            f"{resolution.object_adjustment:+#x}"
            if resolution is not None
            else "-"
        )
        print(
            f"schema-target type={target.type_id:#06x} "
            f"events={type_counts[target.type_id]} "
            f"vtable_rva={target.vtable_rva:#x} "
            f"deserialize_rva={target.deserialize_rva:#x} "
            f"slot08_rva={target.slot08_rva:#x} "
            f"slot28_rva={target.slot28_rva:#x} "
            f"resolved_rva={resolved_rva} "
            f"object_adjustment={object_adjustment} "
            f"code_bytes={len(record.data) if record is not None else 0}"
        )
        if record is None:
            continue
        assembly = None
        if args.disassemble or args.calls:
            try:
                assembly = disassemble(record, args.objdump)
            except subprocess.CalledProcessError as error:
                parser.error(error.stderr.strip() or "objdump failed")
        if args.calls and assembly is not None:
            calls = Counter(int(match["target"], 16) for match in CALL_PATTERN.finditer(assembly))
            print(
                "  direct-calls="
                + (",".join(f"{target:#x}:{count}" for target, count in sorted(calls.items())) or "none")
            )
        if args.disassemble and assembly is not None:
            print(assembly)

    if args.helpers:
        for helper in sorted(helpers.values(), key=lambda record: record.target_rva):
            resolved = (
                f"{helper.resolved_rva:#x}"
                if helper.resolved_rva is not None
                else "-"
            )
            print(
                f"schema-helper target_rva={helper.target_rva:#x} "
                f"resolved_rva={resolved} "
                f"function_rva={helper.function_rva:#x} "
                f"function_end_rva={helper.function_end_rva:#x} "
                f"code_bytes={len(helper.data)} truncated={int(helper.truncated)}"
            )
            assembly = None
            if args.disassemble or args.calls:
                try:
                    assembly = disassemble(helper, args.objdump)
                except subprocess.CalledProcessError as error:
                    parser.error(error.stderr.strip() or "objdump failed")
            if args.calls and assembly is not None:
                calls = Counter(
                    int(match["target"], 16)
                    for match in CALL_PATTERN.finditer(assembly)
                )
                print(
                    "  direct-calls="
                    + (
                        ",".join(
                            f"{target:#x}:{count}"
                            for target, count in sorted(calls.items())
                        )
                        or "none"
                    )
                )
            if args.disassemble and assembly is not None:
                print(assembly)

    if args.nested:
        for record in sorted(
            nested_forward.values(),
            key=lambda item: item.root_rva,
        ):
            print(
                f"schema-nested-forward root_rva={record.root_rva:#x} "
                f"window_start_rva={record.window_start_rva:#x} "
                f"window_end_rva={record.window_end_rva:#x} "
                f"code_bytes={len(record.data)}"
            )
            if args.disassemble or args.calls:
                try:
                    assembly = disassemble(record, args.objdump)
                except subprocess.CalledProcessError as error:
                    parser.error(error.stderr.strip() or "objdump failed")
                if args.calls:
                    calls = Counter(
                        int(match["target"], 16)
                        for match in CALL_PATTERN.finditer(assembly)
                    )
                    print(
                        "  direct-calls="
                        + (
                            ",".join(
                                f"{target:#x}:{count}"
                                for target, count in sorted(calls.items())
                            )
                            or "none"
                        )
                    )
                if args.disassemble:
                    print(assembly)
        for record in sorted(
            nested.values(),
            key=lambda item: (item.root_rva, item.depth, item.target_rva),
        ):
            print(
                f"schema-nested root_rva={record.root_rva:#x} "
                f"depth={record.depth} target_rva={record.target_rva:#x} "
                f"function_rva={record.function_rva:#x} "
                f"function_end_rva={record.function_end_rva:#x} "
                f"code_bytes={len(record.data)} truncated={int(record.truncated)}"
            )
            assembly = None
            if args.disassemble or args.calls:
                try:
                    assembly = disassemble(record, args.objdump)
                except subprocess.CalledProcessError as error:
                    parser.error(error.stderr.strip() or "objdump failed")
            if args.calls and assembly is not None:
                calls = Counter(
                    int(match["target"], 16)
                    for match in CALL_PATTERN.finditer(assembly)
                )
                print(
                    "  direct-calls="
                    + (
                        ",".join(
                            f"{target:#x}:{count}"
                            for target, count in sorted(calls.items())
                        )
                        or "none"
                    )
                )
            if args.disassemble and assembly is not None:
                print(assembly)

    if args.timeline and events:
        first_tick = events[0].tick
        print("Schema timeline:")
        for record in events:
            if args.type is not None and record.type_id != args.type:
                continue
            print(
                f"  sequence={record.sequence} elapsed-ms={record.tick - first_tick} "
                f"type={record.type_id:#06x} "
                f"deserialize_rva={record.deserialize_rva:#x} "
                f"cursor={record.local_cursor}/{record.buffer_length} "
                f"absolute={record.absolute_cursor} has_cursor={int(record.has_cursor)}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
