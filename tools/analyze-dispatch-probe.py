#!/usr/bin/env python3
"""Summarize and optionally disassemble Project ISAC dispatch-probe results."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


TARGET_PATTERN = re.compile(
    r"^DISPATCH_TARGET "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"kind=(?P<kind>inbound-handler|message-type-method|outbound-type-method) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+)$"
)
CODE_PATTERN = re.compile(
    r"^DISPATCH_CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"kind=(?P<kind>inbound-handler|message-type-method|outbound-type-method) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
TYPE_ID_PATTERN = re.compile(
    r"^DISPATCH_TYPE_ID "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"source_rva=(?P<source>0x[0-9a-fA-F]+) "
    r"type_id=(?P<type_id>0x[0-9a-fA-F]{4})$"
)
EVENT_PATTERN = re.compile(
    r"^DISPATCH_EVENT "
    r"sequence=(?P<sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"(?:direction=(?P<direction>inbound|outbound) )?"
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"type_id=(?P<type_id>0x[0-9a-fA-F]{4})$"
)
CALLER_PATTERN = re.compile(
    r"^DISPATCH_CALLER "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"type_id=(?P<type_id>0x[0-9a-fA-F]{4}) "
    r"return_rva=(?P<return_rva>0x[0-9a-fA-F]+)$"
)
CALLER_CODE_PATTERN = re.compile(
    r"^DISPATCH_CALLER_CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"return_rva=(?P<return_rva>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start_rva>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
INBOUND_BATCH_CALLER_PATTERN = re.compile(
    r"^INBOUND_BATCH_CALLER "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"return_rva=(?P<return_rva>0x[0-9a-fA-F]+)$"
)
INBOUND_SCHEDULER_CALLER_PATTERN = re.compile(
    r"^INBOUND_SCHEDULER_CALLER "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"return_rva=(?P<return_rva>0x[0-9a-fA-F]+)$"
)
QUEUE_WRITE_PATTERN = re.compile(
    r"^INBOUND_QUEUE_WRITE "
    r"sequence=(?P<sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"instruction_rva=(?P<instruction>0x[0-9a-fA-F]+) "
    r"frame_count=(?P<frame_count>\d+) "
    r"rvas=(?P<rvas>(?:0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*)?)$"
)
QUEUE_CODE_PATTERN = re.compile(
    r"^INBOUND_QUEUE_CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"kind=(?P<kind>writer|stack-candidate|producer-caller|"
    r"inbound-source-write|inbound-source-caller|reader-vtable-xref|vtable-method) "
    r"anchor_rva=(?P<anchor>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
QUEUE_PRODUCER_PATTERN = re.compile(
    r"^INBOUND_QUEUE_PRODUCER "
    r"sequence=(?P<sequence>\d+) "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"instruction_rva=(?P<instruction>0x[0-9a-fA-F]+) "
    r"type_id=(?P<type_id>0x[0-9a-fA-F]{4}) "
    r"queue_count=(?P<queue_count>\d+) "
    r"queue_capacity=(?P<queue_capacity>\d+) "
    r"function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"function_end_rva=(?P<function_end>0x[0-9a-fA-F]+) "
    r"frame_count=(?P<frame_count>\d+) "
    r"rvas=(?P<rvas>(?:0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*)?)$"
)
QUEUE_PRODUCER_CODE_PATTERN = re.compile(
    r"^INBOUND_QUEUE_PRODUCER_CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"function_end_rva=(?P<function_end>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
INBOUND_READER_CODE_PATTERN = re.compile(
    r"^INBOUND_READER_CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"kind=(?P<kind>read-next|context-init|virtual-read-next|virtual-read-helper|virtual-context-copy|source-advance|source-object-constructor|reader-constructor-a|reader-constructor-b|reader-setup-a|reader-setup-b|reader-register|registration-constructor|transport-delivery|source-append|reader-lock|reader-notify|reader-unlock) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"function_rva=(?P<function>0x[0-9a-fA-F]+) "
    r"function_end_rva=(?P<function_end>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)
INBOUND_READER_FORWARD_CODE_PATTERN = re.compile(
    r"^INBOUND_READER_FORWARD_CODE "
    r"tick_ms=(?P<tick>\d+) "
    r"process=(?P<process>\d+) "
    r"thread=(?P<thread>\d+) "
    r"kind=(?P<kind>read-next|context-init|virtual-read-next|virtual-read-helper|virtual-context-copy|source-advance|source-object-constructor|reader-constructor-a|reader-constructor-b|reader-setup-a|reader-setup-b|reader-register|registration-constructor|transport-delivery|source-append|reader-lock|reader-notify|reader-unlock) "
    r"target_rva=(?P<target>0x[0-9a-fA-F]+) "
    r"start_rva=(?P<start>0x[0-9a-fA-F]+) "
    r"length=(?P<length>\d+) "
    r"bytes=(?P<bytes>[0-9a-fA-F]+)$"
)


@dataclass(frozen=True)
class TargetRecord:
    tick: int
    process: int
    thread: int
    kind: str
    target_rva: int


@dataclass(frozen=True)
class CodeRecord:
    tick: int
    process: int
    thread: int
    kind: str
    target_rva: int
    data: bytes


@dataclass(frozen=True)
class TypeIdRecord:
    tick: int
    process: int
    thread: int
    target_rva: int
    source_rva: int
    type_id: int


@dataclass(frozen=True)
class EventRecord:
    sequence: int
    tick: int
    process: int
    thread: int
    direction: str
    target_rva: int
    type_id: int


@dataclass(frozen=True)
class CallerRecord:
    tick: int
    process: int
    thread: int
    type_id: int
    return_rva: int


@dataclass(frozen=True)
class CallerCodeRecord:
    tick: int
    process: int
    thread: int
    return_rva: int
    start_rva: int
    data: bytes


@dataclass(frozen=True)
class InboundBatchCallerRecord:
    tick: int
    process: int
    thread: int
    return_rva: int


@dataclass(frozen=True)
class QueueWriteRecord:
    sequence: int
    tick: int
    process: int
    thread: int
    instruction_rva: int
    rvas: tuple[int, ...]


@dataclass(frozen=True)
class QueueCodeRecord:
    tick: int
    process: int
    thread: int
    kind: str
    anchor_rva: int
    start_rva: int
    data: bytes


@dataclass(frozen=True)
class QueueProducerRecord:
    sequence: int
    tick: int
    process: int
    thread: int
    instruction_rva: int
    type_id: int
    queue_count: int
    queue_capacity: int
    function_rva: int
    function_end_rva: int
    rvas: tuple[int, ...]


@dataclass(frozen=True)
class QueueProducerCodeRecord:
    tick: int
    process: int
    thread: int
    function_rva: int
    function_end_rva: int
    data: bytes


@dataclass(frozen=True)
class InboundReaderCodeRecord:
    tick: int
    process: int
    thread: int
    kind: str
    target_rva: int
    function_rva: int
    function_end_rva: int
    data: bytes


@dataclass(frozen=True)
class InboundReaderForwardCodeRecord:
    tick: int
    process: int
    thread: int
    kind: str
    target_rva: int
    start_rva: int
    data: bytes


def parse_log(
    path: Path,
) -> tuple[
    list[TargetRecord],
    dict[tuple[str, int], CodeRecord],
    dict[int, TypeIdRecord],
    list[EventRecord],
    list[CallerRecord],
    dict[int, CallerCodeRecord],
    list[InboundBatchCallerRecord],
    list[InboundBatchCallerRecord],
    list[QueueWriteRecord],
    dict[int, QueueCodeRecord],
    list[QueueProducerRecord],
    QueueProducerCodeRecord | None,
    dict[str, InboundReaderCodeRecord],
    dict[str, InboundReaderForwardCodeRecord],
    Counter[str],
    list[str],
]:
    targets: list[TargetRecord] = []
    code: dict[tuple[str, int], CodeRecord] = {}
    type_ids: dict[int, TypeIdRecord] = {}
    dispatch_events: list[EventRecord] = []
    callers: list[CallerRecord] = []
    caller_code: dict[int, CallerCodeRecord] = {}
    inbound_batch_callers: list[InboundBatchCallerRecord] = []
    inbound_scheduler_callers: list[InboundBatchCallerRecord] = []
    queue_writes: list[QueueWriteRecord] = []
    queue_code: dict[int, QueueCodeRecord] = {}
    queue_producers: list[QueueProducerRecord] = []
    queue_producer_code: QueueProducerCodeRecord | None = None
    inbound_reader_code: dict[str, InboundReaderCodeRecord] = {}
    inbound_reader_forward_code: dict[str, InboundReaderForwardCodeRecord] = {}
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
        if event in {
            "DISPATCH_PROBE_ERROR",
            "DISPATCH_CODE_SKIPPED",
            "DISPATCH_EVENT_ERROR",
            "INBOUND_QUEUE_PRODUCER_CODE_ERROR",
            "INBOUND_READER_CODE_ERROR",
        }:
            errors.append(line)
            continue
        if event == "DISPATCH_TARGET":
            match = TARGET_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed DISPATCH_TARGET on line {line_number}")
            targets.append(
                TargetRecord(
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    kind=match["kind"],
                    target_rva=int(match["target"], 16),
                )
            )
        elif event == "DISPATCH_CODE":
            match = CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed DISPATCH_CODE on line {line_number}")
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            record = CodeRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                kind=match["kind"],
                target_rva=int(match["target"], 16),
                data=data,
            )
            key = (record.kind, record.target_rva)
            if key in code and code[key].data != data:
                raise ValueError(f"conflicting code window on line {line_number}")
            code[key] = record
        elif event == "DISPATCH_TYPE_ID":
            match = TYPE_ID_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed DISPATCH_TYPE_ID on line {line_number}")
            record = TypeIdRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                target_rva=int(match["target"], 16),
                source_rva=int(match["source"], 16),
                type_id=int(match["type_id"], 16),
            )
            if record.target_rva in type_ids and type_ids[record.target_rva] != record:
                previous = type_ids[record.target_rva]
                if (
                    previous.source_rva != record.source_rva
                    or previous.type_id != record.type_id
                ):
                    raise ValueError(f"conflicting type ID on line {line_number}")
            type_ids[record.target_rva] = record
        elif event == "DISPATCH_EVENT":
            match = EVENT_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed DISPATCH_EVENT on line {line_number}")
            dispatch_events.append(
                EventRecord(
                    sequence=int(match["sequence"]),
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    direction=match["direction"] or "inbound",
                    target_rva=int(match["target"], 16),
                    type_id=int(match["type_id"], 16),
                )
            )
        elif event == "DISPATCH_CALLER":
            match = CALLER_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"malformed DISPATCH_CALLER on line {line_number}")
            callers.append(
                CallerRecord(
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    type_id=int(match["type_id"], 16),
                    return_rva=int(match["return_rva"], 16),
                )
            )
        elif event == "DISPATCH_CALLER_CODE":
            match = CALLER_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed DISPATCH_CALLER_CODE on line {line_number}"
                )
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            record = CallerCodeRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                return_rva=int(match["return_rva"], 16),
                start_rva=int(match["start_rva"], 16),
                data=data,
            )
            previous = caller_code.get(record.return_rva)
            if previous is not None and (
                previous.start_rva != record.start_rva or
                previous.data != record.data
            ):
                raise ValueError(f"conflicting caller code on line {line_number}")
            caller_code[record.return_rva] = record
        elif event == "INBOUND_BATCH_CALLER":
            match = INBOUND_BATCH_CALLER_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_BATCH_CALLER on line {line_number}"
                )
            inbound_batch_callers.append(
                InboundBatchCallerRecord(
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    return_rva=int(match["return_rva"], 16),
                )
            )
        elif event == "INBOUND_SCHEDULER_CALLER":
            match = INBOUND_SCHEDULER_CALLER_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_SCHEDULER_CALLER on line {line_number}"
                )
            inbound_scheduler_callers.append(
                InboundBatchCallerRecord(
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    return_rva=int(match["return_rva"], 16),
                )
            )
        elif event == "INBOUND_QUEUE_WRITE":
            match = QUEUE_WRITE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_QUEUE_WRITE on line {line_number}"
                )
            rvas = tuple(
                int(value, 16)
                for value in match["rvas"].split(",")
                if value
            )
            if len(rvas) != int(match["frame_count"]):
                raise ValueError(f"frame-count mismatch on line {line_number}")
            queue_writes.append(
                QueueWriteRecord(
                    sequence=int(match["sequence"]),
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    instruction_rva=int(match["instruction"], 16),
                    rvas=rvas,
                )
            )
        elif event == "INBOUND_QUEUE_CODE":
            match = QUEUE_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_QUEUE_CODE on line {line_number}"
                )
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            record = QueueCodeRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                kind=match["kind"],
                anchor_rva=int(match["anchor"], 16),
                start_rva=int(match["start"], 16),
                data=data,
            )
            previous = queue_code.get(record.anchor_rva)
            if previous is not None and (
                previous.start_rva != record.start_rva or
                previous.data != record.data
            ):
                raise ValueError(f"conflicting queue code on line {line_number}")
            queue_code[record.anchor_rva] = record
        elif event == "INBOUND_QUEUE_PRODUCER":
            match = QUEUE_PRODUCER_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_QUEUE_PRODUCER on line {line_number}"
                )
            rvas = tuple(
                int(value, 16)
                for value in match["rvas"].split(",")
                if value
            )
            if len(rvas) != int(match["frame_count"]):
                raise ValueError(f"frame-count mismatch on line {line_number}")
            queue_producers.append(
                QueueProducerRecord(
                    sequence=int(match["sequence"]),
                    tick=int(match["tick"]),
                    process=int(match["process"]),
                    thread=int(match["thread"]),
                    instruction_rva=int(match["instruction"], 16),
                    type_id=int(match["type_id"], 16),
                    queue_count=int(match["queue_count"]),
                    queue_capacity=int(match["queue_capacity"]),
                    function_rva=int(match["function"], 16),
                    function_end_rva=int(match["function_end"], 16),
                    rvas=rvas,
                )
            )
        elif event == "INBOUND_QUEUE_PRODUCER_CODE":
            match = QUEUE_PRODUCER_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_QUEUE_PRODUCER_CODE on line {line_number}"
                )
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            record = QueueProducerCodeRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                function_rva=int(match["function"], 16),
                function_end_rva=int(match["function_end"], 16),
                data=data,
            )
            if queue_producer_code is not None and queue_producer_code != record:
                raise ValueError(
                    f"conflicting queue producer code on line {line_number}"
                )
            queue_producer_code = record
        elif event == "INBOUND_READER_CODE":
            match = INBOUND_READER_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_READER_CODE on line {line_number}"
                )
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            record = InboundReaderCodeRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                kind=match["kind"],
                target_rva=int(match["target"], 16),
                function_rva=int(match["function"], 16),
                function_end_rva=int(match["function_end"], 16),
                data=data,
            )
            previous = inbound_reader_code.get(record.kind)
            if previous is not None and previous != record:
                raise ValueError(
                    f"conflicting inbound reader code on line {line_number}"
                )
            inbound_reader_code[record.kind] = record
        elif event == "INBOUND_READER_FORWARD_CODE":
            match = INBOUND_READER_FORWARD_CODE_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(
                    f"malformed INBOUND_READER_FORWARD_CODE on line {line_number}"
                )
            data = bytes.fromhex(match["bytes"])
            if len(data) != int(match["length"]):
                raise ValueError(f"byte-count mismatch on line {line_number}")
            record = InboundReaderForwardCodeRecord(
                tick=int(match["tick"]),
                process=int(match["process"]),
                thread=int(match["thread"]),
                kind=match["kind"],
                target_rva=int(match["target"], 16),
                start_rva=int(match["start"], 16),
                data=data,
            )
            previous = inbound_reader_forward_code.get(record.kind)
            if previous is not None and previous != record:
                raise ValueError(
                    f"conflicting inbound reader forward code on line {line_number}"
                )
            inbound_reader_forward_code[record.kind] = record
    return (
        targets,
        code,
        type_ids,
        dispatch_events,
        callers,
        caller_code,
        inbound_batch_callers,
        inbound_scheduler_callers,
        queue_writes,
        queue_code,
        queue_producers,
        queue_producer_code,
        inbound_reader_code,
        inbound_reader_forward_code,
        events,
        errors,
    )


def infer_constant_return(data: bytes) -> int | None:
    """Recognize only unambiguous constant-return stubs at the entry point."""
    if len(data) >= 6 and data[0] == 0xB8 and data[5] in {0xC3, 0xF3}:
        if data[5] == 0xC3 or (len(data) >= 7 and data[6] == 0xC3):
            return int.from_bytes(data[1:5], "little")
    if len(data) >= 5 and data[:2] == b"\x66\xb8" and data[4] == 0xC3:
        return int.from_bytes(data[2:4], "little")
    if len(data) >= 3 and data[0] == 0xB0 and data[2] == 0xC3:
        return data[1]
    if len(data) >= 3 and data[:3] in {b"\x31\xc0\xc3", b"\x33\xc0\xc3"}:
        return 0
    return None


def infer_u16_source_rva(target_rva: int, data: bytes) -> int | None:
    """Recognize movzx eax, word ptr [rip+disp32]; ret at the entry point."""
    if len(data) < 8 or data[:3] != b"\x0f\xb7\x05" or data[7] != 0xC3:
        return None
    displacement = int.from_bytes(data[3:7], "little", signed=True)
    source_rva = target_rva + 7 + displacement
    return source_rva if source_rva >= 0 else None


def disassemble(record: CodeRecord, objdump: str) -> str:
    return disassemble_bytes(record.data, record.target_rva, objdump)


def disassemble_bytes(data: bytes, start_rva: int, objdump: str) -> str:
    with tempfile.NamedTemporaryFile(prefix="isac-dispatch-", suffix=".bin") as file:
        file.write(data)
        file.flush()
        result = subprocess.run(
            [
                objdump,
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                f"--adjust-vma={start_rva:#x}",
                file.name,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    return "\n".join(
        line for line in result.stdout.splitlines() if not line.startswith(file.name)
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize Project ISAC dispatch targets and code windows."
    )
    parser.add_argument("log", type=Path, help="project-isac-dispatch-probe.log")
    parser.add_argument(
        "--kind",
        choices=(
            "all",
            "inbound-handler",
            "message-type-method",
            "outbound-type-method",
        ),
        default="all",
        help="restrict displayed records",
    )
    parser.add_argument(
        "--disassemble",
        action="store_true",
        help="print objdump output for every selected code window",
    )
    parser.add_argument(
        "--disassemble-callers",
        action="store_true",
        help="print objdump output for each caller code window",
    )
    parser.add_argument(
        "--disassemble-queue",
        action="store_true",
        help="print objdump output for queue-writer and stack-anchor windows",
    )
    parser.add_argument(
        "--objdump",
        default=shutil.which("objdump"),
        help="objdump-compatible executable",
    )
    parser.add_argument(
        "--events",
        choices=("none", "summary", "timeline"),
        default="none",
        help="print no events, per-type counts, or the complete event timeline",
    )
    args = parser.parse_args()
    if (
        args.disassemble or
        args.disassemble_callers or
        args.disassemble_queue
    ) and args.objdump is None:
        parser.error("objdump was not found")

    try:
        (
            targets,
            code,
            type_ids,
            dispatch_events,
            callers,
            caller_code,
            inbound_batch_callers,
            inbound_scheduler_callers,
            queue_writes,
            queue_code,
            queue_producers,
            queue_producer_code,
            inbound_reader_code,
            inbound_reader_forward_code,
            events,
            errors,
        ) = parse_log(args.log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Ready events: {events['DISPATCH_PROBE_READY']}")
    print(f"Error events: {events['DISPATCH_PROBE_ERROR']}")
    print(f"Limit events: {events['DISPATCH_PROBE_LIMIT']}")
    print(f"Unique targets: {len(targets)}")
    print(f"Code windows: {len(code)}")
    print(f"Captured type IDs: {len(type_ids)}")
    unique_type_ids = {record.type_id for record in type_ids.values()}
    print(f"Unique numeric type IDs: {len(unique_type_ids)}")
    print(f"Dispatch events: {len(dispatch_events)}")
    print(f"Dispatch caller pairs: {len(callers)}")
    print(f"Caller code windows: {len(caller_code)}")
    print(f"Inbound batch callers: {len(inbound_batch_callers)}")
    print(f"Batch caller limit events: {events['INBOUND_BATCH_CALLER_LIMIT']}")
    print(f"Inbound scheduler callers: {len(inbound_scheduler_callers)}")
    print(
        "Scheduler caller limit events: "
        f"{events['INBOUND_SCHEDULER_CALLER_LIMIT']}"
    )
    print(f"Inbound queue writes: {len(queue_writes)}")
    print(f"Inbound queue code windows: {len(queue_code)}")
    print(f"Inbound queue producer events: {len(queue_producers)}")
    print(
        "Inbound queue producer code windows: "
        f"{int(queue_producer_code is not None)}"
    )
    print(f"Inbound reader code windows: {len(inbound_reader_code)}")
    print(
        "Inbound reader forward windows: "
        f"{len(inbound_reader_forward_code)}"
    )
    print(f"Queue watch errors: {events['INBOUND_QUEUE_WATCH_ERROR']}")
    print(f"Queue write limit events: {events['INBOUND_QUEUE_WRITE_LIMIT']}")
    print(f"Queue code limit events: {events['INBOUND_QUEUE_CODE_LIMIT']}")
    print(
        "Queue producer limit events: "
        f"{events['INBOUND_QUEUE_PRODUCER_LIMIT']}"
    )
    print(f"Caller limit events: {events['DISPATCH_CALLER_LIMIT']}")
    print(f"Event limit events: {events['DISPATCH_EVENT_LIMIT']}")
    for kind in (
        "inbound-handler",
        "message-type-method",
        "outbound-type-method",
    ):
        selected = [target for target in targets if target.kind == kind]
        captured = sum((kind, target.target_rva) in code for target in selected)
        print(f"{kind}: {len(selected)} targets; {captured} code windows")
    for error in errors:
        print(f"WARNING: {error}")

    for caller in sorted(callers, key=lambda record: (record.return_rva, record.type_id)):
        print(
            f"dispatch-caller type_id={caller.type_id} ({caller.type_id:#06x}) "
            f"return_rva={caller.return_rva:#x} tick={caller.tick} "
            f"pid={caller.process} tid={caller.thread}"
        )

    for return_rva, record in sorted(caller_code.items()):
        print(
            f"dispatch-caller-code return_rva={return_rva:#x} "
            f"start_rva={record.start_rva:#x} code_bytes={len(record.data)}"
        )
        if args.disassemble_callers:
            try:
                print(disassemble_bytes(record.data, record.start_rva, args.objdump))
            except subprocess.CalledProcessError as error:
                parser.error(error.stderr.strip() or "objdump failed")

    for caller in sorted(inbound_batch_callers, key=lambda record: record.return_rva):
        print(
            f"inbound-batch-caller return_rva={caller.return_rva:#x} "
            f"tick={caller.tick} pid={caller.process} tid={caller.thread}"
        )

    for caller in sorted(
        inbound_scheduler_callers,
        key=lambda record: record.return_rva,
    ):
        print(
            f"inbound-scheduler-caller return_rva={caller.return_rva:#x} "
            f"tick={caller.tick} pid={caller.process} tid={caller.thread}"
        )

    for record in queue_writes:
        print(
            f"inbound-queue-write sequence={record.sequence} "
            f"instruction_rva={record.instruction_rva:#x} "
            f"stack_rvas={','.join(hex(rva) for rva in record.rvas) or 'none'} "
            f"tick={record.tick} pid={record.process} tid={record.thread}"
        )
    for record in queue_producers:
        print(
            f"inbound-queue-producer sequence={record.sequence} "
            f"type_id={record.type_id} ({record.type_id:#06x}) "
            f"queue={record.queue_count}/{record.queue_capacity} "
            f"function_rva={record.function_rva:#x} "
            f"function_end_rva={record.function_end_rva:#x} "
            f"caller_rvas={','.join(hex(rva) for rva in record.rvas) or 'none'} "
            f"tick={record.tick} pid={record.process} tid={record.thread}"
        )
    if queue_producer_code is not None:
        print(
            "inbound-queue-producer-code "
            f"function_rva={queue_producer_code.function_rva:#x} "
            f"function_end_rva={queue_producer_code.function_end_rva:#x} "
            f"code_bytes={len(queue_producer_code.data)}"
        )
        if args.disassemble_queue:
            try:
                print(
                    disassemble_bytes(
                        queue_producer_code.data,
                        queue_producer_code.function_rva,
                        args.objdump,
                    )
                )
            except subprocess.CalledProcessError as error:
                parser.error(error.stderr.strip() or "objdump failed")
    for kind, record in sorted(inbound_reader_code.items()):
        print(
            f"inbound-reader-code kind={kind} target_rva={record.target_rva:#x} "
            f"function_rva={record.function_rva:#x} "
            f"function_end_rva={record.function_end_rva:#x} "
            f"code_bytes={len(record.data)}"
        )
        if args.disassemble_queue:
            try:
                print(disassemble_bytes(record.data, record.function_rva, args.objdump))
            except subprocess.CalledProcessError as error:
                parser.error(error.stderr.strip() or "objdump failed")
    for kind, record in sorted(inbound_reader_forward_code.items()):
        print(
            f"inbound-reader-forward-code kind={kind} "
            f"target_rva={record.target_rva:#x} start_rva={record.start_rva:#x} "
            f"code_bytes={len(record.data)}"
        )
        if args.disassemble_queue:
            try:
                print(disassemble_bytes(record.data, record.start_rva, args.objdump))
            except subprocess.CalledProcessError as error:
                parser.error(error.stderr.strip() or "objdump failed")
    for anchor_rva, record in sorted(queue_code.items()):
        print(
            f"inbound-queue-code kind={record.kind} anchor_rva={anchor_rva:#x} "
            f"start_rva={record.start_rva:#x} code_bytes={len(record.data)}"
        )
        if args.disassemble_queue:
            try:
                print(disassemble_bytes(record.data, record.start_rva, args.objdump))
            except subprocess.CalledProcessError as error:
                parser.error(error.stderr.strip() or "objdump failed")

    for target in targets:
        if args.kind != "all" and target.kind != args.kind:
            continue
        record = code.get((target.kind, target.target_rva))
        type_record = type_ids.get(target.target_rva)
        hint = infer_constant_return(record.data) if record is not None else None
        source_hint = (
            infer_u16_source_rva(target.target_rva, record.data)
            if record is not None and target.kind in {
                "message-type-method",
                "outbound-type-method",
            }
            else None
        )
        suffix = " code=missing"
        if record is not None:
            suffix = f" code_bytes={len(record.data)}"
        if hint is not None:
            suffix += f" constant_return={hint} ({hint:#06x})"
        if type_record is not None:
            suffix += (
                f" type_id={type_record.type_id} ({type_record.type_id:#06x})"
                f" source_rva={type_record.source_rva:#x}"
            )
        elif source_hint is not None:
            suffix += f" u16_source_rva={source_hint:#x} value=not-captured"
        print(
            f"{target.kind} rva={target.target_rva:#x} tick={target.tick} "
            f"pid={target.process} tid={target.thread}{suffix}"
        )
        if args.disassemble and record is not None:
            try:
                print(disassemble(record, args.objdump))
            except subprocess.CalledProcessError as error:
                parser.error(error.stderr.strip() or "objdump failed")
    if args.events == "summary":
        by_type: dict[tuple[str, int], list[EventRecord]] = {}
        for event_record in dispatch_events:
            key = (event_record.direction, event_record.type_id)
            by_type.setdefault(key, []).append(event_record)
        for (direction, type_id), records in sorted(
            by_type.items(), key=lambda item: (-len(item[1]), item[0])
        ):
            print(
                f"event-type direction={direction} "
                f"type_id={type_id} ({type_id:#06x}) "
                f"count={len(records)} first_tick={min(r.tick for r in records)} "
                f"last_tick={max(r.tick for r in records)}"
            )
    elif args.events == "timeline":
        for event_record in sorted(
            dispatch_events, key=lambda record: (record.tick, record.sequence)
        ):
            print(
                f"dispatch-event sequence={event_record.sequence} "
                f"direction={event_record.direction} "
                f"type_id={event_record.type_id} ({event_record.type_id:#06x}) "
                f"tick={event_record.tick} pid={event_record.process} "
                f"tid={event_record.thread} rva={event_record.target_rva:#x}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
