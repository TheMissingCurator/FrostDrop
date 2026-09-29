"""Private timed world-bootstrap replay artifact support."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from isac_protocol import DecodeError, InboundFrameStreamDecoder


CAPTURE_MAGIC = b"ISACWBS1"
BRIDGE_REPLAY_HEADER = struct.pack("<8sII", b"ISACRPL1", 1, 0)
_HEADER = struct.Struct("<8sIIQII")
_RECORD = struct.Struct("<QII")
_FLAG_SYNC = 0x01
_FLAG_GATE_COMPLETE = 0x08


@dataclass(frozen=True)
class TimedWorldSpan:
    delta_ms: int
    flags: int
    data: bytes


@dataclass(frozen=True)
class WorldReplay:
    request_tick_ms: int
    spans: tuple[TimedWorldSpan, ...]
    frame_count: int
    first_gate_frame: int

    @property
    def duration_ms(self) -> int:
        return self.spans[-1].delta_ms

    @property
    def payload_bytes(self) -> int:
        return sum(len(span.data) for span in self.spans)

    @classmethod
    def from_file(cls, path: Path) -> "WorldReplay":
        return cls.from_bytes(path.read_bytes())

    @classmethod
    def from_bytes(cls, wire: bytes) -> "WorldReplay":
        if len(wire) < _HEADER.size:
            raise ValueError("world replay is shorter than its header")
        magic, version, header_size, request_tick, flags, reserved = _HEADER.unpack_from(
            wire
        )
        if magic != CAPTURE_MAGIC:
            raise ValueError("world replay magic is not ISACWBS1")
        if version != 1 or header_size != _HEADER.size:
            raise ValueError("unsupported world replay version")
        if flags != 1 or reserved != 0:
            raise ValueError("unsupported world replay flags")

        spans: list[TimedWorldSpan] = []
        offset = header_size
        previous_delta = 0
        while offset < len(wire):
            if len(wire) - offset < _RECORD.size:
                raise ValueError("truncated world replay span header")
            delta_ms, length, span_flags = _RECORD.unpack_from(wire, offset)
            offset += _RECORD.size
            end = offset + length
            if length == 0 or end > len(wire):
                raise ValueError("invalid world replay span length")
            if spans and delta_ms < previous_delta:
                raise ValueError("world replay timestamps are not monotonic")
            spans.append(TimedWorldSpan(delta_ms, span_flags, wire[offset:end]))
            previous_delta = delta_ms
            offset = end

        if not spans or not spans[0].flags & _FLAG_SYNC:
            raise ValueError("world replay does not begin with a sync span")
        if sum(bool(span.flags & _FLAG_SYNC) for span in spans) != 1:
            raise ValueError("world replay must contain exactly one sync span")
        if sum(bool(span.flags & _FLAG_GATE_COMPLETE) for span in spans) != 1:
            raise ValueError("world replay must contain exactly one completed gate span")

        decoder = InboundFrameStreamDecoder(maximum_frame_length=16_777_216)
        frames = []
        try:
            for span in spans:
                frames.extend(decoder.feed(span.data))
        except DecodeError as error:
            raise ValueError(f"world replay stream is invalid: {error}") from error
        if decoder.buffered_bytes:
            raise ValueError("world replay ends with an incomplete frame")
        if not frames or frames[0].type_id != 0x0002:
            raise ValueError("world replay does not start with type 0x0002")
        gate_index = next(
            (index for index, frame in enumerate(frames) if frame.type_id == 0x0012),
            None,
        )
        if gate_index is None:
            raise ValueError("world replay contains no type 0x0012 gate frame")
        return cls(
            request_tick_ms=request_tick,
            spans=tuple(spans),
            frame_count=len(frames),
            first_gate_frame=gate_index + 1,
        )
