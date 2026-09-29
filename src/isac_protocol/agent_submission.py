"""Observed world-channel 0x000c character submission.

The client reader at RVA 0x178dd10 permits an alternate branch and up to 32
float slots. This codec intentionally supports only the captured 147-byte
branch: raw character ID, zero branch flag, 32 float32 values, final flag.
The business meaning of the final flag is not established.
"""

from dataclasses import dataclass

from .codec import Cursor, DecodeError, WireFloat32, encode_uvarint


@dataclass(frozen=True)
class AgentSubmission:
    character_id: bytes
    float_slots: tuple[WireFloat32, ...]
    final_flag: bool

    def __post_init__(self):
        if len(self.character_id) != 16:
            raise ValueError('agent submission requires a 16-byte character ID')
        if len(self.float_slots) != 32 or not all(isinstance(v, WireFloat32) for v in self.float_slots):
            raise ValueError('observed agent submission requires 32 float32 slots')
        if not isinstance(self.final_flag, bool):
            raise ValueError('final flag requires bool')


def decode_agent_submission(body: bytes, _table=None) -> AgentSubmission:
    if len(body) != 147:
        raise DecodeError('unsupported agent submission length')
    cursor = Cursor(body)
    character_id = cursor.read(16)
    if cursor.read_u8_varint() != 0:
        raise DecodeError('unsupported agent submission branch')
    if cursor.read_uvarint(maximum_bits=32) != 32:
        raise DecodeError('unsupported agent float-slot count')
    floats = tuple(cursor.read_float32() for _ in range(32))
    flag = cursor.read_u8_varint()
    if flag > 1 or cursor.remaining:
        raise DecodeError('noncanonical agent submission tail')
    result = AgentSubmission(character_id, floats, bool(flag))
    if encode_agent_submission(result) != body:
        raise DecodeError('noncanonical agent submission encoding')
    return result


def encode_agent_submission(value: AgentSubmission, _table=None) -> bytes:
    if not isinstance(value, AgentSubmission):
        raise TypeError('agent submission model required')
    return (value.character_id + b'\x00' + encode_uvarint(32, maximum_bits=32)
            + b''.join(slot.encode() for slot in value.float_slots)
            + bytes([int(value.final_flag)]))
