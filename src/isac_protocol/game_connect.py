"""Game-service connect reply, NOT the control-service type-2 schema."""
from dataclasses import dataclass, field

from .codec import Cursor, DecodeError, encode_bool


@dataclass(frozen=True)
class GameConnectReply:
    identifier: bytes = field(repr=False)
    rejected: bool


def decode_game_connect_reply(body: bytes) -> GameConnectReply:
    # Reader 0x22556c0, consumer 0x9e690: false takes the success callback
    # with status 0 and transfers the channel; true closes it with status 3.
    c = Cursor(body)
    identifier = c.read(16)
    flag = c.read_u8_varint()
    if flag > 1 or c.remaining:
        raise DecodeError('invalid game-connect flag or trailing bytes')
    return GameConnectReply(identifier, bool(flag))


def encode_game_connect_reply(value: GameConnectReply) -> bytes:
    if len(value.identifier) != 16:
        raise ValueError('game-connect identifier requires 16 bytes')
    return value.identifier + encode_bool(value.rejected)
