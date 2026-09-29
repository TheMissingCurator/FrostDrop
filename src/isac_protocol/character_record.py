"""Version-8 character-list blob, reader RVA 0xcc6800 (finding 111).

This is presentation/customization data, not a complete world save. Unknown
scalar meanings stay offset-named; fixed-width fields are little-endian,
whereas version and top-level collection counts are unsigned varints.
"""
from dataclasses import dataclass
import struct

from .codec import Cursor, DecodeError, encode_uvarint


@dataclass(frozen=True)
class CharacterNode:
    words_0_8: tuple[int, int]
    bytes_34_35: bytes
    words_10_18: tuple[int, int]
    bits_30: int
    bytes_36_37: bytes
    children: tuple
    words_38_40: tuple[int, int]


@dataclass(frozen=True)
class CharacterRecord:
    flag_450: bool
    nodes: tuple[CharacterNode, ...]
    float_bits_458: tuple[int, ...]
    pairs_4d8: tuple[tuple[int, int], ...]
    words_510_528: tuple[int, int, int, int]
    words_530_538: tuple[int, int, int]
    bits_53c: int

    @property
    def client_accepts_customized_data(self):
        # Final return at 0xcc6b58 requires both collections nonempty.
        return bool(self.nodes and self.float_bits_458)


def decode_character_record(body: bytes) -> CharacterRecord:
    if len(body) > 10000:
        raise DecodeError("oversized character record")
    c = Cursor(body)
    def fixed(fmt):
        return struct.unpack('<' + fmt, c.read(struct.calcsize('<' + fmt)))
    def count():
        n = c.read_uvarint(maximum_bits=32)
        if n > 256:
            raise DecodeError("character collection bound exceeded")
        return n
    budget = 256
    def node(depth=0):
        nonlocal budget
        budget -= 1
        if depth > 8 or budget < 0:
            raise DecodeError("character node nesting bound exceeded")
        a, b, d, e, f = fixed('QQ'), c.read(2), fixed('QQ'), fixed('I')[0], c.read(2)
        n = fixed('I')[0]  # Nested count is fixed-width, unlike top-level.
        if n > budget:
            raise DecodeError("character child count bound exceeded")
        children = tuple(node(depth + 1) for _ in range(n))
        return CharacterNode(a, b, d, e, f, children, fixed('QQ'))
    if c.read_uvarint(maximum_bits=32) != 8:
        raise DecodeError("unsupported character record version")
    flag = c.read(1)[0]
    if flag > 1:
        raise DecodeError("noncanonical character flag")
    nodes = tuple(node() for _ in range(count()))
    floats = tuple(fixed('I')[0] for _ in range(count()))
    pairs = tuple(fixed('QQ') for _ in range(count()))
    value = CharacterRecord(bool(flag), nodes, floats, pairs, fixed('QQQQ'), fixed('III'), fixed('I')[0])
    if c.remaining:
        raise DecodeError("trailing character record data")
    return value


def encode_character_record(value: CharacterRecord) -> bytes:
    def node(n):
        return (struct.pack('<QQ', *n.words_0_8) + n.bytes_34_35
                + struct.pack('<QQI', *n.words_10_18, n.bits_30) + n.bytes_36_37
                + struct.pack('<I', len(n.children)) + b''.join(node(v) for v in n.children)
                + struct.pack('<QQ', *n.words_38_40))
    wire = (b'\x08' + bytes([value.flag_450]) + encode_uvarint(len(value.nodes))
            + b''.join(node(n) for n in value.nodes)
            + encode_uvarint(len(value.float_bits_458))
            + b''.join(struct.pack('<I', n) for n in value.float_bits_458)
            + encode_uvarint(len(value.pairs_4d8))
            + b''.join(struct.pack('<QQ', *p) for p in value.pairs_4d8)
            + struct.pack('<QQQQIIII', *value.words_510_528, *value.words_530_538, value.bits_53c))
    if decode_character_record(wire) != value:
        raise ValueError("invalid character record")
    return wire


def starting_character_record() -> CharacterRecord:
    # Fully reconstructed from typed defaults; no retail IDs, timestamps,
    # tokens, item identifiers, or opaque capture bytes are imported.
    return CharacterRecord(True, (), (0,) * 27, (), (0, 0, 0, 0), (0, 1, 1), 0)
