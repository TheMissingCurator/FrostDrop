"""Main transport's uint16-LE length + streaming LZ4 blocks (finding 096).

This is below root framing and above TLS, not an LZ4 frame-file container.
The client bounds compressed blocks to 1019 bytes and output to 1000 bytes.
Outbound literal-only blocks need no dictionary or third-party dependency.
Inbound matches may refer to previous blocks on the same connection.
"""
from .codec import DecodeError

MAX_BLOCK = 1019
MAX_OUTPUT = 1000


def encode_compressed_stream(data: bytes) -> bytes:
    result = bytearray()
    for offset in range(0, len(data), MAX_OUTPUT):
        chunk = data[offset:offset + MAX_OUTPUT]
        block = bytearray([min(len(chunk), 15) << 4])
        if len(chunk) >= 15:
            extra = len(chunk) - 15
            while extra >= 255:
                block.append(255)
                extra -= 255
            block.append(extra)
        block.extend(chunk)
        result.extend(len(block).to_bytes(2, "little"))
        result.extend(block)
    return bytes(result)


def _decode_block(block: bytes, history: bytes) -> bytes:
    position = 0
    output = bytearray()

    def length(base):
        nonlocal position
        if base == 15:
            while True:
                if position >= len(block):
                    raise DecodeError("truncated LZ4 length")
                extension = block[position]
                position += 1
                base += extension
                if base > MAX_OUTPUT:
                    raise DecodeError("LZ4 output exceeds block limit")
                if extension != 255:
                    break
        return base

    while position < len(block):
        token = block[position]
        position += 1
        literals = length(token >> 4)
        if position + literals > len(block) or len(output) + literals > MAX_OUTPUT:
            raise DecodeError("invalid LZ4 literal length")
        output.extend(block[position:position + literals])
        position += literals
        if position == len(block):
            if not output:
                raise DecodeError("empty LZ4 output")
            return bytes(output)
        if position + 2 > len(block):
            raise DecodeError("truncated LZ4 match offset")
        distance = int.from_bytes(block[position:position + 2], "little")
        position += 2
        count = length(token & 15) + 4
        if not distance or distance > len(history) + len(output):
            raise DecodeError("invalid LZ4 match offset")
        if len(output) + count > MAX_OUTPUT:
            raise DecodeError("LZ4 output exceeds block limit")
        for _ in range(count):
            source = len(output) - distance
            output.append(output[source] if source >= 0 else history[source])
    raise DecodeError("missing LZ4 final literal sequence")


class CompressedStreamDecoder:
    """Block-bounded decoder; optional session budget, per-connection history."""

    def __init__(self, maximum_decoded_bytes=262144):
        if (maximum_decoded_bytes is not None
                and not 1 <= maximum_decoded_bytes <= 16 * 1024 * 1024):
            raise ValueError("invalid decompression budget")
        self.maximum_decoded_bytes = maximum_decoded_bytes
        self.decoded_bytes = 0
        self.blocks = 0
        self.buffer = bytearray()
        self.history = b""
        self.failed = False

    @property
    def pending_bytes(self):
        return len(self.buffer)

    def feed(self, data: bytes) -> list[bytes]:
        if self.failed:
            raise DecodeError("compression decoder already failed")
        try:
            if len(data) > 4096:
                raise DecodeError("compressed input chunk exceeds limit")
            self.buffer.extend(data)
            result = []
            offset = 0
            while len(self.buffer) - offset >= 2:
                size = int.from_bytes(self.buffer[offset:offset + 2], "little")
                if not 1 <= size <= MAX_BLOCK:
                    raise DecodeError("invalid compressed block size")
                end = offset + 2 + size
                if end > len(self.buffer):
                    break
                decoded = _decode_block(bytes(self.buffer[offset + 2:end]), self.history)
                if (self.maximum_decoded_bytes is not None
                        and self.decoded_bytes + len(decoded) > self.maximum_decoded_bytes):
                    raise DecodeError("decompressed session limit exceeded")
                self.decoded_bytes += len(decoded)
                self.blocks += 1
                self.history = (self.history + decoded)[-65536:]
                result.append(decoded)
                offset = end
            del self.buffer[:offset]
            return result
        except DecodeError:
            self.failed = True
            self.buffer.clear()
            self.history = b""
            raise

    def finish(self):
        if self.failed or self.buffer:
            raise DecodeError("failed or truncated compressed stream")
