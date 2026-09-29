from pathlib import Path
import ctypes
import ctypes.util
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_protocol.codec import DecodeError
from isac_protocol.compression import CompressedStreamDecoder, encode_compressed_stream
from isac_protocol.transport import TransportFrame, TransportStreamDecoder


class CompressionTests(unittest.TestCase):
    def test_independent_native_lz4_interoperability(self):
        library = ctypes.util.find_library("lz4")
        if not library:
            self.skipTest("optional native LZ4 test oracle unavailable")
        lib = ctypes.CDLL(library)
        ptr, integer = ctypes.c_void_p, ctypes.c_int
        lib.LZ4_createStream.restype = ptr
        lib.LZ4_createStream.argtypes = []
        lib.LZ4_freeStream.argtypes = [ptr]
        lib.LZ4_compress_fast_continue.argtypes = [ptr, ptr, ptr, integer, integer, integer]
        lib.LZ4_decompress_safe.argtypes = [ptr, ptr, integer, integer]
        rng = random.Random(96)
        chunks = [rng.randbytes(1000), b"abcde" * 200, b"Z" * 1000] * 30
        # Keep all source bytes alive at stable addresses for the streaming C API.
        source = ctypes.create_string_buffer(b"".join(chunks))
        compressed = ctypes.create_string_buffer(1019)
        native = lib.LZ4_createStream()
        self.assertTrue(native)
        try:
            decoder = CompressedStreamDecoder()
            position = 0
            for chunk in chunks:
                size = lib.LZ4_compress_fast_continue(native, ctypes.addressof(source) + position,
                                                     compressed, len(chunk), 1019, 1)
                self.assertGreater(size, 0)
                wire = size.to_bytes(2, "little") + compressed.raw[:size]
                self.assertEqual(decoder.feed(wire), [chunk])
                position += len(chunk)
            decoder.finish()
        finally:
            lib.LZ4_freeStream(native)
        output = ctypes.create_string_buffer(1000)
        for size in (1, 2, 14, 15, 269, 270, 999, 1000):
            chunk = rng.randbytes(size)
            block = encode_compressed_stream(chunk)[2:]
            actual = lib.LZ4_decompress_safe(block, output, len(block), 1000)
            self.assertEqual(actual, size)
            self.assertEqual(output.raw[:actual], chunk)

    def test_exact_game_heartbeat_not_control_zero(self):
        decoder = CompressedStreamDecoder()
        self.assertEqual(decoder.feed(bytes.fromhex("0300200209")), [b"\x02\x09"])
        decoder.finish()
        self.assertEqual(TransportStreamDecoder().feed(b"\x02\x09"), [TransportFrame(False, 9, b"")])
        self.assertEqual(encode_compressed_stream(b"\x02\x0a"), bytes.fromhex("030020020a"))
        self.assertEqual(encode_compressed_stream(bytes.fromhex("07038810040700")),
                         bytes.fromhex("08007007038810040700"))

    def test_literal_lengths_fragmentation_and_coalescing(self):
        for size in (0, 1, 14, 15, 269, 270, 999, 1000, 1001, 3000):
            data = bytes(i % 251 for i in range(size))
            wire = encode_compressed_stream(data)
            for step in (1, 2, 17, 4096):
                decoder = CompressedStreamDecoder()
                result = []
                for offset in range(0, len(wire), step):
                    result.extend(decoder.feed(wire[offset:offset + step]))
                decoder.finish()
                self.assertEqual(b"".join(result), data)

    def test_matches_overlap_and_cross_block_dictionary(self):
        # One literal A, overlapping 12-byte match, five final literals.
        first = bytes.fromhex("0a0018410100504243444546")
        decoder = CompressedStreamDecoder()
        self.assertEqual(decoder.feed(first), [b"A" * 13 + b"BCDEF"])
        # Match 8 bytes from previous block, then five final literals.
        second = bytes.fromhex("0900041200504748494a4b")
        self.assertEqual(decoder.feed(second), [b"A" * 8 + b"GHIJK"])
        decoder.finish()
        with self.assertRaises(DecodeError):
            CompressedStreamDecoder().feed(second)

    def test_history_bounded_and_session_budget(self):
        decoder = CompressedStreamDecoder(100000)
        for _ in range(70):
            decoder.feed(encode_compressed_stream(b"a" * 1000))
        self.assertEqual(len(decoder.history), 65536)
        self.assertEqual(decoder.decoded_bytes, 70000)
        decoder = CompressedStreamDecoder(3)
        decoder.feed(bytes.fromhex("0300200209"))
        with self.assertRaises(DecodeError):
            decoder.feed(bytes.fromhex("0300200209"))

    def test_live_session_has_no_cumulative_decode_cutoff(self):
        decoder = CompressedStreamDecoder(None)
        wire = encode_compressed_stream(b'a' * 1000)
        for _ in range(270):
            self.assertEqual(decoder.feed(wire), [b'a' * 1000])
        self.assertEqual(decoder.decoded_bytes, 270000)
        self.assertEqual(len(decoder.history), 65536)
        decoder.finish()

    def test_malformed_blocks_fail_terminally(self):
        for wire in (b"\0\0", b"\xfc\x03", b"\1\0\0", b"\1\0\xf0",
                     b"\2\0\x30x", b"\2\0\0\1", b"\3\0\0\0\0",
                     b"\3\0\0\1\0", b"\5\0\xf0\xff\xff\xff\xff",
                     b"x" * 4097):
            with self.subTest(wire=wire[:16]):
                decoder = CompressedStreamDecoder()
                with self.assertRaises(DecodeError):
                    decoder.feed(wire)
                self.assertEqual(decoder.pending_bytes, 0)
                self.assertEqual(decoder.history, b"")
                with self.assertRaises(DecodeError):
                    decoder.feed(b"")

    def test_truncated_prefix_or_block(self):
        for wire in (b"\3", b"\3\0", b"\3\0\x20\x02"):
            decoder = CompressedStreamDecoder()
            self.assertEqual(decoder.feed(wire), [])
            with self.assertRaises(DecodeError):
                decoder.finish()


if __name__ == "__main__":
    unittest.main()
