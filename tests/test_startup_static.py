from pathlib import Path
import runpy
import struct
import tempfile
import unittest

ANALYZER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/analyze-startup-static.py"))


class StartupStaticTests(unittest.TestCase):
    def test_ascii_and_wide_strings_with_rvas(self):
        data = b"static2.example\0\xff" + "public-example".encode("utf-16le") + b"\0\0"
        found = list(ANALYZER["strings"](data, 0x1000))
        self.assertIn((0x1000, "ascii", "static2.example"), found)
        self.assertIn((0x1011, "utf16le", "public-example"), found)

    def test_exact_string_lookup(self):
        self.assertEqual(ANALYZER["string_at"](b"HTTP\0", 10, 10), ("ascii", "HTTP"))
        self.assertEqual(ANALYZER["string_at"]("hello\0".encode("utf-16le"), 10, 10),
                         ("utf16le", "hello"))

    def test_lookup_rejects_outside_and_unterminated(self):
        for rva in (9, 20):
            with self.assertRaises(ValueError):
                ANALYZER["string_at"](b"abc\0", rva, 10)
        with self.assertRaises(ValueError):
            ANALYZER["string_at"](b"abcd", 10, 10)

    def test_lea_candidates_and_truncated_instruction(self):
        data = b"\x48\x8d\x15" + struct.pack("<i", 0x2000 - 0x1007) + b"\x4c\x8d\x05"
        self.assertEqual(ANALYZER["lea_references"](data, [0x2000, 0x3000]),
                         {0x2000: [0x1000], 0x3000: []})

    def test_partial_capture_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.bin"
            path.write_bytes(b"ISACRD01")
            with self.assertRaises(ValueError):
                ANALYZER["load_section"](path)

    def test_full_size_wrong_header_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.bin"
            with path.open("wb") as stream:
                stream.write(b"WRONGHDR" + bytes(8))
                stream.truncate(ANALYZER["RDATA_SIZE"] + 16)
            with self.assertRaises(ValueError):
                ANALYZER["load_section"](path)


if __name__ == "__main__":
    unittest.main()
