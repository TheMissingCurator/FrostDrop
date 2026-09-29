import contextlib
import io
from pathlib import Path
import runpy
import tempfile
import unittest

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/analyze-tctd-allocation.py"))


def event(kind=1, seq=1, payload=b"secret-endpoint", size=None):
    return MODULE["HEADER"].pack(kind, seq, 10, len(payload) if size is None else size,
                                 100, 0xDEADBEEF, MODULE["SITES"][kind], 1, 0) + payload


class AllocationTests(unittest.TestCase):
    def test_roundtrip_and_summary_does_not_expose_payload_or_pointer(self):
        data = MODULE["MAGIC"] + event() + event(3, 2) + event(4, 3)
        self.assertEqual(len(MODULE["parse_capture"](data)), 3)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.bin"
            path.write_bytes(data)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                MODULE["summarize"](path)
        text = output.getvalue()
        self.assertIn("Parsed response matches handoff: True", text)
        self.assertNotIn("secret-endpoint", text)
        self.assertNotIn(str(0xDEADBEEF), text)

    def test_truncations_rejected(self):
        data = MODULE["MAGIC"] + event()
        for length in (0, 7, 9, 30, len(data) - 1):
            with self.subTest(length=length), self.assertRaises(ValueError):
                MODULE["parse_capture"](data[:length])

    def test_invalid_length_and_sequence_rejected(self):
        for record in (event(size=65537), event(seq=2)):
            with self.assertRaises(ValueError):
                MODULE["parse_capture"](MODULE["MAGIC"] + record)

    def test_header_only_is_not_success(self):
        self.assertEqual(MODULE["parse_capture"](MODULE["MAGIC"]), [])


if __name__ == "__main__":
    unittest.main()
