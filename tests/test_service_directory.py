import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_protocol.service_directory import (
    DirectoryEntry, ServiceDirectory, decode_directory_body,
    encode_directory_body, encode_directory_response, local_directory,
)
from isac_protocol.codec import DecodeError


class ServiceDirectoryTests(unittest.TestCase):
    def test_code_derived_layout(self):
        directory = local_directory(b"x" * 32)
        expected = b"x" * 32 + b"\x01\x09127.0.0.1\x02" + bytes.fromhex("00 d9 ad 03 00 00 00 d9 ad 03 00 01")
        self.assertEqual(encode_directory_body(directory), expected)
        self.assertEqual(decode_directory_body(expected), directory)
        self.assertEqual(encode_directory_response(directory), bytes.fromhex("07 03 a4 0c 72 00") + expected)

    def test_truncation_rejected(self):
        body = encode_directory_body(local_directory(bytes(32)))
        for offset in range(len(body)):
            with self.subTest(offset=offset), self.assertRaises(DecodeError):
                decode_directory_body(body[:offset])

    def test_reject_bad_indices_port_kind_identifier_hosts(self):
        for entry in (DirectoryEntry(1, 55001, 0, 0), DirectoryEntry(0, 0, 0, 0),
                      DirectoryEntry(0, 65536, 0, 0), DirectoryEntry(0, 55001, 0, 2),
                      DirectoryEntry(0, 55001, -1, 0)):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                encode_directory_body(ServiceDirectory(bytes(32), ("localhost",), (entry,)))
        for host in ("", "x" * 64, "local\0host", "é"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                encode_directory_body(ServiceDirectory(bytes(32), (host,), ()))
        with self.assertRaises(ValueError):
            encode_directory_body(local_directory(bytes(31)))
        with self.assertRaises(DecodeError):
            decode_directory_body(encode_directory_body(local_directory(bytes(32))) + b"\0")

    def test_decode_bounds(self):
        for body in (bytes(32) + b"\x41", bytes(32) + b"\x01\x40",
                     bytes(32) + b"\x00\x81\x02", bytes(32) + b"\x01\x01\xff\x00",
                     bytes(32) + b"\x01\x01x\x01\x01\x01\x00\x00"):
            with self.subTest(body=body), self.assertRaises(DecodeError):
                decode_directory_body(body)

    def test_only_loopback_and_not_plaintext_bridge_advertised(self):
        directory = local_directory(bytes(32))
        self.assertEqual(directory.hosts, ("127.0.0.1",))
        self.assertEqual({entry.port for entry in directory.entries}, {55001})

    def test_split_services_preserves_encoding_and_separates_roles(self):
        directory = local_directory(bytes(32), split_services=True)
        self.assertEqual([(entry.kind, entry.port) for entry in directory.entries], [(0, 55001), (1, 55002)])
        self.assertEqual(decode_directory_body(encode_directory_body(directory)), directory)


if __name__ == "__main__":
    unittest.main()
