#!/usr/bin/env python3

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def tcp_packet(
    source_ip: bytes,
    source_port: int,
    destination_ip: bytes,
    destination_port: int,
    sequence: int,
    payload: bytes,
) -> bytes:
    total_length = 20 + 20 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        0x50,
        0x18,
        65535,
        0,
        0,
    )
    return ip_header + tcp_header + payload


class ExtractFlightsTest(unittest.TestCase):
    def test_extracts_server_then_client_flights(self) -> None:
        server_a = b"\x01server-"
        server_b = b"hello"
        client = b"\x02client-response"
        local_ip = bytes([10, 0, 0, 2])
        remote_ip = bytes([34, 78, 177, 43])
        packets = [
            tcp_packet(remote_ip, 27015, local_ip, 50000, 1000, server_a),
            tcp_packet(remote_ip, 27015, local_ip, 50000, 1000 + len(server_a), server_b),
            tcp_packet(local_ip, 50000, remote_ip, 27015, 2000, client),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            pcap = temporary_path / "input.pcap"
            with pcap.open("wb") as output:
                output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
                for index, packet in enumerate(packets):
                    output.write(struct.pack("<IIII", 1, index, len(packet), len(packet)))
                    output.write(packet)
            private = temporary_path / "private"
            summary = temporary_path / "summary.txt"
            subprocess.run(
                [
                    str(PROJECT / "tools/extract-tctd-pc-flights.py"),
                    str(pcap),
                    str(private),
                    "--summary",
                    str(summary),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual((private / "server-first.bin").read_bytes(), server_a + server_b)
            self.assertEqual((private / "client-first.bin").read_bytes(), client)
            self.assertIn("First payload direction: server", summary.read_text())
            self.assertEqual(os.stat(private / "server-first.bin").st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
