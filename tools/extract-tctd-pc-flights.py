#!/usr/bin/env python3
"""Extract the first port-27015 server/client flights into a private directory."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Payload:
    direction: str
    sequence: int
    data: bytes


@dataclass
class Flow:
    local: str
    remote: str
    payloads: list[Payload] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--max-flight-bytes", type=int, default=262144)
    return parser.parse_args()


def pcap_layout(header: bytes) -> tuple[str, float, int]:
    layouts = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    if header[:4] not in layouts:
        raise ValueError("classic PCAP input is required")
    endian, scale = layouts[header[:4]]
    return endian, scale, struct.unpack_from(f"{endian}I", header, 20)[0]


def ipv4_offset(packet: bytes, link_type: int) -> int | None:
    if link_type == 276:
        return 20 if len(packet) >= 20 and packet[:2] == b"\x08\x00" else None
    if link_type == 113:
        return 16 if len(packet) >= 16 and packet[14:16] == b"\x08\x00" else None
    if link_type == 1:
        return 14 if len(packet) >= 14 and packet[12:14] == b"\x08\x00" else None
    if link_type == 101:
        return 0
    raise ValueError(f"unsupported PCAP link type: {link_type}")


def parse_tcp(packet: bytes, link_type: int):
    ip_offset = ipv4_offset(packet, link_type)
    if ip_offset is None or len(packet) < ip_offset + 40:
        return None
    version_ihl = packet[ip_offset]
    ip_length = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or ip_length < 20 or packet[ip_offset + 9] != 6:
        return None
    total_length = struct.unpack_from("!H", packet, ip_offset + 2)[0]
    tcp_offset = ip_offset + ip_length
    source_port, destination_port = struct.unpack_from("!HH", packet, tcp_offset)
    sequence = struct.unpack_from("!I", packet, tcp_offset + 4)[0]
    tcp_length = (packet[tcp_offset + 12] >> 4) * 4
    payload_offset = tcp_offset + tcp_length
    packet_end = min(len(packet), ip_offset + total_length)
    if tcp_length < 20 or payload_offset > packet_end:
        return None
    source_ip = str(ipaddress.ip_address(packet[ip_offset + 12 : ip_offset + 16]))
    destination_ip = str(ipaddress.ip_address(packet[ip_offset + 16 : ip_offset + 20]))
    return (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        sequence,
        packet[payload_offset:packet_end],
    )


def load_flows(path: Path) -> list[Flow]:
    flows: dict[tuple[str, int, str, int], Flow] = {}
    seen: set[tuple[tuple[str, int, str, int], str, int, bytes]] = set()
    with path.open("rb") as capture:
        header = capture.read(24)
        if len(header) != 24:
            raise ValueError("truncated PCAP header")
        endian, _scale, link_type = pcap_layout(header)
        while True:
            packet_header = capture.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("truncated packet header")
            _seconds, _fraction, captured_length, _wire_length = struct.unpack(
                f"{endian}IIII", packet_header
            )
            packet = capture.read(captured_length)
            if len(packet) != captured_length:
                raise ValueError("truncated packet")
            parsed = parse_tcp(packet, link_type)
            if parsed is None:
                continue
            source_ip, source_port, destination_ip, destination_port, sequence, data = parsed
            if not data:
                continue
            if destination_port == 27015:
                direction = "client"
                key = (source_ip, source_port, destination_ip, destination_port)
            elif source_port == 27015:
                direction = "server"
                key = (destination_ip, destination_port, source_ip, source_port)
            else:
                continue
            duplicate_key = (key, direction, sequence, data)
            if duplicate_key in seen:
                continue
            seen.add(duplicate_key)
            if key not in flows:
                flows[key] = Flow(
                    local=f"{key[0]}:{key[1]}",
                    remote=f"{key[2]}:{key[3]}",
                )
            flows[key].payloads.append(Payload(direction, sequence, data))
    return list(flows.values())


def reassemble(payloads: list[Payload], limit: int) -> bytes:
    if not payloads:
        return b""
    ordered = sorted(payloads, key=lambda item: item.sequence)
    first_sequence = ordered[0].sequence
    output = bytearray()
    for payload in ordered:
        offset = payload.sequence - first_sequence
        if offset > len(output):
            break
        overlap = len(output) - offset
        if overlap < len(payload.data):
            output.extend(payload.data[max(0, overlap) :])
        if len(output) >= limit:
            return bytes(output[:limit])
    return bytes(output)


def first_flights(flow: Flow, limit: int) -> tuple[bytes, bytes, str]:
    if not flow.payloads:
        return b"", b"", "none"
    first_direction = flow.payloads[0].direction
    first_group: list[Payload] = []
    second_group: list[Payload] = []
    changed = False
    for payload in flow.payloads:
        if payload.direction == first_direction and not changed:
            first_group.append(payload)
        elif payload.direction != first_direction:
            changed = True
            second_group.append(payload)
        elif changed:
            break
    first = reassemble(first_group, limit)
    second = reassemble(second_group, limit)
    if first_direction == "server":
        return first, second, first_direction
    return second, first, first_direction


def protocol_class(data: bytes) -> str:
    if len(data) >= 3 and data[0] in {0x14, 0x15, 0x16, 0x17, 0x18} and data[1] == 3:
        return "tls-record"
    if data.startswith((b"GET ", b"POST ", b"HTTP/", b"CONNECT ")):
        return "http"
    if data and all(byte in b"\t\r\n" or 0x20 <= byte <= 0x7E for byte in data[:32]):
        return "printable-text"
    return "custom-binary" if data else "none"


def private_write(path: Path, data: bytes) -> str:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    args = parse_args()
    if args.max_flight_bytes <= 0:
        raise SystemExit("max-flight-bytes must be positive")
    try:
        flows = [flow for flow in load_flows(args.pcap) if flow.payloads]
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
    if not flows:
        raise SystemExit("error: capture contains no TCP port-27015 payload")

    flow = flows[0]
    server, client, first_direction = first_flights(flow, args.max_flight_bytes)
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(args.output_dir, 0o700)
    private_lines = [
        f"flow={flow.local}->{flow.remote}",
        f"first_payload_direction={first_direction}",
    ]
    if server:
        digest = private_write(args.output_dir / "server-first.bin", server)
        private_lines.append(f"server-first.bin bytes={len(server)} sha256={digest}")
    if client:
        digest = private_write(args.output_dir / "client-first.bin", client)
        private_lines.append(f"client-first.bin bytes={len(client)} sha256={digest}")
    private_write(
        args.output_dir / "manifest.txt",
        ("\n".join(private_lines) + "\n").encode("ascii"),
    )

    summary_lines = [
        f"Flow: {flow.local} -> {flow.remote}",
        f"First payload direction: {first_direction}",
        f"Server first flight: {len(server)} bytes ({protocol_class(server)})",
        f"Client first flight: {len(client)} bytes ({protocol_class(client)})",
        f"Private extraction: {args.output_dir}",
    ]
    summary = "\n".join(summary_lines) + "\n"
    if args.summary is not None:
        args.summary.write_text(summary, encoding="utf-8")
    print(summary, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
