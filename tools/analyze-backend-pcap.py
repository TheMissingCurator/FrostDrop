#!/usr/bin/env python3
"""Summarize Project ISAC backend captures without printing payload bytes."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


TARGET_PORTS = {27015, 51000, 55000, 55001, 55002}
TLS_TYPES = {
    20: "change-cipher-spec",
    21: "alert",
    22: "handshake",
    23: "application-data",
}
TLS_HANDSHAKES = {
    1: "client-hello",
    2: "server-hello",
    4: "new-session-ticket",
    11: "certificate",
    12: "server-key-exchange",
    13: "certificate-request",
    14: "server-hello-done",
    15: "certificate-verify",
    16: "client-key-exchange",
    20: "finished",
}
TLS_CIPHERS = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
}


@dataclass
class PayloadEvent:
    timestamp: float
    direction: str
    length: int
    payload_class: str
    protocol_hint: str


@dataclass
class Flow:
    local: str
    remote: str
    first: float
    last: float
    packet_count: int = 0
    payload_packets: dict[str, int] = field(
        default_factory=lambda: {"out": 0, "in": 0}
    )
    payload_bytes: dict[str, int] = field(
        default_factory=lambda: {"out": 0, "in": 0}
    )
    events: list[PayloadEvent] = field(default_factory=list)
    segments: dict[str, list[tuple[int, bytes]]] = field(
        default_factory=lambda: {"out": [], "in": []}
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Report flow metadata and payload equality classes without "
            "displaying captured bytes or cryptographic hashes."
        )
    )
    parser.add_argument("pcap", type=Path)
    parser.add_argument(
        "--events-per-flow",
        type=int,
        default=10,
        help="number of initial payload events to display per flow (default: 10)",
    )
    return parser.parse_args()


def pcap_layout(header: bytes) -> tuple[str, float, int]:
    magic = header[:4]
    layouts = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    if magic not in layouts:
        raise ValueError("unsupported capture format (classic PCAP required)")
    endian, timestamp_scale = layouts[magic]
    link_type = struct.unpack_from(f"{endian}I", header, 20)[0]
    return endian, timestamp_scale, link_type


def ipv4_offset(packet: bytes, link_type: int) -> int | None:
    if link_type == 276:  # Linux cooked capture v2
        if len(packet) < 20 or struct.unpack_from("!H", packet, 0)[0] != 0x0800:
            return None
        return 20
    if link_type == 113:  # Linux cooked capture v1
        if len(packet) < 16 or struct.unpack_from("!H", packet, 14)[0] != 0x0800:
            return None
        return 16
    if link_type == 1:  # Ethernet
        if len(packet) < 14 or struct.unpack_from("!H", packet, 12)[0] != 0x0800:
            return None
        return 14
    if link_type == 101:  # Raw IP
        return 0
    raise ValueError(f"unsupported PCAP link type: {link_type}")


def parse_tcp(packet: bytes, link_type: int):
    ip_offset = ipv4_offset(packet, link_type)
    if ip_offset is None or len(packet) < ip_offset + 20:
        return None
    version_ihl = packet[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or packet[ip_offset + 9] != 6:
        return None
    total_length = struct.unpack_from("!H", packet, ip_offset + 2)[0]
    tcp_offset = ip_offset + ip_header_length
    if len(packet) < tcp_offset + 20:
        return None
    source_port, destination_port = struct.unpack_from("!HH", packet, tcp_offset)
    sequence = struct.unpack_from("!I", packet, tcp_offset + 4)[0]
    tcp_header_length = (packet[tcp_offset + 12] >> 4) * 4
    payload_offset = tcp_offset + tcp_header_length
    ip_end = min(len(packet), ip_offset + total_length)
    if payload_offset > ip_end:
        return None
    source_ip = str(ipaddress.ip_address(packet[ip_offset + 12 : ip_offset + 16]))
    destination_ip = str(
        ipaddress.ip_address(packet[ip_offset + 16 : ip_offset + 20])
    )
    return (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        sequence,
        packet[payload_offset:ip_end],
    )


def protocol_hint(payload: bytes) -> str:
    if (
        len(payload) >= 5
        and payload[0] in TLS_TYPES
        and payload[1] == 3
        and 0 <= payload[2] <= 4
    ):
        record_length = struct.unpack_from("!H", payload, 3)[0]
        return (
            f"TLS-{TLS_TYPES[payload[0]]} "
            f"record-v3.{payload[2]} declared={record_length}"
        )
    return "custom/unknown"


def class_name(index: int) -> str:
    return f"P{index:03d}"


def reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    if not segments:
        return b""
    ordered = sorted(segments, key=lambda item: item[0])
    start = ordered[0][0]
    stream = bytearray()
    for sequence, payload in ordered:
        relative = sequence - start
        if relative < 0:
            continue
        if relative > len(stream):
            break
        overlap = len(stream) - relative
        if overlap < len(payload):
            stream.extend(payload[max(overlap, 0) :])
    return bytes(stream)


def find_tls_offset(stream: bytes) -> int | None:
    for offset in range(min(len(stream), 64)):
        if (
            len(stream) - offset >= 5
            and stream[offset] == 22
            and stream[offset + 1] == 3
            and 0 <= stream[offset + 2] <= 4
        ):
            record_length = struct.unpack_from("!H", stream, offset + 3)[0]
            if record_length <= 0x5000:
                return offset
    return None


def tls_records(stream: bytes, offset: int):
    records = []
    cursor = offset
    while cursor + 5 <= len(stream):
        content_type = stream[cursor]
        major = stream[cursor + 1]
        minor = stream[cursor + 2]
        length = struct.unpack_from("!H", stream, cursor + 3)[0]
        end = cursor + 5 + length
        if content_type not in TLS_TYPES or major != 3 or end > len(stream):
            break
        records.append((content_type, major, minor, stream[cursor + 5 : end]))
        cursor = end
    return records


def handshake_messages(records):
    plaintext = bytearray()
    for content_type, _, _, data in records:
        if content_type == 20:
            break
        if content_type == 22:
            plaintext.extend(data)
    messages = []
    cursor = 0
    while cursor + 4 <= len(plaintext):
        message_type = plaintext[cursor]
        length = int.from_bytes(plaintext[cursor + 1 : cursor + 4], "big")
        end = cursor + 4 + length
        if end > len(plaintext):
            break
        messages.append((message_type, bytes(plaintext[cursor + 4 : end])))
        cursor = end
    return messages


def parse_client_hello(body: bytes):
    if len(body) < 35:
        return None
    cursor = 34
    session_id_length = body[cursor]
    cursor += 1 + session_id_length
    if cursor + 2 > len(body):
        return None
    cipher_length = struct.unpack_from("!H", body, cursor)[0]
    cursor += 2
    if cursor + cipher_length > len(body) or cipher_length % 2 != 0:
        return None
    ciphers = [
        struct.unpack_from("!H", body, index)[0]
        for index in range(cursor, cursor + cipher_length, 2)
    ]
    cursor += cipher_length
    if cursor >= len(body):
        return {"ciphers": ciphers, "sni": None}
    compression_length = body[cursor]
    cursor += 1 + compression_length
    if cursor + 2 > len(body):
        return {"ciphers": ciphers, "sni": None}
    extensions_length = struct.unpack_from("!H", body, cursor)[0]
    cursor += 2
    extensions_end = min(len(body), cursor + extensions_length)
    sni = None
    while cursor + 4 <= extensions_end:
        extension_type, extension_length = struct.unpack_from("!HH", body, cursor)
        cursor += 4
        extension = body[cursor : cursor + extension_length]
        cursor += extension_length
        if extension_type == 0 and len(extension) >= 5:
            name_length = struct.unpack_from("!H", extension, 3)[0]
            name = extension[5 : 5 + name_length]
            try:
                sni = name.decode("ascii")
            except UnicodeDecodeError:
                sni = "<non-ASCII>"
    return {"ciphers": ciphers, "sni": sni}


def parse_server_hello(body: bytes):
    if len(body) < 38:
        return None
    cursor = 34
    session_id_length = body[cursor]
    cursor += 1 + session_id_length
    if cursor + 3 > len(body):
        return None
    return struct.unpack_from("!H", body, cursor)[0]


def tls_profile(flow: Flow):
    output = []
    for direction in ("out", "in"):
        stream = reassemble(flow.segments[direction])
        offset = find_tls_offset(stream)
        if offset is None:
            continue
        records = tls_records(stream, offset)
        messages = handshake_messages(records)
        names = [TLS_HANDSHAKES.get(kind, f"type-{kind}") for kind, _ in messages]
        output.append(
            f"{direction}: preface={offset}B records={len(records)} "
            f"handshakes={','.join(names) if names else 'encrypted/none'}"
        )
        for kind, body in messages:
            if kind == 1:
                hello = parse_client_hello(body)
                if hello is not None:
                    offered = ",".join(
                        f"0x{cipher:04x}:{TLS_CIPHERS.get(cipher, 'unknown')}"
                        for cipher in hello["ciphers"]
                    )
                    output.append(
                        f"{direction}: client-hello sni={hello['sni'] or '<none>'} "
                        f"offered-ciphers={offered}"
                    )
            elif kind == 2:
                cipher = parse_server_hello(body)
                if cipher is not None:
                    cipher_name = TLS_CIPHERS.get(cipher, "unknown")
                    output.append(
                        f"{direction}: selected-cipher=0x{cipher:04x} {cipher_name}"
                    )
    return output


def analyze(path: Path, events_per_flow: int) -> None:
    classes: dict[tuple[int, bytes], str] = {}
    flows: dict[tuple[str, int, str, int], Flow] = {}
    class_uses: dict[str, set[tuple[str, str, str]]] = defaultdict(set)

    with path.open("rb") as capture:
        global_header = capture.read(24)
        if len(global_header) != 24:
            raise ValueError("truncated PCAP global header")
        endian, timestamp_scale, link_type = pcap_layout(global_header)

        while True:
            packet_header = capture.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            seconds, fraction, captured_length, _ = struct.unpack(
                f"{endian}IIII", packet_header
            )
            packet = capture.read(captured_length)
            if len(packet) != captured_length:
                raise ValueError("truncated PCAP packet data")
            parsed = parse_tcp(packet, link_type)
            if parsed is None:
                continue
            (
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                sequence,
                payload,
            ) = parsed
            if destination_port in TARGET_PORTS:
                direction = "out"
                local_ip, local_port = source_ip, source_port
                remote_ip, remote_port = destination_ip, destination_port
            elif source_port in TARGET_PORTS:
                direction = "in"
                local_ip, local_port = destination_ip, destination_port
                remote_ip, remote_port = source_ip, source_port
            else:
                continue

            timestamp = seconds + fraction / timestamp_scale
            key = (local_ip, local_port, remote_ip, remote_port)
            if key not in flows:
                flows[key] = Flow(
                    local=f"{local_ip}:{local_port}",
                    remote=f"{remote_ip}:{remote_port}",
                    first=timestamp,
                    last=timestamp,
                )
            flow = flows[key]
            flow.last = timestamp
            flow.packet_count += 1
            if not payload:
                continue

            flow.segments[direction].append((sequence, payload))

            digest_key = (len(payload), hashlib.sha256(payload).digest())
            if digest_key not in classes:
                classes[digest_key] = class_name(len(classes) + 1)
            payload_class = classes[digest_key]
            flow.payload_packets[direction] += 1
            flow.payload_bytes[direction] += len(payload)
            flow.events.append(
                PayloadEvent(
                    timestamp=timestamp,
                    direction=direction,
                    length=len(payload),
                    payload_class=payload_class,
                    protocol_hint=protocol_hint(payload),
                )
            )
            class_uses[payload_class].add((flow.local, flow.remote, direction))

    print(f"Capture: {path}")
    print(f"Link type: {link_type}")
    print(f"Flows: {len(flows)}")
    print()

    for flow in sorted(flows.values(), key=lambda item: item.first):
        print(f"{flow.local} -> {flow.remote}")
        print(
            "  duration={:.3f}s packets={} payload="
            "out:{}B/{} in:{}B/{}".format(
                flow.last - flow.first,
                flow.packet_count,
                flow.payload_bytes["out"],
                flow.payload_packets["out"],
                flow.payload_bytes["in"],
                flow.payload_packets["in"],
            )
        )
        for event in flow.events[:events_per_flow]:
            print(
                "  +{:.3f}s {:>3} len={:<4} class={} {}".format(
                    event.timestamp - flow.first,
                    event.direction,
                    event.length,
                    event.payload_class,
                    event.protocol_hint,
                )
            )
        if len(flow.events) > events_per_flow:
            print(f"  ... {len(flow.events) - events_per_flow} payload events omitted")
        for profile_line in tls_profile(flow):
            print(f"  TLS {profile_line}")
        print()

    reused = [
        (payload_class, uses)
        for payload_class, uses in class_uses.items()
        if len(uses) > 1
    ]
    print("Payload classes reused across distinct TCP flows:")
    if not reused:
        print("  none")
    for payload_class, uses in sorted(reused):
        groups = ", ".join(
            f"{local}->{remote}/{direction}"
            for local, remote, direction in sorted(uses)
        )
        print(f"  {payload_class}: {groups}")


def main() -> int:
    args = parse_args()
    try:
        analyze(args.pcap, args.events_per_flow)
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
