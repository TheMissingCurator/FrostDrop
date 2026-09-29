#!/usr/bin/env python3
"""Silent loopback listener for the Division's initial tctd-pc service."""

from __future__ import annotations

import argparse
import hashlib
import os
import selectors
import signal
import socket
from dataclasses import dataclass
from pathlib import Path


TLS_CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17, 0x18}
HTTP_PREFIXES = (
    b"CONNECT ",
    b"DELETE ",
    b"GET ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"POST ",
    b"PUT ",
    b"HTTP/",
)


def classify_protocol(data: bytes) -> str:
    if len(data) >= 3 and data[0] in TLS_CONTENT_TYPES and data[1] == 0x03:
        return "tls-record"
    if any(data.startswith(prefix) for prefix in HTTP_PREFIXES):
        return "http"
    if data and all(byte in b"\t\r\n" or 0x20 <= byte <= 0x7E for byte in data[:32]):
        return "printable-text"
    return "custom-binary"


@dataclass
class Connection:
    identifier: int
    sock: socket.socket
    path: Path
    output: object | None = None
    received: int = 0
    captured: int = 0
    digest: object | None = None
    protocol: str = "none"
    receive_events: int = 0

    def record(self, data: bytes, limit: int) -> None:
        self.received += len(data)
        self.receive_events += 1
        if self.protocol == "none":
            self.protocol = classify_protocol(data)
            print(
                "TCTD_PC_CLIENT_FIRST "
                f"connection={self.identifier} protocol={self.protocol} "
                f"first_chunk={len(data)} prefix8={data[:8].hex()}",
                flush=True,
            )
        remaining = max(0, limit - self.captured)
        chunk = data[:remaining]
        if not chunk:
            return
        if self.output is None:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            self.output = os.fdopen(descriptor, "wb")
            self.digest = hashlib.sha256()
        self.output.write(chunk)
        self.output.flush()
        self.digest.update(chunk)
        self.captured += len(chunk)

    def close(self, reason: str) -> None:
        if self.output is not None:
            self.output.close()
        try:
            self.sock.close()
        except OSError:
            pass
        digest = self.digest.hexdigest() if self.digest is not None else "none"
        inference = "client-first" if self.received else "server-first-or-client-idle"
        print(
            "TCTD_PC_CONNECTION_SUMMARY "
            f"connection={self.identifier} reason={reason} "
            f"client_bytes={self.received} captured_bytes={self.captured} "
            f"receive_events={self.receive_events} protocol={self.protocol} "
            f"sha256={digest} inference={inference}",
            flush=True,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=27015)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--max-capture-bytes", type=int, default=65536)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    if args.max_capture_bytes < 0:
        raise SystemExit("max-capture-bytes must not be negative")

    args.capture_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.capture_dir, 0o700)
    stop = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    selector = selectors.DefaultSelector()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.address, args.port))
    listener.listen(16)
    listener.setblocking(False)
    selector.register(listener, selectors.EVENT_READ, None)
    connections: dict[socket.socket, Connection] = {}
    next_identifier = 1
    print(
        "TCTD_PC_LISTENER_READY "
        f"address={args.address} port={args.port} "
        f"capture_limit={args.max_capture_bytes} response_mode=silent",
        flush=True,
    )

    try:
        while not stop:
            for key, _mask in selector.select(timeout=0.5):
                if key.data is None:
                    client, _peer = listener.accept()
                    client.setblocking(False)
                    identifier = next_identifier
                    next_identifier += 1
                    connection = Connection(
                        identifier,
                        client,
                        args.capture_dir / f"connection-{identifier:04d}-client.bin",
                    )
                    connections[client] = connection
                    selector.register(client, selectors.EVENT_READ, connection)
                    print(
                        f"TCTD_PC_CLIENT_CONNECTED connection={identifier}",
                        flush=True,
                    )
                    continue

                connection = key.data
                try:
                    data = connection.sock.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError as error:
                    selector.unregister(connection.sock)
                    connections.pop(connection.sock, None)
                    connection.close(f"socket-error-{error.errno}")
                    continue
                if data:
                    connection.record(data, args.max_capture_bytes)
                else:
                    selector.unregister(connection.sock)
                    connections.pop(connection.sock, None)
                    connection.close("peer-closed")
    finally:
        for connection in list(connections.values()):
            try:
                selector.unregister(connection.sock)
            except Exception:
                pass
            connection.close("listener-stopped")
        selector.unregister(listener)
        listener.close()
        selector.close()
        print(
            f"TCTD_PC_LISTENER_STOPPED accepted={next_identifier - 1}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
