#!/usr/bin/env python3
"""Replay the tctd-pc preface and terminate its observed TLS 1.2 session."""

from __future__ import annotations

import argparse
import hashlib
import os
import signal
import socket
import ssl
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_protocol.certificate_bootstrap import encode_certificate_bootstrap


TLS_CIPHER = "ECDHE-ECDSA-AES256-GCM-SHA384"
TLS_CURVE = "prime256v1"
SERVER_TRANSITION = bytes.fromhex("040001")


def private_write(path: Path, data: bytes) -> str:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
    return hashlib.sha256(data).hexdigest()


def read_exact_file(path: Path, expected_size: int, label: str) -> bytes:
    data = path.read_bytes()
    if len(data) != expected_size:
        raise ValueError(
            f"{label} must contain exactly {expected_size} bytes, got {len(data)}"
        )
    return data


def receive_exact(sock: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        chunk = sock.recv(size - len(output))
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def create_tls_context(cert: Path, key: Path, keylog: Path | None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(TLS_CIPHER)
    context.set_ecdh_curve(TLS_CURVE)
    context.load_cert_chain(certfile=cert, keyfile=key)

    # The retail service requests a certificate, but the captured client sends
    # an empty Certificate message and the service accepts it. CERT_OPTIONAL
    # reproduces that server-side behavior without requiring client identity.
    context.verify_mode = ssl.CERT_OPTIONAL
    if keylog is not None:
        context.keylog_filename = str(keylog)
    return context


@dataclass(frozen=True)
class ProbeConfig:
    server_preface: bytes
    expected_client_preface: bytes
    capture_dir: Path
    io_timeout: float
    post_handshake_timeout: float
    max_capture_bytes: int
    bootstrap_certificate_der: bytes | None = None


def describe_ssl_error(error: ssl.SSLError) -> str:
    library = getattr(error, "library", None) or "unknown"
    reason = getattr(error, "reason", None) or "unknown"
    return f"library={library} reason={reason} errno={error.errno}"


def handle_connection(
    identifier: int,
    client: socket.socket,
    context: ssl.SSLContext,
    config: ProbeConfig,
) -> None:
    tls_socket: ssl.SSLSocket | None = None
    client_preface = b""
    plaintext = bytearray()
    stage = "accepted"
    outcome = "unknown"
    try:
        client.settimeout(config.io_timeout)
        client.sendall(config.server_preface)
        stage = "server-preface-sent"
        print(
            "TCTD_PC_SERVER_PREFACE_SENT "
            f"connection={identifier} bytes={len(config.server_preface)}",
            flush=True,
        )

        client_preface = receive_exact(client, len(config.expected_client_preface))
        digest = private_write(
            config.capture_dir / f"connection-{identifier:04d}-client-preface.bin",
            client_preface,
        )
        preface_matches = client_preface == config.expected_client_preface
        print(
            "TCTD_PC_CLIENT_PREFACE "
            f"connection={identifier} bytes={len(client_preface)} "
            f"expected_bytes={len(config.expected_client_preface)} "
            f"match={'yes' if preface_matches else 'no'} sha256={digest}",
            flush=True,
        )
        if len(client_preface) != len(config.expected_client_preface):
            outcome = "short-client-preface"
            return

        client.sendall(SERVER_TRANSITION)
        stage = "transition-sent"
        print(
            "TCTD_PC_TLS_TRANSITION_SENT "
            f"connection={identifier} bytes={len(SERVER_TRANSITION)}",
            flush=True,
        )

        tls_socket = context.wrap_socket(
            client,
            server_side=True,
            do_handshake_on_connect=False,
        )
        tls_socket.settimeout(config.io_timeout)
        tls_socket.do_handshake()
        stage = "tls-established"
        cipher = tls_socket.cipher()
        print(
            "TCTD_PC_TLS_ESTABLISHED "
            f"connection={identifier} version={tls_socket.version()} "
            f"cipher={cipher[0] if cipher else 'none'} "
            f"client_certificate={'yes' if tls_socket.getpeercert(binary_form=True) else 'no'}",
            flush=True,
        )

        tls_socket.settimeout(config.post_handshake_timeout)
        if config.bootstrap_certificate_der is not None:
            response = encode_certificate_bootstrap(config.bootstrap_certificate_der)
            tls_socket.sendall(response)
            stage = "certificate-response-sent"
            print(
                "TCTD_PC_CERTIFICATE_SENT "
                f"connection={identifier} protocol_version=303 "
                f"wire_bytes={len(response)} "
                f"certificate_bytes={len(config.bootstrap_certificate_der)} "
                f"certificate_sha256={hashlib.sha256(config.bootstrap_certificate_der).hexdigest()} "
                "client_acceptance=unconfirmed",
                flush=True,
            )
        while len(plaintext) < config.max_capture_bytes:
            try:
                chunk = tls_socket.recv(
                    min(65536, config.max_capture_bytes - len(plaintext))
                )
            except socket.timeout:
                outcome = "tls-idle-timeout"
                break
            if not chunk:
                outcome = "tls-peer-closed"
                break
            plaintext.extend(chunk)
        else:
            outcome = "plaintext-capture-limit"
    except socket.timeout:
        outcome = f"timeout-at-{stage}"
        print(
            f"TCTD_PC_TIMEOUT connection={identifier} stage={stage}",
            flush=True,
        )
    except ssl.SSLError as error:
        outcome = f"tls-error-at-{stage}"
        print(
            "TCTD_PC_TLS_ERROR "
            f"connection={identifier} stage={stage} {describe_ssl_error(error)}",
            flush=True,
        )
    except (ConnectionError, OSError) as error:
        outcome = f"socket-error-at-{stage}"
        print(
            "TCTD_PC_SOCKET_ERROR "
            f"connection={identifier} stage={stage} errno={error.errno}",
            flush=True,
        )
    finally:
        plaintext_digest = "none"
        if plaintext:
            plaintext_digest = private_write(
                config.capture_dir
                / f"connection-{identifier:04d}-client-plaintext.bin",
                bytes(plaintext),
            )
        print(
            "TCTD_PC_CONNECTION_SUMMARY "
            f"connection={identifier} stage={stage} outcome={outcome} "
            f"client_preface_bytes={len(client_preface)} "
            f"client_plaintext_bytes={len(plaintext)} "
            f"client_plaintext_sha256={plaintext_digest}",
            flush=True,
        )
        target = tls_socket if tls_socket is not None else client
        try:
            target.close()
        except OSError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=27015)
    parser.add_argument("--server-preface", type=Path, required=True)
    parser.add_argument("--expected-client-preface", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--io-timeout", type=float, default=10.0)
    parser.add_argument("--post-handshake-timeout", type=float, default=15.0)
    parser.add_argument("--max-capture-bytes", type=int, default=65536)
    parser.add_argument(
        "--serve-certificate", action="store_true",
        help="send version 303 and the local TLS certificate as application type 0",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    if args.io_timeout <= 0 or args.post_handshake_timeout <= 0:
        raise SystemExit("timeouts must be positive")
    if args.max_capture_bytes <= 0:
        raise SystemExit("max-capture-bytes must be positive")
    if args.serve_certificate and args.address != "127.0.0.1":
        raise SystemExit("certificate bootstrap service must bind to 127.0.0.1")
    try:
        server_preface = read_exact_file(args.server_preface, 36, "server preface")
        expected_client_preface = read_exact_file(
            args.expected_client_preface, 8, "expected client preface"
        )
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error

    os.umask(0o077)
    args.capture_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.capture_dir, 0o700)
    keylog = args.capture_dir / "tls-keylog.txt"
    try:
        context = create_tls_context(args.cert, args.key, keylog)
        certificate_der = None
        if args.serve_certificate:
            certificate_der = ssl.PEM_cert_to_DER_cert(args.cert.read_text(encoding="ascii"))
            encode_certificate_bootstrap(certificate_der)  # Validate before listening.
    except (OSError, ValueError, ssl.SSLError) as error:
        raise SystemExit(f"error: cannot configure TLS: {error}") from error

    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.address, args.port))
    listener.listen(16)
    listener.settimeout(0.5)
    threads: list[threading.Thread] = []
    config = ProbeConfig(
        server_preface=server_preface,
        expected_client_preface=expected_client_preface,
        capture_dir=args.capture_dir,
        io_timeout=args.io_timeout,
        post_handshake_timeout=args.post_handshake_timeout,
        max_capture_bytes=args.max_capture_bytes,
        bootstrap_certificate_der=certificate_der,
    )
    accepted = 0
    print(
        "TCTD_PC_TLS_PROBE_READY "
        f"address={args.address} port={args.port} "
        "preface_mode=captured-replay tls=TLSv1.2 "
        f"cipher={TLS_CIPHER} curve={TLS_CURVE} "
        f"server_application_mode={'local-certificate' if args.serve_certificate else 'silent'}",
        flush=True,
    )
    try:
        while not stop.is_set():
            try:
                client, _peer = listener.accept()
            except socket.timeout:
                continue
            accepted += 1
            print(f"TCTD_PC_CLIENT_CONNECTED connection={accepted}", flush=True)
            thread = threading.Thread(
                target=handle_connection,
                args=(accepted, client, context, config),
                name=f"tctd-pc-{accepted}",
            )
            thread.start()
            threads.append(thread)
    finally:
        listener.close()
        for thread in threads:
            thread.join(timeout=args.io_timeout + args.post_handshake_timeout + 1)
        if keylog.exists():
            os.chmod(keylog, 0o600)
        print(f"TCTD_PC_TLS_PROBE_STOPPED accepted={accepted}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
