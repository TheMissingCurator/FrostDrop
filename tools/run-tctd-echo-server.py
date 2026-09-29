#!/usr/bin/env python3
"""Loopback-only direct-TLS echo/service-directory candidate endpoint."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import runpy
import signal
import socket
import ssl
import sys
import threading

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from isac_protocol.service_directory import encode_directory_response, local_directory

TLS = runpy.run_path(str(PROJECT / "tools/run-tctd-pc-tls-probe.py"))


def handle_connection(identifier, client, context, capture_dir, response, timeout=5.0):
    tls = None
    plaintext = bytearray()
    stage = "tls-handshake"
    outcome = "unknown"
    try:
        client.settimeout(timeout)
        tls = context.wrap_socket(client, server_side=True)
        stage = "tls-established"
        print(f"TCTD_ECHO_TLS_ESTABLISHED connection={identifier} "
              f"client_certificate={'yes' if tls.getpeercert(binary_form=True) else 'no'}", flush=True)
        tls.sendall(response)
        stage = "candidate-sent"
        print(f"TCTD_ECHO_CANDIDATE_SENT connection={identifier} bytes={len(response)} "
              "version=1572 hosts=1 entries=2 endpoints=loopback-only schema=unconfirmed", flush=True)
        while len(plaintext) < 65536:
            data = tls.recv(min(4096, 65536 - len(plaintext)))
            if not data:
                outcome = "peer-closed"
                break
            plaintext.extend(data)
        else:
            outcome = "capture-limit"
    except socket.timeout:
        outcome = "timeout"
    except ssl.SSLError as error:
        outcome = "tls-error"
        print(f"TCTD_ECHO_TLS_ERROR connection={identifier} stage={stage} "
              f"{TLS['describe_ssl_error'](error)}", flush=True)
    except OSError as error:
        outcome = f"socket-error-{error.errno}"
    finally:
        if plaintext:
            TLS["private_write"](capture_dir / f"echo-{identifier:04d}-plaintext.bin", bytes(plaintext))
        print(f"TCTD_ECHO_SUMMARY connection={identifier} stage={stage} "
              f"outcome={outcome} client_bytes={len(plaintext)}", flush=True)
        (tls if tls is not None else client).close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=51000)
    parser.add_argument("--split-services", action="store_true",
                        help="candidate kind-0 backend on 55001, kind-1 latency on 55002")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("invalid port")
    os.umask(0o077)
    args.capture_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(args.capture_dir, 0o700)
    context = TLS["create_tls_context"](args.cert, args.key, args.capture_dir / "echo-tls-keylog.txt")
    # Stable local revision identifier, not an account token or captured secret.
    identifier = hashlib.sha256(b"Project ISAC local directory candidate "
                                + (b"split-v2" if args.split_services else b"v1")).digest()
    response = encode_directory_response(local_directory(identifier, split_services=args.split_services))
    if args.split_services:
        print("TCTD_ECHO_ROUTES kind_0=127.0.0.1:55001 kind_1=127.0.0.1:55002 mapping=static-candidate", flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    workers = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.port))
        listener.listen(8)
        listener.settimeout(0.5)
        print(f"TCTD_ECHO_READY address=127.0.0.1 port={args.port} "
              "transport=direct-tls schema=static-candidate trust=bootstrap-ca", flush=True)
        sequence = 0
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            workers = [worker for worker in workers if worker.is_alive()]
            if len(workers) >= 8:
                client.close()
                continue
            sequence += 1
            worker = threading.Thread(target=handle_connection,
                args=(sequence, client, context, args.capture_dir, response))
            worker.start()
            workers.append(worker)
    for worker in workers:
        worker.join(timeout=6)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
