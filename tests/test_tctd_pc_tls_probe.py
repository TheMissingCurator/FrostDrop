#!/usr/bin/env python3
"""Tests for the local port-27015 preface and TLS probe."""

from __future__ import annotations

import runpy
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
PROBE = runpy.run_path(str(PROJECT / "tools/run-tctd-pc-tls-probe.py"))


class TctdPcTlsProbeTests(unittest.TestCase):
    def test_bootstrap_wrapper_clears_stale_capture_flags(self) -> None:
        environment = dict(os.environ, ISAC_TCTD_ALLOCATION_CAPTURE="1", ISAC_WORLD_BOOTSTRAP_REPLAY="1")
        result = subprocess.run(
            [str(PROJECT / "tools/steam-tctd-bootstrap-wrapper.sh"), "env"],
            env=environment, text=True, capture_output=True, check=True,
        )
        flags = {line for line in result.stdout.splitlines() if line.startswith("ISAC_")}
        self.assertEqual(flags, {
            "ISAC_STACK_PROBE=1", "ISAC_LOCAL_BACKEND_BRIDGE=1",
            "ISAC_TRANSPORT_STARTUP_PROBE=1", "ISAC_TCTD_PC_LOOPBACK=1",
            "ISAC_TCTD_LOCAL_ACCEPT=1",
        })

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
    def test_bootstrap_identity_is_persistent_and_rejects_partial_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity = Path(temporary) / "identity"
            command = [str(PROJECT / "tools/generate-tctd-bootstrap-identity.sh"), str(identity)]
            subprocess.run(command, check=True, capture_output=True)
            cert = (identity / "server-cert.pem").read_bytes()
            key = (identity / "server-key.pem").read_bytes()
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual((identity / "server-cert.pem").read_bytes(), cert)
            self.assertEqual((identity / "server-key.pem").read_bytes(), key)
            self.assertEqual(identity.stat().st_mode & 0o777, 0o700)
            partial = Path(temporary) / "partial"
            partial.mkdir()
            (partial / "server-cert.pem").write_bytes(cert)
            failed = subprocess.run([command[0], str(partial)], capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual((partial / "server-cert.pem").read_bytes(), cert)
            self.assertFalse((partial / "server-key.pem").exists())

    def test_receive_exact_stops_at_requested_boundary(self) -> None:
        left, right = socket.socketpair()
        try:
            right.sendall(b"12345678trailing")
            self.assertEqual(PROBE["receive_exact"](left, 8), b"12345678")
            self.assertEqual(left.recv(8), b"trailing")
        finally:
            left.close()
            right.close()

    def test_read_exact_file_rejects_wrong_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "short.bin"
            path.write_bytes(b"short")
            with self.assertRaisesRegex(ValueError, "exactly 8 bytes"):
                PROBE["read_exact_file"](path, 8, "test preface")

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
    def test_preface_and_tls_handshake_accept_empty_client_certificate(self) -> None:
        self.run_tls_exchange(serve_certificate=False)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
    def test_local_certificate_service_over_real_tls(self) -> None:
        self.run_tls_exchange(serve_certificate=True)

    def run_tls_exchange(self, *, serve_certificate: bool) -> None:
        with tempfile.TemporaryDirectory() as directory_string:
            directory = Path(directory_string)
            identity = directory / "identity"
            subprocess.run(
                [
                    str(PROJECT / "tools" / (
                        "generate-tctd-bootstrap-identity.sh" if serve_certificate
                        else "generate-tctd-pc-probe-cert.sh"
                    )),
                    str(identity),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            capture = directory / "capture"
            capture.mkdir()
            server_context = PROBE["create_tls_context"](
                identity / "server-cert.pem",
                identity / "server-key.pem",
                capture / "keylog.txt",
            )
            server_preface = bytes(range(36))
            client_preface = b"12345678"
            certificate_der = ssl.PEM_cert_to_DER_cert(
                (identity / "server-cert.pem").read_text()
            ) if serve_certificate else None
            config = PROBE["ProbeConfig"](
                server_preface=server_preface,
                expected_client_preface=client_preface,
                capture_dir=capture,
                io_timeout=2.0,
                post_handshake_timeout=0.5,
                max_capture_bytes=1024,
                bootstrap_certificate_der=certificate_der,
            )
            server_socket, client_socket = socket.socketpair()
            thread = threading.Thread(
                target=PROBE["handle_connection"],
                args=(1, server_socket, server_context, config),
            )
            thread.start()
            try:
                self.assertEqual(PROBE["receive_exact"](client_socket, 36), server_preface)
                client_socket.sendall(client_preface)
                self.assertEqual(
                    PROBE["receive_exact"](client_socket, 3),
                    PROBE["SERVER_TRANSITION"],
                )
                client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_context.minimum_version = ssl.TLSVersion.TLSv1_2
                client_context.maximum_version = ssl.TLSVersion.TLSv1_2
                if serve_certificate:
                    client_context.load_verify_locations(identity / "server-cert.pem")
                else:
                    client_context.check_hostname = False
                    client_context.verify_mode = ssl.CERT_NONE
                client_context.set_ciphers(PROBE["TLS_CIPHER"])
                tls_client = client_context.wrap_socket(
                    client_socket,
                    server_hostname="localhost" if serve_certificate else None,
                )
                if serve_certificate:
                    response = PROBE["encode_certificate_bootstrap"](certificate_der)
                    received = PROBE["receive_exact"](tls_client, len(response))
                    self.assertEqual(received, response)
                    # Test the decoder independently of the response encoder.
                    from isac_protocol.certificate_bootstrap import decode_certificate_bootstrap
                    self.assertEqual(decode_certificate_bootstrap(received), certificate_der)
                    self.assertEqual(tls_client.getpeercert(binary_form=True), certificate_der)
                    self.assertEqual((identity / "server-key.pem").stat().st_mode & 0o777, 0o600)
                tls_client.sendall(b"decrypted-test-payload")
                tls_client.close()
            finally:
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(
                (capture / "connection-0001-client-preface.bin").read_bytes(),
                client_preface,
            )
            self.assertEqual(
                (capture / "connection-0001-client-plaintext.bin").read_bytes(),
                b"decrypted-test-payload",
            )


if __name__ == "__main__":
    unittest.main()
