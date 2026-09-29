import contextlib
import io
import os
from pathlib import Path
import runpy
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SERVER = runpy.run_path(str(PROJECT / "tools/run-tctd-backend-server.py"))
from isac_protocol.transport import TransportFrame, encode_transport_frame
from isac_protocol.codec import DecodeError
from isac_protocol.compression import encode_compressed_stream
from isac_backend.services import local_service_advertisements
from isac_protocol.service_advertisement import encode_service_advertisement


class BackendServerTests(unittest.TestCase):
    def test_public_service_category_never_prints_arbitrary_registration_name(self):
        from isac_backend.channels import Registration
        self.assertEqual(SERVER['public_service_name'](Registration(1,b'profile_client',b'private-target')),
                         'profile_client')
        self.assertEqual(SERVER['public_service_name'](Registration(1,b'private-player-name',b'private-target')),
                         'unrecognized')

    def test_advertisements_require_main_channel_mode(self):
        with self.assertRaisesRegex(ValueError, 'requires local profiles'):
            SERVER['BackendConfig'](Path('/unused'), b'', b'', world_template=object())
        with self.assertRaises(ValueError):
            SERVER["BackendConfig"](Path("/unused"), b"", b"", experimental_profiles=True)
        for changes in ({}, {"channel_setup": True, "protocol_version": 556}):
            with self.assertRaises(ValueError):
                SERVER["BackendConfig"](Path("/unused"), b"", b"", service_advertisements=True, **changes)
        with self.assertRaises(ValueError):
            SERVER["BackendConfig"](Path("/unused"), b"", b"", channel_setup=True, experimental_auth=True)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_combined_cli_listeners_and_shutdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca, leaf = root / "ca", root / "leaf"
            subprocess.run([str(PROJECT / "tools/generate-tctd-bootstrap-identity.sh"), str(ca)],
                           check=True, capture_output=True)
            subprocess.run([str(PROJECT / "tools/generate-tctd-echo-identity.sh"), str(ca), str(leaf)],
                           check=True, capture_output=True)
            preface = bytes.fromhex("46010220") + bytes(32)
            (root / "server.bin").write_bytes(preface)
            (root / "client.bin").write_bytes(bytes.fromhex("0e01000408000000"))
            with socket.socket() as first, socket.socket() as second:
                first.bind(("127.0.0.1", 0))
                second.bind(("127.0.0.1", 0))
                ports = (first.getsockname()[1], second.getsockname()[1])
            process = subprocess.Popen([
                sys.executable, str(PROJECT / "tools/run-tctd-backend-server.py"),
                "--cert", str(leaf / "server-cert.pem"), "--key", str(leaf / "server-key.pem"),
                "--capture-dir", str(root / "capture"), "--server-preface", str(root / "server.bin"),
                "--expected-client-preface", str(root / "client.bin"),
                "--port", str(ports[0]), "--latency-port", str(ports[1]), "--channel-setup"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = bytearray()
            try:
                deadline = time.monotonic() + 5
                while b"TCTD_BACKEND_READY" not in output and time.monotonic() < deadline:
                    if select.select([process.stdout], [], [], 0.1)[0]:
                        data = os.read(process.stdout.fileno(), 4096)
                        if not data:
                            break
                        output.extend(data)
                self.assertIn(b"TCTD_BACKEND_READY", output)
                self.assertIn(b"TCTD_LATENCY_READY", output)
                with socket.create_connection(("127.0.0.1", ports[0]), timeout=2) as client:
                    self.assertEqual(SERVER["TLS"]["receive_exact"](client, 36), preface)
                with socket.create_connection(("127.0.0.1", ports[1]), timeout=2) as client:
                    self.assertEqual(SERVER["TLS"]["receive_exact"](client, 8),
                                     bytes.fromhex("0703ac040600c801"))
                    process.terminate()
                    self.assertEqual(client.recv(1), b"")
                output.extend(process.communicate(timeout=7)[0])
                self.assertEqual(process.returncode, 0, output.decode())
                self.assertEqual((root / "capture").stat().st_mode & 0o777, 0o700)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)

    def assert_peer_closed(self, tls):
        # A bounded diagnostic endpoint closes without waiting for the peer's
        # TLS close_notify. OpenSSL may surface that as EOF or EPIPE on AF_UNIX.
        try:
            self.assertEqual(tls.recv(1), b"")
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
            pass

    def test_metadata_does_not_print_opaque_payloads(self):
        secret = b"synthetic-account-secret"
        text = SERVER["frame_metadata"](TransportFrame(False, 8, secret))
        self.assertNotIn(secret.decode(), text)
        self.assertIn("type=0x0008", text)
        with self.assertRaises(DecodeError):
            SERVER["frame_metadata"](TransportFrame(True, 3, b"\x01\x02"))

    def test_mismatching_preface_never_starts_tls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server, client = socket.socketpair()
            config = SERVER["BackendConfig"](root, b"s" * 36, b"c" * 8)
            worker = threading.Thread(target=SERVER["handle_connection"], args=(1, server, None, config))
            with contextlib.redirect_stdout(io.StringIO()) as log:
                worker.start()
                client.settimeout(2)
                try:
                    self.assertEqual(SERVER["TLS"]["receive_exact"](client, 36), b"s" * 36)
                    client.sendall(b"bad-data")
                    self.assertEqual(client.recv(1), b"")
                finally:
                    client.close()
                    worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertIn("client-preface-mismatch", log.getvalue())
            self.assertNotIn("TLS_ESTABLISHED", log.getvalue())

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_preface_tls_root_capture_and_clean_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca, leaf = root / "ca", root / "leaf"
            subprocess.run([str(PROJECT / "tools/generate-tctd-bootstrap-identity.sh"), str(ca)],
                           check=True, capture_output=True)
            subprocess.run([str(PROJECT / "tools/generate-tctd-echo-identity.sh"), str(ca), str(leaf)],
                           check=True, capture_output=True)
            context = SERVER["TLS"]["create_tls_context"](leaf / "server-cert.pem", leaf / "server-key.pem", None)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.minimum_version = client_context.maximum_version = ssl.TLSVersion.TLSv1_2
            client_context.load_verify_locations(ca / "server-cert.pem")
            client_context.set_ciphers(SERVER["TLS"]["TLS_CIPHER"])
            preface = bytes.fromhex("46010220") + bytes(32)
            client_preface = bytes.fromhex("0e01000408000000")
            for identifier, mode in enumerate(("normal", "malformed", "bad-root", "unsupported", "truncated", "limit", "stopped", "channels", "advertisements"), 1):
                with self.subTest(mode=mode):
                    stop = threading.Event()
                    server, client = socket.socketpair()
                    config = SERVER["BackendConfig"](root, preface, client_preface,
                        max_capture_bytes=8 if mode == "limit" else 262144,
                        channel_setup=mode in ("channels", "unsupported", "advertisements"),
                        service_advertisements=mode == "advertisements")
                    worker = threading.Thread(target=SERVER["handle_connection"],
                        args=(identifier, server, context, config, stop))
                    secret = b"synthetic-private-auth-body"
                    data = {"malformed": b"\0\0", "bad-root": encode_compressed_stream(b"\0"),
                            "unsupported": encode_compressed_stream(encode_transport_frame(TransportFrame(False, 99, b""))),
                            "truncated": b"\x03"}.get(mode,
                            encode_compressed_stream(encode_transport_frame(TransportFrame(False, 8, secret))))
                    with contextlib.redirect_stdout(io.StringIO()) as log:
                        worker.start()
                        client.settimeout(2)
                        try:
                            self.assertEqual(SERVER["TLS"]["receive_exact"](client, 36), preface)
                            actual_preface = client_preface[:4] + (identifier - 1).to_bytes(4, "little")
                            for byte in actual_preface:
                                client.sendall(bytes([byte]))
                            self.assertEqual(SERVER["TLS"]["receive_exact"](client, 3), bytes.fromhex("040001"))
                            with client_context.wrap_socket(client, server_hostname="localhost") as tls:
                                startup = bytes.fromhex("07038810")
                                if config.channel_setup:
                                    startup += bytes.fromhex("040700")
                                if config.service_advertisements:
                                    startup += b"".join(encode_transport_frame(encode_service_advertisement(r))
                                                        for r in local_service_advertisements())
                                expected_start = encode_compressed_stream(startup)
                                self.assertEqual(SERVER["TLS"]["receive_exact"](tls, len(expected_start)), expected_start)
                                if mode in ("channels", "advertisements"):
                                    from test_main_channels import registration
                                    request = registration()
                                    if mode == "advertisements":
                                        auth = next(r for r in local_service_advertisements()
                                                    if dict(r.attributes)[b"type"] == b"auth")
                                        # Synthetic use of an advertised ID, NOT proof of
                                        # retail registration-field direction/binding.
                                        request = registration(name=auth.name)
                                    # Exact regression from the game, split across TLS writes.
                                    data = bytes.fromhex("0300200209")
                                    for byte in data:
                                        tls.sendall(bytes([byte]))
                                    self.assertEqual(SERVER["TLS"]["receive_exact"](tls, 5), bytes.fromhex("030020020a"))
                                    registration_wire = encode_compressed_stream(encode_transport_frame(request))
                                    data += registration_wire
                                    tls.sendall(registration_wire)
                                    expected = encode_compressed_stream(bytes.fromhex("0801110001"))
                                    self.assertEqual(SERVER["TLS"]["receive_exact"](tls, len(expected)), expected)
                                    heartbeat = encode_compressed_stream(encode_transport_frame(TransportFrame(False, 9, b"")))
                                    data += heartbeat
                                    tls.sendall(heartbeat)
                                    self.assertEqual(SERVER["TLS"]["receive_exact"](tls, 5), bytes.fromhex("030020020a"))
                                elif mode == "stopped":
                                    stop.set()
                                    self.assert_peer_closed(tls)
                                else:
                                    tls.sendall(data)
                                    if mode == "truncated":
                                        # Send close_notify so the server observes EOF, not
                                        # AF_UNIX's platform-dependent abrupt-close EPIPE.
                                        try:
                                            tls.unwrap()
                                        except (ssl.SSLError, BrokenPipeError, ConnectionResetError):
                                            pass
                                    if mode in ("limit", "malformed", "bad-root", "unsupported"):
                                        self.assert_peer_closed(tls)
                        finally:
                            client.close()
                            worker.join(3)
                    self.assertFalse(worker.is_alive())
                    self.assertIn("TCTD_BACKEND_TLS_ESTABLISHED", log.getvalue())
                    self.assertIn(f"header_match=1 template_match={int(actual_preface == client_preface)}", log.getvalue())
                    self.assertNotIn(secret.decode(), log.getvalue())
                    self.assertIn("application_responses=" + ("3" if mode in ("channels", "advertisements") else "0"), log.getvalue())
                    self.assertNotIn("synthetic-service", log.getvalue())
                    if mode in ("channels", "advertisements"):
                        path = root / f"backend-{identifier:04d}-client-root.bin"
                        self.assertEqual(path.read_bytes(), b"\x02\x09" +
                                         encode_transport_frame(request) + b"\x02\x09")
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                        self.assertIn("compression_blocks=3", log.getvalue())
                        server_root = (root / f"backend-{identifier:04d}-server-root.bin").read_bytes()
                        self.assertEqual(server_root, startup + bytes.fromhex("020a0801110001020a"))
                    if mode == "advertisements":
                        self.assertIn("ADVERTISEMENTS_SENT connection=9 count=24", log.getvalue())
                        for record in local_service_advertisements():
                            self.assertNotIn(record.name.decode(), log.getvalue())
                    else:
                        self.assertNotIn("ADVERTISEMENTS_SENT", log.getvalue())
                    if mode != "stopped":
                        path = root / f"backend-{identifier:04d}-plaintext.bin"
                        self.assertEqual(path.read_bytes(), data[:config.max_capture_bytes])
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertIn({"normal": "root-frames-received", "limit": "capture-limit",
                                   "malformed": "invalid-compression", "bad-root": "invalid-root-framing",
                                   "unsupported": "invalid-channel-message", "truncated": "invalid-compression",
                                   "stopped": "outcome=stopped",
                                   "channels": "registration-ack-sent",
                                   "advertisements": "registration-ack-sent"}[mode], log.getvalue())

    def test_plain_tcp_latency_handler(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server, client = socket.socketpair()
            stop = threading.Event()
            worker = threading.Thread(target=SERVER["handle_latency"], args=(1, server, root, stop))
            with contextlib.redirect_stdout(io.StringIO()) as log:
                worker.start()
                client.settimeout(2)
                try:
                    self.assertEqual(SERVER["TLS"]["receive_exact"](client, 8), bytes.fromhex("0703ac040600c801"))
                    sent = bytearray()
                    for sequence in range(3):
                        frame = encode_transport_frame(TransportFrame(False, 1, bytes([sequence])))
                        sent.extend(frame)
                        client.sendall(frame)
                        self.assertEqual(SERVER["TLS"]["receive_exact"](client, 3), bytes([4, 2, sequence]))
                    summary = encode_transport_frame(TransportFrame(False, 3, b"\x03\x06\x01\x03\x00"))
                    sent.extend(summary)
                    client.sendall(summary)
                    self.assertEqual(client.recv(1), b"")
                finally:
                    client.close()
                    worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertIn("outcome=complete pings=3", log.getvalue())
            path = root / "latency-0001-plaintext.bin"
            self.assertEqual(path.read_bytes(), bytes(sent))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
