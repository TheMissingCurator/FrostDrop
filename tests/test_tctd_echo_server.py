import os
from pathlib import Path
import runpy
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SERVER = runpy.run_path(str(PROJECT / "tools/run-tctd-echo-server.py"))


class EchoServerTests(unittest.TestCase):
    def test_wrapper_clears_old_probe_flags(self):
        result = subprocess.run([str(PROJECT / "tools/steam-tctd-echo-wrapper.sh"), "env"],
            env=dict(os.environ, ISAC_TCTD_ALLOCATION_CAPTURE="1"),
            check=True, text=True, capture_output=True)
        flags = {line for line in result.stdout.splitlines() if line.startswith("ISAC_")}
        self.assertEqual(flags, {"ISAC_STACK_PROBE=1", "ISAC_LOCAL_BACKEND_BRIDGE=1",
            "ISAC_TRANSPORT_STARTUP_PROBE=1", "ISAC_TCTD_PC_LOOPBACK=1",
            "ISAC_TCTD_LOCAL_ACCEPT=1", "ISAC_TCTD_ECHO_LOCAL=1"})

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_two_direct_tls_connections_trust_bootstrap_ca_and_receive_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca, leaf = root / "ca", root / "echo"
            subprocess.run([str(PROJECT / "tools/generate-tctd-bootstrap-identity.sh"), str(ca)],
                           check=True, capture_output=True)
            command = [str(PROJECT / "tools/generate-tctd-echo-identity.sh"), str(ca), str(leaf)]
            subprocess.run(command, check=True, capture_output=True)
            original = (leaf / "server-cert.pem").read_bytes()
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(original, (leaf / "server-cert.pem").read_bytes())
            self.assertNotEqual(original, (ca / "server-cert.pem").read_bytes())
            self.assertEqual((leaf / "server-key.pem").stat().st_mode & 0o777, 0o600)
            context = SERVER["TLS"]["create_tls_context"](leaf / "server-cert.pem", leaf / "server-key.pem", None)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.minimum_version = client_context.maximum_version = ssl.TLSVersion.TLSv1_2
            client_context.load_verify_locations(ca / "server-cert.pem")
            client_context.set_ciphers(SERVER["TLS"]["TLS_CIPHER"])
            response = SERVER["encode_directory_response"](SERVER["local_directory"](bytes(32)))
            for identifier in (1, 2):
                server_socket, client_socket = socket.socketpair()
                client_socket.settimeout(2)
                worker = threading.Thread(target=SERVER["handle_connection"],
                    args=(identifier, server_socket, context, root, response, 1))
                worker.start()
                try:
                    with client_context.wrap_socket(client_socket, server_hostname="localhost") as tls:
                        # No custom preface or application request sent before receiving.
                        received = SERVER["TLS"]["receive_exact"](tls, len(response))
                        self.assertEqual(received, response)
                        tls.sendall(b"synthetic-client-diagnostic")
                finally:
                    client_socket.close()
                    worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
                capture = root / f"echo-{identifier:04d}-plaintext.bin"
                self.assertEqual(capture.read_bytes(), b"synthetic-client-diagnostic")
                self.assertEqual(capture.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
