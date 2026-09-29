from datetime import datetime, timedelta, timezone
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from isac_backend.sdk_services import ACCOUNT_ID, FEATURES, SDKServer, SDKServices, configuration
from isac_backend.auth import INTERNAL_AUTH_PATH, validate_with_sdk


class SessionTest(unittest.TestCase):
    def test_identity_expiry_and_bounded_sessions(self):
        now = datetime(2026, 9, 26, tzinfo=timezone.utc)
        services = SDKServices(lambda: now)
        session = services.create_session()
        self.assertEqual(session["profileId"], ACCOUNT_ID)
        self.assertEqual(session["userId"], ACCOUNT_ID)
        self.assertEqual(session["environment"], "Prod")
        self.assertNotEqual(session["token"], session["ticket"])
        headers = {"Ubi-SessionId": session["sessionId"], "Authorization": "Ubi_v1 t=" + session["ticket"]}
        self.assertTrue(services.authorized(headers))
        self.assertFalse(services.authorized(dict(headers, Authorization="bad")))
        self.assertFalse(services.authorized({}))
        for _ in range(63):
            self.assertIsNotNone(services.create_session())
        self.assertIsNone(services.create_session())
        now += timedelta(hours=3)
        self.assertFalse(services.authorized(headers))
        self.assertIsNotNone(services.create_session())
        self.assertEqual(len(services.sessions), 1)

    def test_config_typed_explicit_switches_local_resources(self):
        config = configuration()
        switches = {entry["name"]: entry["value"] for entry in config["featuresSwitches"]}
        self.assertEqual(len(FEATURES), 30)
        self.assertEqual(set(switches), set(FEATURES))
        self.assertFalse(switches["Connection"])
        self.assertFalse(switches["WebSocketClient"])
        self.assertTrue(switches["HttpClient"])
        for resource in config["resources"]:
            self.assertTrue(resource["url"].startswith("http://127.0.0.1:55003/"))
            self.assertIs(type(resource["version"]), int)
        self.assertNotIn("ubi.com", json.dumps(config))


class HTTPTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.server = SDKServer(port=0, emit=self.events.append)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            data = response.read()
            self.assertEqual(response.getheader("Connection"), "close")
            self.assertEqual(int(response.getheader("Content-Length")), len(data))
            return response.status, json.loads(data) if data else None
        finally:
            connection.close()

    def test_session_config_logout_roundtrip_and_redaction(self):
        status, session = self.request("POST", "/v3/profiles/sessions?private=never-log", "{}",
                                       {"Authorization": "private-launcher-ticket"})
        self.assertEqual(status, 200)
        headers = {"Ubi-SessionId": session["sessionId"], "Authorization": "Ubi_v1 t=" + session["ticket"]}
        status, config = self.request("GET", "/v1/applications/123/configuration", headers=headers)
        self.assertEqual((status, config), (200, configuration()))
        self.assertEqual(self.request("DELETE", "/v3/profiles/sessions", headers=headers), (204, None))
        self.assertEqual(self.request("GET", "/v1/applications/123/configuration", headers=headers)[0], 401)
        log = "\n".join(self.events)
        for secret in ("never-log", "private-launcher-ticket", session["ticket"], session["sessionId"]):
            self.assertNotIn(secret, log)

    def test_backend_ticket_validation_roundtrip_revocation_and_redaction(self):
        _, session = self.request("POST", "/v1/profiles/sessions", "{}")
        profile = validate_with_sdk(session["ticket"].encode(), port=self.server.server_port)
        self.assertEqual(profile.profile_id, ACCOUNT_ID)
        self.assertEqual(profile.session_id, session["sessionId"])
        self.assertIsNone(validate_with_sdk(b"isac-local-" + b"0" * 64, port=self.server.server_port))
        for body in ('{}', '[]', '{', '{"ticket":123}', '{"ticket":"x","extra":1}'):
            self.assertIn(self.request("POST", INTERNAL_AUTH_PATH, body)[0], (400, 401))
        headers = {"Ubi-SessionId": session["sessionId"], "Authorization": "Ubi_v1 t=" + session["ticket"]}
        self.request("DELETE", "/v1/profiles/sessions", headers=headers)
        self.assertIsNone(validate_with_sdk(session["ticket"].encode(), port=self.server.server_port))
        for value in (session["ticket"], session["sessionId"], ACCOUNT_ID):
            self.assertNotIn(value, "\n".join(self.events))

    def test_reject_invalid_payload_and_unsupported_routes(self):
        for body in ("[1]", "{", b"\xff"):
            self.assertEqual(self.request("POST", "/v1/profiles/sessions", body)[0], 400)
        self.assertEqual(self.request("POST", "/v1/profiles/sessions", "x" * 65537)[0], 413)
        for method, path in (("GET", "/v1/profiles/sessions"), ("POST", "/unknown"),
                             ("GET", "https://example.invalid/private"), ("GET", "/v1/news")):
            self.assertEqual(self.request(method, path)[0], 404)
        self.assertEqual(self.request("GET", "/v1/applications/123/configuration")[0], 401)

    def test_ambiguous_and_chunked_framing_rejected(self):
        for framing in (b"Content-Length: 0\r\nContent-Length: 0", b"Transfer-Encoding: chunked",
                        b"Content-Length: nope"):
            with socket.create_connection(self.server.server_address, timeout=2) as connection:
                connection.sendall(b"POST /v1/profiles/sessions HTTP/1.1\r\nHost: localhost\r\n" + framing + b"\r\n\r\n")
                self.assertIn(b" 400 ", connection.recv(4096))

    def test_logs_bounded(self):
        self.server.event_count = 999
        for _ in range(3):
            self.request("GET", "/unsupported")
        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.events[-1], "SDK_HTTP log_limit=1000")


class OfflineCheckTest(unittest.TestCase):
    def test_interface_flags(self):
        spec = importlib.util.spec_from_file_location("offline", ROOT / "tools/require-offline-network.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        def flags(_fd, _op, request):
            name = request.split(b"\0", 1)[0]
            value = {b"lo": 9, b"wifi": 1, b"ethernet": 0}[name]
            return bytes(16) + struct.pack("H", value) + bytes(238)
        with patch.object(module.socket, "if_nameindex", return_value=[(1, "lo"), (2, "wifi"), (3, "ethernet")]), \
             patch.object(module.fcntl, "ioctl", side_effect=flags):
            self.assertEqual(module.active_links(), ["wifi"])


if __name__ == "__main__":
    unittest.main()
