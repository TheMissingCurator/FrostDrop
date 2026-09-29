import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("steam_ipc_relay", ROOT / "tools/steam_ipc_relay.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class EndpointTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        process = Path(self.temp.name)
        (process / "fd").mkdir()
        (process / "net").mkdir()
        (process / "comm").write_text("steam\n")
        (process / "exe").symlink_to("/example/steam")
        (process / "stat").write_text("123 (steam) " + "0 " * 19 + "100 0")
        (process / "fd/1").symlink_to("socket:[1234]")
        self.endpoint = relay.SteamEndpoint.__new__(relay.SteamEndpoint)
        self.endpoint.process = process
        self.endpoint.started = "100"
        self.table()

    def tearDown(self):
        self.temp.cleanup()

    def table(self, address="0100007F:DFFF", state="0A", uid=None, inode="1234"):
        uid = os.getuid() if uid is None else uid
        (self.endpoint.process / "net/tcp").write_text(
            f"header\n0: {address} 00000000:0000 {state} 0:0 0:0 0 {uid} 0 {inode}\n")

    def test_only_owned_loopback_listener(self):
        self.endpoint.validate()
        for changes in ({"address": "00000000:DFFF"}, {"address": "0100007F:1234"},
                        {"state": "01"}, {"inode": "other"}, {"uid": os.getuid() + 1}):
            self.table(**changes)
            with self.assertRaises(RuntimeError):
                self.endpoint.validate()

    def test_pid_restart_or_executable_change_refused(self):
        self.endpoint.started = "99"
        with self.assertRaisesRegex(RuntimeError, "changed"):
            self.endpoint.validate()
        self.endpoint.started = "100"
        (self.endpoint.process / "comm").write_text("not-steam")
        with self.assertRaisesRegex(RuntimeError, "changed"):
            self.endpoint.validate()


class PumpTest(unittest.TestCase):
    def test_large_transfer_half_close_and_reverse_reply(self):
        client, left = socket.socketpair()
        right, server = socket.socketpair()
        stop = threading.Event()
        worker = threading.Thread(target=relay.pump, args=(left, right, stop))
        worker.start()
        payload = b"bounded-local-test" * 32768
        received = bytearray()
        def receiver():
            while data := server.recv(8192):
                received.extend(data)
            server.sendall(b"reply")
            server.shutdown(socket.SHUT_WR)
        reader = threading.Thread(target=receiver)
        reader.start()
        try:
            client.settimeout(5)
            server.settimeout(5)
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(5), b"reply")
            self.assertEqual(client.recv(1), b"")
            worker.join(timeout=5)
            reader.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(received, payload)
        finally:
            stop.set()
            for peer in (client, left, right, server):
                peer.close()
            worker.join(timeout=2)
            reader.join(timeout=2)


@unittest.skipUnless(os.environ.get("ISAC_TEST_STEAM_IPC") == "1", "Opt-in local Steam handshake")
class RealSteamTest(unittest.TestCase):
    def test_isolated_steam_handshake_and_network_controls(self):
        with tempfile.TemporaryDirectory(prefix="isac-steam-ipc-test-") as temporary:
            directory = Path(temporary)
            probe = directory / "probe"
            subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-rdynamic",
                            str(ROOT / "tests/steam_ipc_probe.c"), "-ldl", "-o", str(probe)], check=True)
            library = Path.home() / ".local/share/Steam/linux64/steamclient.so"
            # One host listener verifies the bridge does NOT expose other ports.
            with socket.socket() as host:
                host.bind(("127.0.0.1", 0))
                host.listen()
                command = [sys.executable, str(ROOT / "tests/steam_ipc_fixture.py"), str(probe),
                           str(library), str(host.getsockname()[1])]
                manager = [sys.executable, str(ROOT / "tools/isac-netns.py"),
                           "--state-dir", str(directory / "state")]
                marker = directory / "peer.json"
                fixture = [sys.executable, str(ROOT / "tests/netns_fixture.py")]
                (directory / "compat/pfx").mkdir(parents=True)
                with (directory / "runner.log").open("w+") as log:
                    owner = subprocess.Popen([*manager, "--steam-ipc", "run", "--", *fixture,
                                              "serve", str(marker), str(host.getsockname()[1])],
                                             stdout=log, stderr=subprocess.STDOUT)
                    try:
                        deadline = time.monotonic() + 10
                        while not marker.exists():
                            if owner.poll() is not None or time.monotonic() > deadline:
                                log.seek(0)
                                self.fail("Relay startup failed: " + log.read())
                            time.sleep(0.05)
                        # Match the game: launcher joins only user/network NS,
                        # not the backend supervisor's private PID namespace.
                        result = subprocess.run([*manager, "join-game", "--", *command],
                                                capture_output=True, text=True, timeout=45,
                                                env=dict(os.environ, STEAM_COMPAT_DATA_PATH=str(directory / "compat")))
                        subprocess.run([*manager, "join", "--", *fixture, "client", str(marker), "stop"],
                                       check=True, capture_output=True, timeout=10)
                        self.assertEqual(owner.wait(timeout=10), 0)
                    finally:
                        if owner.poll() is None:
                            owner.terminate()
                        owner.wait(timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("pipe_created=1", result.stdout)
            self.assertIn("user_connected=1", result.stdout)
            self.assertIn("STEAM_IPC_NEGATIVE_CONTROLS_OK", result.stdout)
            self.assertFalse((directory / "state/session.json").exists())
            self.assertFalse((directory / "state/steam-ipc.sock").exists())
