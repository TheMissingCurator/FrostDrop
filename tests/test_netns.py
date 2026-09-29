import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/isac-netns.py"
FIXTURE = ROOT / "tests/netns_fixture.py"
spec = importlib.util.spec_from_file_location("isac_netns", TOOL)
netns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netns)


class NetnsUnitTest(unittest.TestCase):
    def test_member_check_requires_namespace_and_live_owner_identity(self):
        record = {"pid": os.getpid(), "uid": os.getuid(), "net": 20,
                  "host_net": 10, "user": 30, "owner_start_time": 456}
        with patch.object(netns, "private_directory"), \
             patch.object(netns, "read_state", return_value=record), \
             patch.object(netns, "process_start_time", return_value=456) as birth, \
             patch.object(netns, "inode", return_value=20) as identity, \
             patch.object(netns, "check_network") as network, \
             patch.dict(os.environ, {"ISAC_HOST_PROC": "/proc"}):
            self.assertEqual(netns.check_member(Path("/unused")), record)
            identity.assert_called_once_with("/proc/self/ns/net")
            network.assert_called_once()
            network.reset_mock()
            identity.return_value = 10
            with self.assertRaisesRegex(RuntimeError, "outside"):
                netns.check_member(Path("/unused"))
            network.assert_not_called()
            identity.return_value = 20
            birth.return_value = 457
            with self.assertRaisesRegex(RuntimeError, "lifetime changed"):
                netns.check_member(Path("/unused"))
            birth.side_effect = FileNotFoundError
            with self.assertRaises(FileNotFoundError):
                netns.check_member(Path("/unused"))
            for value in (None, True, 0, "456"):
                record["owner_start_time"] = value
                with self.assertRaisesRegex(RuntimeError, "lifetime identity"):
                    netns.check_member(Path("/unused"))

    def test_process_start_time_handles_parentheses_in_comm(self):
        fields = ["S"] + ["0"] * 18 + ["123456"] + ["0"] * 8
        with patch.object(Path, "read_text", return_value="123 (odd (process) name) " + " ".join(fields)):
            self.assertEqual(netns.process_start_time(Path("/fixture")), 123456)

    def test_environment_drops_proxies(self):
        with patch.dict(os.environ, {"http_proxy": "secret", "HTTPS_PROXY": "secret", "KEEP": "yes"}, clear=True):
            self.assertEqual(netns.clean_environment(), {"KEEP": "yes", "NO_PROXY": "*"})

    def test_directory_permissions_and_missing_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            netns.private_directory(directory)
            with self.assertRaises(FileNotFoundError):
                netns.read_state(directory)
            directory.chmod(0o755)
            with self.assertRaises(RuntimeError):
                netns.private_directory(directory)

    def test_reject_host_namespace_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "session.json"
            state.write_text(json.dumps({"pid": os.getpid(), "uid": os.getuid(),
                                         "net": 1, "host_net": 1, "user": 2}))
            state.chmod(0o600)
            with self.assertRaises(RuntimeError):
                netns.read_state(Path(temporary))

    def test_non_loopback_fails_before_probing(self):
        with patch.object(netns.socket, "if_nameindex", return_value=[(1, "lo"), (2, "ethernet")]), \
             patch.object(netns.socket, "socket") as probe:
            with self.assertRaises(RuntimeError):
                netns.check_network()
            probe.assert_not_called()

    def test_external_or_uninspectable_wine_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "12345"
            process.mkdir()
            (process / "comm").write_text("wineserver\n")
            with patch.object(netns.Path, "iterdir", return_value=[process]), \
                 patch.object(netns, "process_prefix", return_value=(1, 2)):
                with patch.object(netns, "inode", return_value=10):
                    netns.reject_external_wine(10, (1, 2))
                    with self.assertRaisesRegex(RuntimeError, "wineserver"):
                        netns.reject_external_wine(20, (1, 2))
                with patch.object(netns, "inode", side_effect=PermissionError):
                    with self.assertRaisesRegex(RuntimeError, "unreadable"):
                        netns.reject_external_wine(20, (1, 2))

    def test_unrelated_prefix_ignores_even_unreadable_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "12345"
            process.mkdir()
            (process / "comm").write_text("wineserver\n")
            with patch.object(netns.Path, "iterdir", return_value=[process]), \
                 patch.object(netns, "process_prefix", return_value=(3, 4)), \
                 patch.object(netns, "inode", side_effect=PermissionError) as ns:
                netns.reject_external_wine(20, (1, 2))
                ns.assert_not_called()

    def test_unknown_prefix_still_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "12345"
            process.mkdir()
            (process / "comm").write_text("wineserver\n")
            with patch.object(netns.Path, "iterdir", return_value=[process]), \
                 patch.object(netns, "process_prefix", side_effect=PermissionError):
                with self.assertRaisesRegex(RuntimeError, "unidentified"):
                    netns.reject_external_wine(20, (1, 2))

    def test_prefix_identity_aliases_and_environment_precedence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compat = root / "compat"
            target = compat / "pfx"
            target.mkdir(parents=True)
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            other = root / "other"
            other.mkdir()
            with patch.dict(os.environ, {"STEAM_COMPAT_DATA_PATH": str(compat), "WINEPREFIX": str(other)}, clear=True):
                self.assertEqual(netns.launch_prefix(), netns.directory_identity(target))
            with patch.dict(os.environ, {"WINEPREFIX": str(alias)}, clear=True):
                self.assertEqual(netns.launch_prefix(), netns.directory_identity(target))
            process = root / "12345"
            process.mkdir()
            (process / "root").symlink_to("/", target_is_directory=True)
            (process / "environ").write_bytes(os.fsencode(f"WINEPREFIX={alias}\0STEAM_COMPAT_DATA_PATH={other}\0"))
            self.assertEqual(netns.process_prefix(process), netns.directory_identity(target))

    def test_process_root_and_default_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / "12345"
            target = process / "root/home/example/.wine"
            target.mkdir(parents=True)
            (process / "environ").write_bytes(b"HOME=/home/example\0")
            self.assertEqual(netns.process_prefix(process), netns.directory_identity(target))
            (process / "environ").write_bytes(b"WINEPREFIX=relative\0")
            with self.assertRaises(RuntimeError):
                netns.process_prefix(process)

    def test_missing_launch_prefix_refuses(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "Cannot identify"):
                netns.launch_prefix()


@unittest.skipUnless(os.environ.get("ISAC_TEST_NETNS") == "1", "Opt-in real kernel namespace test")
class NetnsIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="project-isac-netns-test-")
        self.directory = Path(self.temporary.name)
        self.state = self.directory / "state"
        self.marker = self.directory / "peer.json"
        self.host = socket.socket()
        self.host.bind(("127.0.0.1", 0))
        self.host.listen()
        self.log = open(self.directory / "namespace.log", "w+")
        self.process = subprocess.Popen(self.command("run", "--", sys.executable, str(FIXTURE), "serve",
                                                      str(self.marker), str(self.host.getsockname()[1])),
                                        stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not self.marker.exists():
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    self.log.seek(0)
                    self.fail("Namespace did not start: " + self.log.read())
                time.sleep(0.05)
        except BaseException:
            self.tearDown()
            raise

    def command(self, *args):
        return [sys.executable, str(TOOL), "--state-dir", str(self.state), *args]

    def tearDown(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=10)
        self.host.close()
        self.log.close()
        self.temporary.cleanup()

    def peer(self, message):
        return subprocess.run(self.command("join", "--", sys.executable, str(FIXTURE), "client",
                                           str(self.marker), message), capture_output=True, text=True, timeout=10,
                              env=dict(os.environ, http_proxy="http://127.0.0.1:9"))

    def test_join_bidirectional_isolation_and_cleanup(self):
        record = json.loads(self.marker.read_text())
        self.assertNotEqual(record["net"], os.stat("/proc/self/ns/net").st_ino)
        with socket.socket() as host_probe:
            host_probe.settimeout(0.5)
            self.assertNotEqual(host_probe.connect_ex(("127.0.0.1", record["port"])), 0)
        child = self.peer("hello")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertIn("NETNS_PEER_OK", child.stdout)
        second = subprocess.run(self.command("run", "--", "/usr/bin/true"), capture_output=True, text=True)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("already running", second.stderr)
        outside = subprocess.run(self.command("check"), capture_output=True, text=True)
        self.assertNotEqual(outside.returncode, 0)
        self.assertEqual(self.peer("stop").returncode, 0)
        self.assertEqual(self.process.wait(timeout=10), 0)
        self.assertFalse((self.state / "session.json").exists())
        stale = self.peer("hello")
        self.assertNotEqual(stale.returncode, 0)
        self.assertNotIn("NETNS_PEER_OK", stale.stdout)

    def test_termination_removes_namespace_processes(self):
        state = json.loads((self.state / "session.json").read_text())
        self.process.terminate()
        self.process.wait(timeout=10)
        self.assertFalse((self.state / "session.json").exists())
        deadline = time.monotonic() + 3
        while Path(f"/proc/{state['pid']}").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(Path(f"/proc/{state['pid']}").exists())

    def test_game_join_uses_prefix_guard(self):
        compat = self.directory / "compat"
        (compat / "pfx").mkdir(parents=True)
        # Optional real Division prefix: inspect its identity without starting
        # Wine or touching prefix contents. Existing unrelated apps stay running.
        target = os.environ.get("ISAC_TEST_GAME_COMPAT", str(compat))
        result = subprocess.run(self.command("join-game", "--", sys.executable, str(FIXTURE), "client",
                                             str(self.marker), "game-guard"),
                                capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, STEAM_COMPAT_DATA_PATH=target))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NETNS_PEER_OK", result.stdout)

    @unittest.skipUnless(os.environ.get("ISAC_TEST_STEAM_RUNTIME"), "Optional installed Steam runtime check")
    def test_steam_runtime_keeps_private_network(self):
        runtime = os.environ["ISAC_TEST_STEAM_RUNTIME"]
        result = subprocess.run(self.command("join", "--", runtime, "--verb=run", "--",
                                             "/usr/bin/python3", str(FIXTURE), "client", str(self.marker), "runtime"),
                                capture_output=True, text=True, timeout=45,
                                env=dict(os.environ, PRESSURE_VESSEL_VARIABLE_DIR=str(self.directory / "runtime")))
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        self.assertIn("NETNS_PEER_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
