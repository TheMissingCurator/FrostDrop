import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit-game-routes.py"
spec = importlib.util.spec_from_file_location("route_audit", TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def encode(address, port):
    raw = ipaddress.ip_address(address).packed
    words = [f"{struct.unpack('=I', raw[i:i + 4])[0]:08X}" for i in range(0, len(raw), 4)]
    return "".join(words) + f":{port:04X}"


def row(address="127.0.0.1", port=55003, inode=123, state=1):
    local = "::1" if ":" in address else "127.0.0.1"
    return f"0: {encode(local, 43210)} {encode(address, port)} {state:02X} 0:0 0:0 0 1000 0 {inode} 1\n"


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = self.root / "game-prefix"
        self.prefix.mkdir()
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.events = []

    def process(self, pid=12, prefix=None, comm="thedivision.exe", extra_env=b"", start=100):
        path = self.proc / str(pid)
        path.mkdir()
        (path / "comm").write_text(comm + "\n")
        fields = ["S", "10"] + ["0"] * 17 + [str(start)]
        (path / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))
        (path / "root").symlink_to("/", target_is_directory=True)
        (path / "environ").write_bytes(b"WINEPREFIX=" + os.fsencode(prefix or self.prefix) + b"\0" + extra_env)
        (path / "fd").mkdir()
        (path / "fd/3").symlink_to("socket:[123]")
        (path / "net").mkdir()
        for name in module.TABLES:
            (path / "net" / name).write_text("header\n")
        return path

    def audit(self, limit=4096):
        return module.RouteAudit(self.prefix, self.events.append, self.proc, limit)

    def test_ipv4_ipv6_and_mapped_scope(self):
        for address in ("127.0.0.2", "8.8.8.8", "::1", "2001:db8::1234", "::ffff:127.0.0.1"):
            decoded, port = module.endpoint(encode(address, 443), ":" in address)
            self.assertEqual(ipaddress.ip_address(decoded), ipaddress.ip_address(address))
            self.assertEqual(port, 443)
        self.assertEqual(module.route_class("::ffff:127.0.0.1", 55003), "local-backend-port")
        self.assertEqual(module.route_class("::1", 57343), "local-steam-ipc-port")
        self.assertEqual(module.route_class("127.0.0.1", 9999), "other-loopback")
        for address in ("192.168.1.1", "8.8.8.8", "2001:db8::1"):
            self.assertEqual(module.route_class(address, 443), "non-loopback-candidate")

    def test_filters_namespace_table_by_owned_inode(self):
        process = self.process()
        (process / "net/tcp").write_text("header\n" + row() + row("8.8.8.8", 443, 999))
        audit = self.audit()
        audit.sample()
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0]["destination"], "127.0.0.1")
        self.assertNotIn("8.8.8.8", json.dumps(audit.summary()))

    def test_other_prefix_and_unrelated_app_excluded(self):
        other = self.root / "other-prefix"
        other.mkdir()
        process = self.process(13, other, "wineserver")
        (process / "net/tcp").write_text(row("8.8.8.8", 443))
        app = self.process(14, self.prefix, "firefox")
        (app / "net/tcp").write_text(row("1.1.1.1", 443))
        audit = self.audit()
        audit.sample()
        self.assertEqual(audit.summary()["matched_processes"], 0)
        self.assertEqual(self.events, [])

    def test_alias_prefix_identity_and_compatdata_fallback(self):
        alias = self.root / "alias"
        alias.symlink_to(self.prefix, target_is_directory=True)
        process = self.process(prefix=alias)
        self.assertEqual(module.process_prefix(process), module.identity(self.prefix))
        compat = self.root / "compat"
        compat.mkdir()
        (compat / "pfx").symlink_to(self.prefix, target_is_directory=True)
        (process / "environ").write_bytes(b"STEAM_COMPAT_DATA_PATH=" + os.fsencode(compat) + b"\0")
        self.assertEqual(module.process_prefix(process), module.identity(self.prefix))
        (process / "environ").write_bytes(b"WINEPREFIX=relative\0")
        with self.assertRaises(ValueError):
            module.process_prefix(process)

    def test_metadata_dedup_state_change_and_pid_reuse(self):
        process = self.process()
        table = process / "net/tcp"
        table.write_text(row("8.8.8.8", 443, state=2))
        audit = self.audit()
        audit.sample()
        audit.sample()
        self.assertEqual(len(self.events), 1)
        table.write_text(row("8.8.8.8", 443, state=1))
        audit.sample()
        self.assertEqual(len(self.events), 2)
        fields = ["S", "10"] + ["0"] * 17 + ["200"]
        (process / "stat").write_text("12 (thedivision.exe) " + " ".join(fields))
        audit.sample()
        self.assertEqual(len(self.events), 3)
        summary = audit.summary()
        self.assertEqual(summary["matched_processes"], 2)
        self.assertEqual(summary["routes"][0]["states"], ["established", "syn-sent"])

    def test_no_listener_or_unconnected_udp_destination(self):
        lines = row(state=10) + row("0.0.0.0", 0)
        self.assertEqual(list(module.parse_table(io.StringIO(lines), "tcp", {123})), [])
        self.assertEqual(list(module.parse_table(io.StringIO(row("::", 0)), "tcp6", {123})), [])
        self.assertEqual(list(module.parse_table(io.StringIO(row("0.0.0.0", 0)), "udp", {123})), [])
        self.assertEqual(len(list(module.parse_table(io.StringIO(row("8.8.8.8", 53)), "udp", {123}))), 1)

    def test_bounded_logging_and_limit_record(self):
        process = self.process()
        (process / "net/tcp").write_text(row() + row("8.8.8.8", 443))
        audit = self.audit(limit=1)
        audit.sample()
        audit.sample()
        self.assertEqual([item["event"] for item in self.events], ["socket", "limit"])
        self.assertTrue(audit.summary()["limit_reached"])
        self.assertEqual(len(audit.seen), 1)

    def test_secrets_not_logged_or_used_for_network_requests(self):
        process = self.process(extra_env=b"TOKEN=SECRET_TOKEN\0URL=https://user:password@example.invalid/?key=PRIVATE\0")
        (process / "net/tcp").write_text(row("8.8.8.8", 443))
        (process / "cmdline").write_bytes(b"SECRET_COMMAND\0")
        audit = self.audit()
        with patch.object(socket, "socket", side_effect=AssertionError("No sockets allowed")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("No DNS allowed")):
            audit.sample()
        output = json.dumps(self.events) + json.dumps(audit.summary()) + module.report(audit.summary())
        for secret in ("SECRET_TOKEN", "password", "PRIVATE", "SECRET_COMMAND", str(self.prefix)):
            self.assertNotIn(secret, output)

    def test_unreadable_prefix_and_fd_counted_not_misattributed(self):
        process = self.process()
        (process / "environ").write_bytes(b"TOKEN=never-print\0")
        audit = self.audit()
        audit.sample()
        self.assertEqual(audit.errors["prefix_unavailable"], 1)
        self.assertEqual(audit.summary()["matched_processes"], 0)
        self.assertEqual(self.events, [])
        (process / "environ").write_bytes(b"WINEPREFIX=" + os.fsencode(self.prefix) + b"\0")
        with patch.object(module, "socket_inodes", side_effect=PermissionError):
            audit.sample()
        self.assertEqual(audit.errors["fd_unavailable"], 1)
        self.assertEqual(audit.summary()["matched_processes"], 1)
        self.assertEqual(self.events, [])

    def test_cli_stops_and_writes_summary(self):
        process = self.process()
        (process / "net/tcp").write_text(row())
        output = self.root / "evidence"
        output.mkdir()
        child = subprocess.Popen([sys.executable, str(TOOL), "--prefix", str(self.prefix),
                                  "--output-dir", str(output)],
                                 env=dict(os.environ, ISAC_HOST_PROC=str(self.proc)),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            file = output / "route-audit.jsonl"
            if file.exists() and '"event": "socket"' in file.read_text():
                break
            time.sleep(0.02)
        child.send_signal(signal.SIGTERM)
        stdout, stderr = child.communicate(timeout=3)
        self.assertEqual((child.returncode, stdout, stderr), (0, "", ""))
        values = [json.loads(line) for line in (output / "route-audit.jsonl").read_text().splitlines()]
        self.assertEqual(values[0]["event"], "ready")
        self.assertEqual(values[-1]["event"], "finished")
        self.assertEqual(json.loads((output / "route-audit-summary.json").read_text())["events"], 1)
        self.assertIn("local-backend-port", (output / "route-audit-summary.txt").read_text())

    def test_empty_inventory_does_not_claim_no_traffic(self):
        audit = self.audit()
        audit.sample()
        self.assertIn("not proof of no external traffic", module.report(audit.summary()))

    def test_capture_lifecycle_in_temporary_project(self):
        # Exercise the actual shell/helper lifecycle, not a game launch. Keep
        # every generated evidence file inside this test's disposable project.
        project = self.root / "project"
        tools = project / "tools"
        tools.mkdir(parents=True)
        for name in ("capture-startup-linux.sh", "audit-game-routes.py", "watch-sdk-protection.py"):
            shutil.copy2(ROOT / "tools" / name, tools / name)
        game = self.root / "empty-game-directory"
        game.mkdir()
        compat = self.root / "compat"
        (compat / "pfx").mkdir(parents=True)
        environment = dict(os.environ, ISAC_ROUTE_AUDIT="1", ISAC_CAPTURE_BACKEND="0", ISAC_ACTION_MARKERS="0",
                           ISAC_SDK_PROTECT_TRACE="1")
        environment.pop("ISAC_HOST_PROC", None)
        for input_text, expected_status in (("\n", 0), ("", 1)):
            before = set((project / "evidence").glob("*-linux")) if (project / "evidence").exists() else set()
            result = subprocess.run(["bash", str(tools / "capture-startup-linux.sh"),
                                     "route-lifecycle-" + str(expected_status), str(game), str(compat)],
                                    env=environment, input=input_text, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, expected_status, result.stderr)
            created = set((project / "evidence").glob("*-linux")) - before
            self.assertEqual(len(created), 1)
            output = created.pop()
            value = json.loads((output / "route-audit-summary.json").read_text())
            self.assertGreaterEqual(value["samples"], 1)
            maps = [json.loads(line) for line in (output / "sdk-protection-maps.jsonl").read_text().splitlines()]
            self.assertEqual((maps[0]["event"], maps[-1]["event"]), ("ready", "finished"))
            if expected_status == 0:
                self.assertIn("Route audit requested: 1", (output / "summary.txt").read_text())


class LiveSocketTest(unittest.TestCase):
    def test_real_proc_socket_attribution_without_game_or_external_traffic(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as server:
            prefix = Path(directory) / "prefix"
            prefix.mkdir()
            server.bind(("127.0.0.1", 0))
            server.listen()
            port = server.getsockname()[1]
            script = (
                "import socket,sys; s=socket.create_connection(('127.0.0.1',int(sys.argv[1]))); "
                "print('ready',flush=True); sys.stdin.read(1); s.close()"
            )
            child = subprocess.Popen([sys.executable, "-c", script, str(port)],
                                     env=dict(os.environ, WINEPREFIX=str(prefix)),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                events = []
                audit = module.RouteAudit(prefix, events.append)
                audit.sample()
                selected = [value for value in events if value["pid"] == child.pid]
                self.assertEqual(len(selected), 1)
                self.assertEqual((selected[0]["destination"], selected[0]["port"], selected[0]["state"]),
                                 ("127.0.0.1", port, "established"))
                self.assertEqual({value["pid"] for value in events}, {child.pid})
                child.communicate(input="x", timeout=3)
                self.assertEqual(child.returncode, 0)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
