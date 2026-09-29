import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


watch = load("protect_watch", "watch-sdk-protection.py")
analysis = load("protect_analysis", "analyze-sdk-protection.py")


def marker_line(phase="begin", timestamp=123000):
    return (f"SDK_PROTECT_CALL tick_ms=1 process=312 thread=316 detail=phase={phase},unix_ms={timestamp},"
            "target=0x1100,length=47,requested=0x8,win32_error=5,virtual_protect=0x2000,nt_protect=0x3000\n")


def binding_line(edge="shim-to-kernel32", phase="begin", destination="0x2000", status="ok"):
    return (f"SDK_API_BINDING tick_ms=1 process=312 thread=316 detail=phase={phase},unix_ms=123000,"
            f"edge={edge},status={status},slot=0x1000,destination={destination},expected=0x2000,"
            "matches=1,owner=kernel32,allocation=0x1800,rva=0x800,protect=0x20,memory_type=0x1000000,"
            "entry_slot=0x1000,entry_slot_matches=1\n")


class ProtectionTest(unittest.TestCase):
    def test_binding_parse_redacts_unknown_fields_and_derives_comparisons(self):
        value = analysis.binding(binding_line(destination="0x3000").replace("matches=1", "matches=0")
                                 .replace("\n", ",ACCOUNT_TOKEN=SECRET\n"))
        self.assertFalse(value["matches"])
        self.assertNotIn("SECRET", json.dumps(value))
        for line in (binding_line(edge="not-known"), binding_line(status="SECRET"),
                     binding_line(destination="-1"), binding_line().replace("slot=0x1000", "slot=broken")):
            self.assertIsNone(analysis.binding(line))

    def test_binding_report_complete_mismatch_change_and_missing_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "project-isac-stack-probe.log"
            path.write_text("".join(binding_line(edge=edge) for edge in sorted(analysis.EDGES)))
            report = "\n".join(analysis.binding_report(root))
            self.assertIn("match all export references", report)
            self.assertIn("does NOT prove entry code", report)
            self.assertNotIn("Incomplete", report)
            path.write_text("".join(binding_line(edge=edge, status="entry-not-rip-indirect" if edge == "kernel32-entry" else "ok")
                                    for edge in sorted(analysis.EDGES)))
            report = "\n".join(analysis.binding_report(root))
            self.assertIn("match all export references", report)
            self.assertIn("not evidence of a hook", report)
            with path.open("a") as target:
                target.write(binding_line(phase="write-failed", destination="0x3000"))
            report = "\n".join(analysis.binding_report(root))
            self.assertIn("Destination differs", report)
            self.assertIn("Binding changed", report)
            path.write_text(binding_line(status="unreadable-slot"))
            report = "\n".join(analysis.binding_report(root))
            self.assertIn("Incomplete pre-call binding coverage", report)
            self.assertNotIn("match all export references", report)

    @unittest.skipUnless(shutil.which("strace"), "strace not installed")
    def test_real_strace_filter_reports_refusal_without_file_contents(self):
        # Local-only fixture, not the game: a shared read-only file mapping must
        # reject adding write permission. Exercise the actual launch wrapper.
        fixture = r'''
import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
fd = os.open(sys.argv[1], os.O_RDONLY)
address = libc.mmap(None, 4096, 1, 1, fd, 0)
assert address not in (None, ctypes.c_void_p(-1).value)
assert libc.mprotect(address, 4096, 3) == -1
assert ctypes.get_errno() == errno.EACCES
assert libc.munmap(address, 4096) == 0
os.close(fd)
print("fixture refusal confirmed")
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            wrapper = root / "tools/steam-login-handoff-wrapper.sh"
            shutil.copy2(ROOT / "tools/steam-login-handoff-wrapper.sh", wrapper)
            private_file = root / "private-fixture"
            private_file.write_bytes(b"PRIVATE_FIXTURE_BYTES_NOT_FOR_LOGS".ljust(4096, b"\0"))
            result = subprocess.run(["bash", str(wrapper), "--sdk-local", "--sdk-protect-trace",
                                     sys.executable, "-c", fixture, str(private_file)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "fixture refusal confirmed")
            paths = list((root / "evidence/proton-logs").glob("sdk-protection-linux-*.log"))
            self.assertEqual(len(paths), 1)
            data = paths[0].read_text()
            # -D detaches the tracer: the tracee may have exited before its last
            # trace record is flushed. Wait for the bounded fixture output.
            deadline = time.monotonic() + 3
            while "EACCES" not in data and time.monotonic() < deadline:
                time.sleep(0.02)
                data = paths[0].read_text()
            self.assertNotIn("PRIVATE_FIXTURE_BYTES_NOT_FOR_LOGS", data)
            self.assertNotIn("private-fixture", data)
            calls = [analysis.syscall(line) for line in data.splitlines()]
            self.assertTrue(any(call and call["errno"] == "EACCES" for call in calls), data + result.stderr)

    def test_marker_only_parses_numeric_diagnostic_fields(self):
        value = watch.marker(marker_line())
        self.assertEqual((value["target"], value["length"], value["unix_ms"]), (0x1100, 47, 123000))
        self.assertIsNone(watch.marker("SECRET_TOKEN=private\n"))
        self.assertIsNone(watch.marker(marker_line("unsupported")))

    def test_mapping_metadata_redacts_paths_and_does_not_span_regions(self):
        line = "00001000-00002000 r--s 00000000 00:01 123 /private/ACCOUNT_TOKEN (deleted)\n"
        value = watch.selected_mapping(io.StringIO(line), 0x1100, 47)
        self.assertEqual((value["permissions"], value["backing_class"], value["deleted"]), ("r--s", "file", True))
        self.assertNotIn("ACCOUNT_TOKEN", json.dumps(value))
        self.assertIsNone(watch.selected_mapping([line], 0x1fff, 47))

    def test_parse_strace_and_correlate_pid_address_and_time(self):
        call = analysis.syscall("13 123.025000 mprotect(0x1000, 4096, PROT_READ|PROT_WRITE) = -1 EACCES (Permission denied)")
        self.assertEqual((call["tid"], call["errno"]), (13, "EACCES"))
        records = [{"event": "marker", **watch.marker(marker_line())},
                   {"event": "marker", **watch.marker(marker_line("write-failed", 123050))},
                   {"event": "mapping", "target": 0x1100, "thread_ids": [12, 13]}]
        self.assertEqual(analysis.correlate(records, [call]), [call])
        for changes in ({"tid": 99}, {"address": 0x2000}, {"time": 100.0}, {"length": 8}):
            self.assertEqual(analysis.correlate(records, [{**call, **changes}]), [])
        self.assertIsNotNone(analysis.syscall("[pid 13] 123.025 pkey_mprotect(0x1000, 4096, PROT_READ|PROT_WRITE, -1) = -1 EPERM"))
        self.assertIsNone(analysis.syscall("13 123.025 read(3, \"PRIVATE\", 7) = 7"))

    def test_missing_evidence_not_called_api_interception(self):
        with tempfile.TemporaryDirectory() as directory:
            report = analysis.analyze(Path(directory))
        self.assertIn("NOT proof of API interception", report)
        self.assertIn("Missing Linux syscall trace", report)

    def test_mapping_watcher_cli_prefix_identity_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "prefix"
            prefix.mkdir()
            proc = root / "proc"
            game = proc / "12"
            game.mkdir(parents=True)
            (game / "root").symlink_to("/")
            (game / "comm").write_text("thedivision.exe\n")
            (game / "stat").write_text("12 (thedivision.exe) " + " ".join(["S", "1"] + ["0"] * 17 + ["100"]))
            (game / "environ").write_bytes(b"WINEPREFIX=" + os.fsencode(prefix) + b"\0TOKEN=SECRET\0")
            (game / "maps").write_text("00001000-00002000 r--s 00000000 00:01 123 /private/SECRET\n")
            (game / "smaps").write_text((game / "maps").read_text() + "VmFlags: rd mr sh ms\n")
            (game / "status").write_text("NoNewPrivs:\t1\nSeccomp:\t2\nTracerPid:\t100\n")
            (game / "task/12").mkdir(parents=True)
            log = root / "stack.log"
            old = marker_line().encode()
            log.write_bytes(old)
            output = root / "output.jsonl"
            child = subprocess.Popen([sys.executable, str(ROOT / "tools/watch-sdk-protection.py"),
                                      "--prefix", str(prefix), "--stack-log", str(log), "--offset", str(len(old)),
                                      "--output", str(output)], env=dict(os.environ, ISAC_HOST_PROC=str(proc)),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                log.write_bytes(old + marker_line("write-failed", 123050).encode())
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    if output.exists() and '"event": "mapping"' in output.read_text():
                        break
                    time.sleep(0.02)
                child.send_signal(signal.SIGTERM)
                stdout, stderr = child.communicate(timeout=3)
                self.assertEqual((child.returncode, stdout, stderr), (0, "", ""))
                data = output.read_text()
                self.assertNotIn("SECRET", data)
                values = [json.loads(line) for line in data.splitlines()]
                maps = [value for value in values if value["event"] == "mapping"]
                self.assertEqual(len(maps), 1)
                self.assertEqual(maps[0]["vm_flags"], ["rd", "mr", "sh", "ms"])
                self.assertEqual(maps[0]["linux_pid"], 12)
                self.assertEqual(values[-1]["event"], "finished")
                self.assertEqual([value["phase"] for value in values if value["event"] == "marker"], ["write-failed"])
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
