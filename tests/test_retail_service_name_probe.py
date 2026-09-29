import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import signal
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import retail_service_name_probe as probe


class LauncherTests(unittest.TestCase):
    def test_refuses_adapter_wrong_exe_and_existing_wine(self):
        with tempfile.TemporaryDirectory() as directory:
            game = compat = Path(directory)
            with patch.object(probe.runner, "digest", return_value="adapter"):
                with self.assertRaisesRegex(RuntimeError, "restored retail"):
                    probe.verify_retail(game, compat)
            with patch.object(probe.runner, "digest", side_effect=[probe.runner.RETAIL_DLL_HASH, "wrong"]):
                with self.assertRaisesRegex(RuntimeError, "Unsupported executable"):
                    probe.verify_retail(game, compat)
            with patch.object(probe.runner, "digest", side_effect=[probe.runner.RETAIL_DLL_HASH, probe.runner.GAME_HASH]), \
                    patch.object(probe.runner.netns, "directory_identity", return_value=(1, 2)), \
                    patch.object(probe.runner.netns, "launch_prefix", return_value=(1, 2)), \
                    patch.object(probe.runner.netns, "reject_external_wine", side_effect=RuntimeError("existing Wine")) as reject:
                with self.assertRaisesRegex(RuntimeError, "existing Wine"):
                    probe.verify_retail(game, compat)
                reject.assert_called_once_with(-1, (1, 2))

    def test_launcher_requires_opaque_steam_command_and_shell_syntax(self):
        result = subprocess.run(["bash", "-n", str(ROOT / "tools/steam-service-name-probe.sh")], capture_output=True)
        self.assertEqual(result.returncode, 0)
        with patch.object(sys, "argv", ["probe"]):
            self.assertEqual(probe.main(), 2)


@unittest.skipUnless(os.environ.get("ISAC_TEST_DEBUGGER") == "1", "Opt-in real Linux debugger test")
class DebuggerTests(unittest.TestCase):
    def test_real_four_slot_producer_gate_and_lingering_helper_shutdown(self):
        with tempfile.TemporaryDirectory(prefix="isac-retail-name-") as directory:
            capture = Path(directory)
            (capture / "producer-private").mkdir(mode=0o700)
            binary = capture / "retail-name-fixture"
            compiled = subprocess.run(["cc", "-g", "-Wall", "-Wextra", "-Werror", "-no-pie", "-pthread",
                str(ROOT / "tests/retail_service_name_fixture.c"), str(ROOT / "tests/retail_service_name_fixture.S"),
                "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            # Fixture relocations require symbols before run; the production
            # driver uses absolute PE addresses through the /usr/bin/env hop.
            argv = [str(probe.runner.GDB), "-nx", "-nh", "--batch", "-q", "-ex",
                "source " + str(ROOT / "tests/retail_service_name_gdb_fixture.py"), "--args", str(binary)]
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("LD_", "PYTHON"))}
            environment["ISAC_RETAIL_PROBE_CAPTURE"] = str(capture)
            environment["ISAC_FIXTURE_EXEC"] = "2"
            environment["ISAC_FIXTURE_HELPER_EXEC"] = "1"
            environment["ISAC_FIXTURE_FAIL_EXEC"] = "1"
            try:
                result = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=8)
            except subprocess.TimeoutExpired as error:
                self.fail("Synthetic debugger timeout: " + (error.stdout or b"").decode(errors="replace"))
            details = result.stdout + result.stderr
            if os.environ.get("ISAC_FIXTURE_LIFECYCLE") == "1":
                debug_dir = Path(tempfile.mkdtemp(prefix="retail-probe-lifecycle-", dir=ROOT / "private"))
                fd = os.open(debug_dir / "debugger.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write(details)
                details = "Lifecycle diagnostics: " + str(debug_dir / "debugger.log")
            self.assertEqual(result.returncode, 0, details)
            self.assertIn("ISAC_RETAIL_PROBE_READY slots=4 mode=read-only", result.stdout)
            self.assertIn("complete=1 parsed=1 accepted=1 name_length=20", result.stdout)
            self.assertIn("record_written=1 copy_equal=1 registry_before=0 registry_after=1", result.stdout)
            self.assertIn("gate_empty=0 copy_equal=1 final_length=20", result.stdout)
            self.assertIn("reason=game-exited", result.stdout)
            self.assertIn("retail fixture: normal fields and result preserved", result.stdout)
            self.assertNotIn("fixture-service-name", result.stdout)
            files = list((capture / "producer-private").glob("*.json"))
            self.assertEqual(len(files), 1)
            fields = json.loads(files[0].read_text())
            self.assertEqual(bytes.fromhex(fields["name_hex"]), b"fixture-service-name")
            self.assertEqual(fields["attributes"], [{"index": 0, "key_hex": b"type".hex(), "value_hex": b"auth".hex()}])
            self.assertTrue(fields["complete_fields"])

            # Exercise the actual production /usr/bin/env debugger invocation,
            # plus exec'ing helper interleaving before the game checkpoint.
            environment["ISAC_FIXTURE_BINARY"] = str(binary)
            environment["ISAC_FIXTURE_GAME_CHILD"] = "1"
            argv, environment = probe.runner.debugger_invocation([str(binary)], environment,
                ROOT / "tests/retail_service_name_gdb_fixture.py")
            try:
                result = subprocess.run(argv, env=environment, capture_output=True, text=True, timeout=8)
            except subprocess.TimeoutExpired as error:
                details = (error.stdout or b"").decode(errors="replace")
                self.fail("Forked-game synthetic timeout: " + details)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("complete=1 parsed=1 accepted=1 name_length=20", result.stdout)
            self.assertIn("gate_empty=0 copy_equal=1 final_length=20", result.stdout)

            # Steam's real launch chain includes a 32-bit reaper followed by
            # 64-bit native helpers. A static i386 stub avoids multilib libc.
            stub = capture / "retail-32bit-launcher"
            obj = capture / "launcher32.o"
            for command in (["as", "--32", str(ROOT / "tests/retail_service_name_32bit_fixture.S"), "-o", str(obj)],
                            ["ld", "-m", "elf_i386", "-o", str(stub), str(obj)]):
                built = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            mixed_environment = dict(environment, ISAC_FIXTURE_MUNMAP="1", ISAC_FIXTURE_THREADS="1",
                                     ISAC_FIXTURE_TRAPS="1")
            mixed_argv, mixed_environment = probe.runner.debugger_invocation([str(stub), str(binary)],
                mixed_environment, ROOT / "tests/retail_service_name_gdb_fixture.py")
            result = subprocess.run(mixed_argv, env=mixed_environment, capture_output=True, text=True, timeout=10)
            diagnosis = "\n".join(line for line in result.stdout.splitlines()
                if line.startswith(("FIXTURE_TRAP", "retail fixture:", "ISAC_RETAIL_PROBE")))
            self.assertEqual(result.returncode, 0, diagnosis + "\n" + result.stderr)
            self.assertIn("complete=1 parsed=1 accepted=1 name_length=20", result.stdout)
            self.assertIn("gate_empty=0 copy_equal=1 final_length=20", result.stdout)
            self.assertNotIn("in munmap", result.stdout)
            self.assertIn("architecture=i386 exec_numbers=11,358", result.stdout)
            self.assertIn("architecture=i386:x86-64 exec_numbers=59,322", result.stdout)
            self.assertIn("retail fixture: breakpoint and trace signals preserved", result.stdout)
            self.assertIn("retail fixture: i386 breakpoint and trace signals preserved", result.stdout)
            self.assertIn("trace_count=8 breakpoint_count=1", result.stdout)
            self.assertEqual(result.stdout.count("ISAC_RETAIL_PROBE_TRAP_PASSTHROUGH"), 2)
            self.assertLess(result.stdout.count("Hardware assisted breakpoint"), 50,
                            "Native munmap must not churn game bootstrap guards")

            # Steam Stop is forwarded as debugger interruption. Cover shutdown
            # while the synthetic game and its own helper are both still alive.
            (files[0]).unlink()
            environment["ISAC_FIXTURE_HANG"] = "1"
            fd = os.open(capture / "stop-debugger.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            log = os.fdopen(fd, "w")
            child = subprocess.Popen(argv, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not list((capture / "producer-private").glob("*.json")) and child.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("fixture did not reach producer before interruption")
                    time.sleep(0.02)
                child.send_signal(signal.SIGINT)
                child.wait(timeout=10)
                output = (capture / "stop-debugger.log").read_text()
                self.assertEqual(child.returncode, 1, output)
                self.assertIn("ISAC_RETAIL_PROBE_ERROR reason=debugger-interrupted-or-failed", output)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                log.close()


if __name__ == "__main__":
    unittest.main()
