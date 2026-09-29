import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sdk_runner_debugger_test", ROOT / "tools/sdk_adapter_test.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@unittest.skipUnless(os.environ.get("ISAC_TEST_DEBUGGER") == "1", "Opt-in real Linux debugger test")
class DebuggerTest(unittest.TestCase):
    def test_name_assignment_lineage_without_edits_or_public_name_bytes(self):
        with tempfile.TemporaryDirectory(prefix="isac-name-debugger-") as directory:
            binary = Path(directory) / "sdk-debugger-fixture"
            result = subprocess.run(["cc", "-g", "-Wall", "-Wextra", "-Werror", "-no-pie", "-pthread",
                str(ROOT / "tests/sdk_adapter_debugger_fixture.c"),
                str(ROOT / "tests/sdk_adapter_debugger_fixture.S"),
                str(ROOT / "src/uplay_probe/sdk_http_entry.S"), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            environment = {**os.environ, "ISAC_FIXTURE_NAME": "1"}
            for key in ("ISAC_FIXTURE_TRACE", "ISAC_FIXTURE_HANDOFF", "ISAC_FIXTURE_CHANNEL"):
                environment.pop(key, None)
            result = subprocess.run(["gdb", "-nx", "-nh", "--batch", "-q", "-ex",
                "source " + str(ROOT / "tests/sdk_adapter_gdb_fixture.py"), "--args", str(binary)],
                capture_output=True, text=True, timeout=45, env=environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("profile=name-lineage hardware_slots=2", result.stdout)
            self.assertIn("initialized_registry_count=0", result.stdout)
            self.assertEqual(result.stdout.count("ISAC_BACKEND_TRACE_NAME_LINEAGE"), 2)
            self.assertIn("root_type=5 field_offset=856 before_empty=1 copy_equal=1 length=20", result.stdout)
            self.assertIn("gate_empty=0 copy_equal=1 final_length=20", result.stdout)
            self.assertIn("name_calls=6 name_results=6 producer_calls=1 producer_results=1", result.stdout)
            self.assertIn("ISAC_ADAPTER_DEBUGGER_FINISHED installs=2", result.stdout)
            self.assertNotIn("fixture-service-name", result.stdout)
            self.assertEqual(result.stdout.count("ISAC_TRANSPORT_CERTIFICATE pinned=1 applied=1"), 2)

    def test_channel_branches_with_four_slots_and_unchanged_results(self):
        with tempfile.TemporaryDirectory(prefix="isac-channel-debugger-") as directory:
            binary = Path(directory) / "sdk-debugger-fixture"
            result = subprocess.run(["cc", "-g", "-Wall", "-Wextra", "-Werror", "-no-pie", "-pthread",
                str(ROOT / "tests/sdk_adapter_debugger_fixture.c"),
                str(ROOT / "tests/sdk_adapter_debugger_fixture.S"),
                str(ROOT / "src/uplay_probe/sdk_http_entry.S"), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            environment = {**os.environ, "ISAC_FIXTURE_CHANNEL": "1"}
            for key in ("ISAC_FIXTURE_TRACE", "ISAC_FIXTURE_HANDOFF"):
                environment.pop(key, None)
            result = subprocess.run(["gdb", "-nx", "-nh", "--batch", "-q", "-ex",
                "source " + str(ROOT / "tests/sdk_adapter_gdb_fixture.py"), "--args", str(binary)],
                capture_output=True, text=True, timeout=45, env=environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("profile=channel hardware_slots=2", result.stdout)
            self.assertEqual(result.stdout.count("ISAC_BACKEND_TRACE_CHANNEL_ROUTE"), 3)
            self.assertIn("candidate_count=0", result.stdout)
            self.assertIn("transport_rejected=0 prepared_name_empty=1 registration_seen=0", result.stdout)
            self.assertIn("registration_seen=1 registration_result=1 channel_rejected=0", result.stdout)
            self.assertIn("result=1 output_present=1", result.stdout)
            self.assertIn("channel_calls=12 channel_results=12 changed_routes=3 pending_results=0", result.stdout)
            self.assertIn("channel fixture: selection, rejection and registration observed without edits", result.stdout)
            self.assertIn("ISAC_ADAPTER_DEBUGGER_FINISHED installs=2", result.stdout)
            self.assertNotIn("fixture-secret", result.stdout)
            self.assertEqual(result.stdout.count("ISAC_TRANSPORT_CERTIFICATE pinned=1 applied=1"), 2)

    def test_handoff_with_paired_result_and_existing_hooks(self):
        with tempfile.TemporaryDirectory(prefix="isac-handoff-debugger-") as directory:
            binary = Path(directory) / "sdk-debugger-fixture"
            result = subprocess.run(["cc", "-g", "-Wall", "-Wextra", "-Werror", "-no-pie", "-pthread",
                str(ROOT / "tests/sdk_adapter_debugger_fixture.c"),
                str(ROOT / "tests/sdk_adapter_debugger_fixture.S"),
                str(ROOT / "src/uplay_probe/sdk_http_entry.S"), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            environment = {**os.environ, "ISAC_FIXTURE_HANDOFF": "1"}
            environment.pop("ISAC_FIXTURE_TRACE", None)
            result = subprocess.run(["gdb", "-nx", "-nh", "--batch", "-q", "-ex",
                "source " + str(ROOT / "tests/sdk_adapter_gdb_fixture.py"), "--args", str(binary)],
                capture_output=True, text=True, timeout=45, env=environment)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("profile=handoff hardware_slots=2", result.stdout)
            self.assertIn("services_ticket_present=1 auth_ticket_present=1", result.stdout)
            self.assertIn("kind=0 channel_param=4097 paired=1 result=1 output_present=1", result.stdout)
            self.assertIn("channel_state=2 channel_error=1 channel_owner_present=1", result.stdout)
            self.assertIn("channel_present=1 manager_state=2", result.stdout)
            self.assertIn("ISAC_ADAPTER_DEBUGGER_FINISHED installs=2", result.stdout)
            self.assertIn("handoff fixture: frontend and paired channel result observed without edits", result.stdout)
            self.assertNotIn("fixture-secret", result.stdout)
            self.assertEqual(result.stdout.count("ISAC_TRANSPORT_CERTIFICATE pinned=1 applied=1"), 2)

    def test_new_threads_and_register_preservation(self):
        with tempfile.TemporaryDirectory(prefix="isac-debugger-") as directory:
            binary = Path(directory) / "sdk-debugger-fixture"
            result = subprocess.run(["cc", "-g", "-Wall", "-Wextra", "-Werror", "-no-pie", "-pthread",
                str(ROOT / "tests/sdk_adapter_debugger_fixture.c"),
                str(ROOT / "tests/sdk_adapter_debugger_fixture.S"),
                str(ROOT / "src/uplay_probe/sdk_http_entry.S"), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(["gdb", "-nx", "-nh", "--batch", "-q", "-ex",
                "source " + str(ROOT / "tests/sdk_adapter_gdb_fixture.py"), "--args", str(binary)],
                capture_output=True, text=True, timeout=45, env={**os.environ, "ISAC_FIXTURE_TRACE": "1"})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ISAC_ADAPTER_DEBUGGER_FINISHED installs=2", result.stdout)
            self.assertIn("two new threads installed before publication", result.stdout)
            self.assertEqual(result.stdout.count("ISAC_TRANSPORT_CERTIFICATE pinned=1 applied=1"), 2)
            self.assertIn("ISAC_TRANSPORT_CERTIFICATE pinned=0 applied=0", result.stdout)
            self.assertIn("certificate fixture: exact pin admitted, other certificate unchanged", result.stdout)
            self.assertIn("ISAC_BACKEND_TRACE_VERSION transport=1 expected=2056 received=2056 accepted=1", result.stdout)
            self.assertIn("consumer_result=1 waiting_before=1", result.stdout)
            self.assertIn("ISAC_BACKEND_TRACE_REGISTRATION", result.stdout)
            self.assertIn("code=15 name=version-mismatch", result.stdout)
            self.assertIn("code=8 name=decompression", result.stdout)
            self.assertIn("registration_calls=1", result.stdout)
            self.assertIn("backend trace fixture: version, settings, registration, error observed without edits", result.stdout)

    def test_game_environment_restored_through_real_debugger(self):
        with tempfile.TemporaryDirectory(prefix="isac-loader-") as directory:
            overrides = {"LD_LIBRARY_PATH": directory + ":/path with spaces/$literal",
                         "PYTHONHOME": "/nonexistent-steam-python",
                         "PYTHONPATH": "/path with spaces;$literal"}
            child = ("import os; expected = " + repr(overrides) + "; "
                     "assert all(os.environ.get(k) == v for k, v in expected.items()); "
                     "print('ISAC_INFERIOR_ENV_OK')")
            argv, host = runner.debugger_invocation(
                ["/usr/bin/python3", "-E", "-c", child], dict(os.environ, **overrides), Path("/unused"))
            argv[argv.index("-ex") + 1] = "set startup-with-shell off"
            index = argv.index("--args")
            argv[index:index] = ["-ex", "set debuginfod enabled off", "-ex", "run"]
            result = subprocess.run(argv, env=host, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ISAC_INFERIOR_ENV_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
