import os
from pathlib import Path
import subprocess
import tempfile
import unittest

WRAPPER = Path(__file__).resolve().parents[1] / "tools/steam-login-handoff-wrapper.sh"
RUNNER = WRAPPER.parent / "run-offline-integration.sh"


class HandoffWrapperTest(unittest.TestCase):
    def environment(self, *args):
        env = dict(os.environ, ISAC_STALE="1", ISAC_LOGIN_HANDOFF_SWEEP="1", PROTON_LOG="0")
        result = subprocess.run([str(WRAPPER), *args, "/usr/bin/env"], env=env,
                                check=True, text=True, capture_output=True)
        return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)

    def test_modes_only_change_sweeping(self):
        off, on = self.environment("--sweep", "off"), self.environment("--sweep", "on")
        for env, value in ((off, "0"), (on, "1")):
            self.assertEqual(env["ISAC_LOGIN_HANDOFF_SWEEP"], value)
            self.assertNotIn("ISAC_STALE", env)
            self.assertEqual(env["PROTON_LOG"], "1")
            self.assertEqual(env["WINEDEBUG"], "+timestamp,+pid,+tid,+seh")
            self.assertTrue(env["PROTON_LOG_DIR"].endswith("/evidence/proton-logs"))
        keys = {k for k in off if k.startswith(("ISAC_", "PROTON_", "WINEDEBUG"))}
        self.assertEqual({k: off[k] for k in keys if k != "ISAC_LOGIN_HANDOFF_SWEEP"},
                         {k: on[k] for k in keys if k != "ISAC_LOGIN_HANDOFF_SWEEP"})

    def test_default_off_and_arguments(self):
        self.assertEqual(self.environment()["ISAC_LOGIN_HANDOFF_SWEEP"], "0")
        result = subprocess.run([str(WRAPPER), "--sweep", "off", "/usr/bin/printf", "%s", "a b"],
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout, "a b")

    def test_invalid_modes(self):
        for args in (("--sweep", "bad"), ("--sweep",), ("--sweep", "on"), ("--sdk-local",),
                     ("--sdk-local", "--sweep", "on"), ("--sdk-local", "--sweep", "bad"),
                     ("--sdk-protect-trace", "/usr/bin/env"), ("--sdk-local", "--sdk-protect-trace")):
            result = subprocess.run([str(WRAPPER), *args], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_protection_trace_options_and_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            tracer = Path(directory) / "strace"
            tracer.write_text('#!/bin/sh\nprintf "TRACE_ARG=%s\\n" "$@" >&2\n'
                              'while [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
            tracer.chmod(0o700)
            result = subprocess.run([str(WRAPPER), "--sdk-local", "--sdk-protect-trace", "/usr/bin/env"],
                                    env=dict(os.environ, PATH=directory + ":" + os.environ["PATH"]),
                                    text=True, capture_output=True, check=True)
            values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            self.assertEqual(values["ISAC_SDK_PROTECT_TRACE"], "1")
            self.assertEqual(values["WINEDEBUG"], "+timestamp,+pid,+tid,+seh,+virtual")
            self.assertIn("TRACE_ARG=trace=mprotect,pkey_mprotect", result.stderr)
            self.assertIn("TRACE_ARG=status=failed", result.stderr)
            self.assertIn("TRACE_ARG=signal=none", result.stderr)
            self.assertIn("TRACE_ARG=-D", result.stderr)
            self.assertNotIn("trace=all", result.stderr)

    def test_protection_trace_missing_dependency_does_not_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("bash", "dirname", "mkdir"):
                (Path(directory) / name).symlink_to("/usr/bin/" + name)
            result = subprocess.run([str(WRAPPER), "--sdk-local", "--sdk-protect-trace",
                                     "/usr/bin/printf", "NOT_LAUNCHED"],
                                    env=dict(os.environ, PATH=directory), text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("requires strace", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_native_trace_uses_dispatcher_not_strace_or_hardware(self):
        environment = self.environment("--sdk-local", "--sdk-native-trace")
        self.assertEqual(environment["ISAC_SDK_NATIVE_TRACE"], "1")
        self.assertEqual(environment["ISAC_SDK_PROTECT_TRACE"], "1")
        self.assertEqual(environment["WINEDEBUG"], "+timestamp,+pid,+tid,+seh,+virtual,+syscall")
        self.assertNotIn("ISAC_SDK_NATIVE_TRACE", self.environment("--sdk-local", "--sdk-protect-trace"))
        for args in (("--sdk-native-trace", "/usr/bin/env"),
                     ("--sdk-local", "--sdk-protect-trace", "--sdk-native-trace", "/usr/bin/env"),
                     ("--sdk-local", "--sdk-native-trace", "--sdk-protect-trace", "/usr/bin/env")):
            result = subprocess.run([str(WRAPPER), *args], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_sdk_host_launch_without_network_helper(self):
        # A failing helper must never be called: sdk-local now deliberately
        # launches on the existing network without joining or checking one.
        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / "python3"
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >&2\nexit 42\n')
            stub.chmod(0o700)
            for marker in ("0", "1"):
                environment = dict(os.environ, PATH=directory + ":" + os.environ["PATH"],
                                   ISAC_NETNS_JOINED=marker, ISAC_NETNS_INNER="1", ISAC_HOST_PROC="/missing")
                result = subprocess.run([str(WRAPPER), "--sdk-local", "/usr/bin/env"],
                                        env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
                self.assertEqual(values["ISAC_SDK_LOCAL"], "1")
                self.assertEqual(values["ISAC_LOCAL_BACKEND_BRIDGE"], "1")
                self.assertEqual(values["ISAC_TCTD_PC_LOOPBACK"], "1")
                self.assertNotIn("ISAC_NETNS_JOINED", values)
                self.assertNotIn("ISAC_NETNS_INNER", values)
                self.assertNotIn("ISAC_HOST_PROC", values)

    def test_sdk_arguments_and_sweeping(self):
        for mode, value in (("off", "0"), ("on", "1")):
            environment = self.environment("--sdk-local", "--sweep", mode)
            self.assertEqual(environment["ISAC_SDK_LOCAL"], "1")
            self.assertEqual(environment["ISAC_LOGIN_HANDOFF_SWEEP"], value)
        result = subprocess.run([str(WRAPPER), "--sdk-local", "/usr/bin/printf", "%s", "a b"],
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout, "a b")

    def test_sdk_keeps_existing_network_namespace(self):
        expected = os.readlink("/proc/self/ns/net")
        result = subprocess.run([str(WRAPPER), "--sdk-local", "/usr/bin/readlink", "/proc/self/ns/net"],
                                check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), expected)

    def test_sdk_runner_reaches_file_checks_without_network_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # No fake game executable: do not start backend services or a game.
            for name, body in (("python3", 'printf "HELPER_CALLED\\n" >&2; exit 42'),
                               ("ps", "exit 0")):
                stub = root / name
                stub.write_text("#!/bin/sh\n" + body + "\n")
                stub.chmod(0o700)
            environment = dict(os.environ, PATH=directory + ":" + os.environ["PATH"])
            environment.pop("ISAC_NETNS_INNER", None)
            result = subprocess.run([str(RUNNER), directory, directory, "sdk-local"],
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("Required file is missing:", result.stderr)
            self.assertNotIn("HELPER_CALLED", result.stderr)

    def test_runner_has_no_automatic_network_gate_or_false_isolation_claim(self):
        source = RUNNER.read_text()
        for removed in ("isac-netns.py", "require-offline-network.py",
                        "private loopback-only network namespace", "Steam IPC exception:",
                        "external network must be disabled"):
            self.assertNotIn(removed, source)
        self.assertIn("Network isolation: disabled", source)
        self.assertIn("External game connections: not blocked", source)


if __name__ == "__main__":
    unittest.main()
