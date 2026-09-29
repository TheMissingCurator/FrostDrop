"""Native service glue: mock ABI/transport gates, not a retail execution test."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeServiceTest(unittest.TestCase):
    def test_private_slot_writer(self):
        with tempfile.TemporaryDirectory(prefix="isac-slot-writer-") as directory:
            executable = Path(directory) / "slot-test"
            command = shlex.split(os.environ.get("CC", "cc"))
            command += ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-g", "-D_WIN32",
                        "-I" + str(ROOT / "tests/sdk_win32_stub")]
            if os.environ.get("ISAC_ADAPTER_SANITIZE") == "1":
                command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            command += [str(ROOT / "tests/sdk_http_install_smoke.c"),
                        str(ROOT / "src/uplay_probe/sdk_http_install_win32.c"), "-o", str(executable)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("compare/exchange tests passed", result.stdout)

    def test_native_service(self):
        with tempfile.TemporaryDirectory(prefix="isac-native-service-") as directory:
            executable = Path(directory) / "service-test"
            command = shlex.split(os.environ.get("CC", "cc"))
            command += ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-g"]
            if os.environ.get("ISAC_ADAPTER_SANITIZE") == "1":
                command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            command += [str(ROOT / "tests/sdk_http_native_service_smoke.c"),
                        str(ROOT / "src/uplay_probe/sdk_http_native_service.c"),
                        str(ROOT / "src/uplay_probe/sdk_http_adapter.c"), "-o", str(executable)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("epoch tests passed", result.stdout)
            # Intentional process termination leaves the live SDK epoch intact;
            # leak cleanup cannot be required after this fatal boundary.
            env = os.environ.copy()
            env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") + ":detect_leaks=0"
            for failure in ("result", "return", "drain"):
                stopped = subprocess.run([str(executable), failure], capture_output=True,
                                         text=True, timeout=30, env=env)
                self.assertEqual(stopped.returncode, 77, stopped.stdout + stopped.stderr)
                self.assertIn("without external fallback", stopped.stdout)


if __name__ == "__main__":
    unittest.main()
