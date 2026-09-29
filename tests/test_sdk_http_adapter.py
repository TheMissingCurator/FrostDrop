"""Native portable-core test; no Wine, game files or network required."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SDKHTTPAdapterTest(unittest.TestCase):
    def test_adapter_core(self):
        with tempfile.TemporaryDirectory(prefix="isac-http-adapter-") as directory:
            executable = Path(directory) / "adapter-test"
            command = shlex.split(os.environ.get("CC", "cc"))
            command += ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-g"]
            if os.environ.get("ISAC_ADAPTER_SANITIZE") == "1":
                command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            command += [str(ROOT / "tests/sdk_http_adapter_smoke.c"),
                        str(ROOT / "src/uplay_probe/sdk_http_adapter.c"),
                        "-o", str(executable)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("lifecycle passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
