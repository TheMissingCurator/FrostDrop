import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("steam_env_test", ROOT / "tools/steam_launch_environment.py")
env_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(env_tools)


class LauncherEnvironmentTest(unittest.TestCase):
    def test_exact_roundtrip_without_helper_loader_or_python_overrides(self):
        original = {"PATH": "/usr/bin", "SteamAppId": "365590", "ISAC_HOST_PROC": "/trusted/proc",
                    "LD_PRELOAD": "", "LD_LIBRARY_PATH": "/path with spaces:$literal;value\nnext",
                    "LD_AUDIT": "/audit.so", "PYTHONHOME": "/bad-home",
                    "PYTHONPATH": "quotes ' \" $() : = and\nnewlines"}
        saved = original.copy()
        helper = env_tools.helper_environment(original)
        self.assertEqual(original, saved)
        self.assertFalse(any(env_tools.game_only(key) for key in helper))
        self.assertEqual(env_tools.helper_environment(helper), helper)
        self.assertEqual(env_tools.game_environment(helper), original)
        self.assertEqual(helper["ISAC_HOST_PROC"], "/trusted/proc")

    def test_carrier_cannot_override_unrelated_configuration(self):
        for key in ("PATH", "ISAC_SDK_ADAPTER", "HOME", "LD_PRELOAD;bad"):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                env_tools.game_environment({env_tools.PREFIX + key: "value"})
        with self.assertRaisesRegex(RuntimeError, "Conflicting"):
            env_tools.helper_environment({"LD_PRELOAD": "one", env_tools.PREFIX + "LD_PRELOAD": "two"})

    def compile_fixture(self, root):
        source = str(ROOT / "tests/sdk_helper_preload_fixture.c")
        for flags, name in ((["-shared", "-fPIC", "-DISAC_SHARED_PRELOAD"], "tripwire.so"),
                            ([], "game-env-fixture")):
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", *flags, source,
                            "-o", str(root / name)], check=True, capture_output=True, text=True)

    def dirty_environment(self, root):
        environment = {k: v for k, v in os.environ.items()
                       if not env_tools.game_only(k) and not k.startswith("ISAC_")}
        environment.update(LD_PRELOAD=str(root / "tripwire.so"),
                           LD_LIBRARY_PATH=str(root) + ":/path with spaces/$literal",
                           PYTHONHOME="/isac-fixture-invalid-python-home",
                           PYTHONPATH="/path with spaces;$literal")
        return environment

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_real_wrapper_sanitizes_before_python_interpreter_starts(self):
        with tempfile.TemporaryDirectory(prefix="isac-preload-test-") as directory:
            root = Path(directory); self.compile_fixture(root)
            environment = self.dirty_environment(root)
            environment.pop("STEAM_COMPAT_INSTALL_PATH", None)
            environment.pop("STEAM_COMPAT_DATA_PATH", None)
            control = subprocess.run(["/usr/bin/python3", "-c", "raise SystemExit(0)"],
                                     env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(control.returncode, 86)
            self.assertIn("ISAC_FIXTURE_UNSAFE_PYTHON_PRELOAD", control.stderr)
            environment.update(ISAC_GAME_ENV_LD_PRELOAD="untrusted inherited value",
                               ISAC_GAME_ENV_PATH="must not be carried", ISAC_WORLD_REPLAY="1")
            result = subprocess.run([str(ROOT / "tools/steam-isac-mode.sh"), "custom", "--", "/usr/bin/true"],
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("Steam must supply an absolute STEAM_COMPAT_INSTALL_PATH", result.stderr)
            self.assertNotIn("ISAC_FIXTURE_UNSAFE_PYTHON_PRELOAD", result.stderr)
            self.assertNotIn("Fatal Python error", result.stderr)

    @unittest.skipUnless(os.environ.get("ISAC_TEST_DEBUGGER") == "1" and
                         os.environ.get("ISAC_TEST_TRANSPORT") == "1", "Opt-in namespace/backend/debugger pipeline")
    def test_clean_helpers_through_real_namespace_backend_and_debugger(self):
        with tempfile.TemporaryDirectory(prefix="isac-helper-pipeline-") as directory:
            root = Path(directory); self.compile_fixture(root)
            # Same builtin-only shell preparation as the production wrapper.
            shell = ('source "$1/tools/steam-helper-env.sh"; '
                     'exec /usr/bin/python3 "$1/tests/sdk_helper_environment_fixture.py" outer "$2"')
            result = subprocess.run(["/usr/bin/bash", "-c", shell, "--", str(ROOT), directory],
                                    env=self.dirty_environment(root), capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ISAC_FIXTURE_CLEAN_BACKEND_OK", result.stdout)
            self.assertIn("ISAC_FIXTURE_HELPER_PIPELINE_OK", result.stdout)
            self.assertNotIn("ISAC_FIXTURE_UNSAFE_PYTHON_PRELOAD", result.stderr)


if __name__ == "__main__":
    unittest.main()
