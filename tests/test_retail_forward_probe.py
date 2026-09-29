import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import retail_forward_probe as probe


class RetailForwardTests(unittest.TestCase):
    def test_environment_keeps_steam_and_removes_all_offline_flags(self):
        actual = probe.environment_for_game({"ISAC_GAME_ENV_LD_PRELOAD": "steam-overlay.so",
            "ISAC_LOCAL_BACKEND_BRIDGE": "1", "ISAC_SDK_ADAPTER": "1",
            "ISAC_STACK_PROBE": "1", "SteamAppId": "365590", "PATH": "/usr/bin"})
        self.assertEqual(actual, {"LD_PRELOAD": "steam-overlay.so", "SteamAppId": "365590", "PATH": "/usr/bin"})

    def test_verifies_game_original_and_installed_probe(self):
        game = Path("/fictional-game")
        for values, passes in (([probe.GAME_HASH, probe.RETAIL_HASH, "probe", "probe"], True),
                               (["wrong"], False), ([probe.GAME_HASH, "offline"], False),
                               ([probe.GAME_HASH, probe.RETAIL_HASH, "adapter", "probe"], False)):
            with patch.object(probe, "digest", side_effect=values):
                if passes:
                    probe.verify(game)
                else:
                    with self.assertRaises(RuntimeError):
                        probe.verify(game)

    def test_execs_opaque_command_without_monitor_or_debugger(self):
        command = ["/steam wrapper", "argument with spaces", "--unchanged"]
        with patch.object(sys, "argv", ["probe", "--", *command]), \
                patch.dict(os.environ, {"STEAM_COMPAT_INSTALL_PATH": "/game", "ISAC_SDK_ADAPTER": "1"}, clear=True), \
                patch.object(probe, "prepare_capture", return_value=Path("/private-capture")), \
                patch.object(probe, "verify") as verify, patch.object(probe.os, "execvpe") as execute:
            probe.main()
            verify.assert_called_once_with(Path("/game"))
            execute.assert_called_once_with(command[0], command, {"STEAM_COMPAT_INSTALL_PATH": "/game",
                "ISAC_RETAIL_TYPE5": "1", "ISAC_RETAIL_CAPTURE_DIR": "Z:\\private-capture\\producer-private"})

    def test_native_core_bounds_and_pairing(self):
        with tempfile.TemporaryDirectory(prefix="isac-type5-core-") as directory:
            binary = Path(directory) / "core"
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "tests/retail_type5_core.c"),
                            "-o", str(binary)], check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=5)

    def test_capture_is_private_and_contains_no_account_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evidence").mkdir()
            previous = os.umask(0o077)
            try:
                with patch.object(probe, "ROOT", root), patch.object(probe, "digest", return_value="fixture-hash"):
                    capture = probe.prepare_capture()
                self.assertEqual(capture.stat().st_mode & 0o777, 0o700)
                self.assertEqual((capture / "producer-private").stat().st_mode & 0o777, 0o700)
                self.assertEqual((capture / "metadata.json").stat().st_mode & 0o777, 0o600)
                self.assertFalse(json.loads((capture / "metadata.json").read_text())["debugger"])
            finally:
                os.umask(previous)

    @unittest.skipUnless(os.environ.get("ISAC_TEST_RETAIL_WINE") == "1", "Opt-in temporary-prefix Wine smoke test")
    def test_retail_dll_forwards_even_with_legacy_offline_flags(self):
        with tempfile.TemporaryDirectory(prefix="isac-retail-forward-") as directory:
            work = Path(directory)
            original = work / "uplay_r1_loader64_isac_original.dll"
            binary = work / "forward-smoke.exe"
            for command in (["x86_64-w64-mingw32-gcc", "-shared", "-O2", "-Wall", "-Wextra", "-Werror",
                             str(ROOT / "tests/uplay_probe_original_smoke.c"),
                             str(ROOT / "tests/uplay_probe_original_smoke.def"), "-o", str(original)],
                            ["x86_64-w64-mingw32-gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                             str(ROOT / "tests/uplay_abi_probe_smoke.c"), "-o", str(binary)]):
                subprocess.run(command, check=True, capture_output=True, text=True)
            dll = work / "uplay_r1_loader64.dll"
            shutil.copyfile(probe.PROBE, dll)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("LD_", "PYTHON", "ISAC_", "WINE"))}
            environment.update(WINEPREFIX=str(work / "prefix"), WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=")
            try:
                subprocess.run(["wineboot", "-u"], env=environment, check=True, capture_output=True, timeout=45)
                # The retail binary must be incapable of activating old features,
                # even if somebody bypasses the wrapper's environment cleanup.
                environment.update({key: "1" for key in ("ISAC_UPLAY_ABI_PROBE", "ISAC_STACK_PROBE",
                    "ISAC_PLAINTEXT_PROBE", "ISAC_LOCAL_BACKEND_BRIDGE", "ISAC_LOCAL_BACKEND_INJECT",
                    "ISAC_TCTD_PC_LOOPBACK", "ISAC_SDK_ADAPTER")})
                result = subprocess.run(["wine", str(binary), "Z:" + str(dll).replace("/", "\\")],
                                        env=environment, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("smoke test passed", result.stdout)
                log = (work / "project-isac-uplay-probe.log").read_text()
                self.assertIn("RETAIL_FORWARD_ONLY service-name-observer=opt-in-type5", log)
                self.assertIn("UPLAY_USER_IsOwned", log)
                self.assertEqual([p.name for p in work.glob("project-isac-*.log")], ["project-isac-uplay-probe.log"])
                observer = work / "type5-smoke.exe"
                subprocess.run(["x86_64-w64-mingw32-gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(ROOT / "tests/retail_type5_wine.c"), str(ROOT / "tests/retail_service_name_fixture.S"),
                    "-o", str(observer)], check=True, capture_output=True, text=True)
                events = work / "type5.jsonl"
                result = subprocess.run(["wine", str(observer), "Z:" + str(events).replace("/", "\\")],
                    env=environment, capture_output=True, text=True, timeout=20, umask=0o077)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(events.stat().st_mode & 0o777, 0o600)
                records = [json.loads(line) for line in events.read_text().splitlines()]
                fields = [r for r in records if r["event"] == "type5"]
                self.assertEqual(len(fields), 2)
                for field in fields:
                    self.assertTrue(field["complete_fields"])
                    self.assertEqual(field["copy_equal"], 1)
                    self.assertEqual(bytes.fromhex(field["name_hex"]), b"fixture-service-name")
                    self.assertEqual(field["attributes"], [{"index": 0, "key_hex": b"type".hex(), "value_hex": b"auth".hex()}])
                self.assertEqual(len([r for r in records if r["event"] == "gate" and r["gate_empty"] == 0]), 2)
                self.assertEqual(records[-1]["event"], "end")
                self.assertEqual(records[-1]["pending"], 0)
            finally:
                subprocess.run(["wineserver", "-k"], env=environment, capture_output=True, timeout=10)
                subprocess.run(["wineserver", "-w"], env=environment, capture_output=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
