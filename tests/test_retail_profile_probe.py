import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import retail_profile_probe as probe
spec = importlib.util.spec_from_file_location("inspect_profile", ROOT / "tools/inspect-retail-profile.py")
inspect_profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspect_profile)


class ProfileProbeTests(unittest.TestCase):
    def test_direct_exec_and_flag_isolation(self):
        with patch.object(sys, "argv", ["probe", "--", "/steam wrapper", "a b"]), \
             patch.dict(os.environ, {"STEAM_COMPAT_INSTALL_PATH": "/game", "ISAC_RETAIL_TYPE5": "1", "ISAC_SDK_ADAPTER": "1"}, clear=True), \
             patch.object(probe.forward, "verify") as verify, \
             patch.object(probe, "prepare_capture", return_value=Path("/private")), \
             patch.object(probe.os, "execvpe") as execute:
            probe.main()
            verify.assert_called_once_with(Path("/game"), probe=probe.PROBE)
            execute.assert_called_once()
            command, argv, env = execute.call_args.args
            self.assertEqual((command, argv), ("/steam wrapper", ["/steam wrapper", "a b"]))
            self.assertEqual({k for k in env if k.startswith("ISAC_")}, {"ISAC_RETAIL_PROFILE", "ISAC_RETAIL_CAPTURE_DIR"})
            self.assertEqual(env["ISAC_RETAIL_CAPTURE_DIR"], "Z:\\private\\profile-private")

    def test_private_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "evidence").mkdir()
            old = os.umask(0o077)
            try:
                with patch.object(probe.forward, "ROOT", root), patch.object(probe.forward, "digest", return_value="fixture"):
                    capture = probe.prepare_capture()
                self.assertEqual(capture.stat().st_mode & 0o777, 0o700)
                self.assertEqual((capture / "profile-private").stat().st_mode & 0o777, 0o700)
                self.assertEqual((capture / "metadata.json").stat().st_mode & 0o777, 0o600)
            finally:
                os.umask(old)

    def test_core_and_static_signatures(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / "core")
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "tests/retail_profile_core.c"), "-o", binary], check=True, capture_output=True)
            subprocess.run([binary], check=True, capture_output=True, timeout=5)
        snapshot = ROOT / "private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin"
        if snapshot.exists():
            code = snapshot.read_bytes()
            source = (ROOT / "src/uplay_probe/retail_type5_win.c").read_text()
            profile = source.split("static const Site sites[] = {", 1)[1].split("#else", 1)[0]
            for rva, signature in re.findall(r'SITE\((0x[0-9a-f]+),"([^"]+)"\)', profile):
                expected = bytes.fromhex(signature.replace('\\x', ''))
                offset = int(rva,16)-0x1000
                self.assertEqual(code[offset:offset+len(expected)], expected, rva)

    def test_summary_decodes_and_does_not_print_private_fields(self):
        import contextlib, io
        value = {"event":"create_reply", "encoding":"reconstructed-body-v1", "complete":True,
                 "data_hex":(b'\0\0'+b'SECRET-CHAR-ID!!!'[:16]).hex()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"profile.jsonl"
            path.write_text(json.dumps(value)+'\n')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                inspect_profile.summarize(path)
            self.assertNotIn("SECRET", output.getvalue())
            self.assertIn("status=0", output.getvalue())
            self.assertIn("No end record", output.getvalue())
        with self.assertRaises(ValueError):
            inspect_profile.decode("create_reply", b'\0\0')

    @unittest.skipUnless(os.environ.get("ISAC_TEST_PROFILE_PROTON") == "1", "Opt-in actual Proton fixture")
    def test_actual_proton(self):
        from test_retail_type5_proton import COMMON, STEAM_CLIENT
        with tempfile.TemporaryDirectory(prefix="isac-profile-proton-") as directory:
            work = Path(directory); (work / "compat").mkdir()
            binary = work / "profile.exe"; events = work / "profile.jsonl"
            subprocess.run(["x86_64-w64-mingw32-gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(ROOT / "tests/retail_profile_wine.c"), str(ROOT / "tests/retail_profile_fixture.S"),
                            "-o", str(binary)], check=True, capture_output=True)
            env = {k:v for k,v in os.environ.items() if not k.startswith(("LD_","PYTHON","WINE","ISAC_","STEAM_COMPAT_"))}
            env.update(STEAM_COMPAT_DATA_PATH=str(work/"compat"),STEAM_COMPAT_CLIENT_INSTALL_PATH=STEAM_CLIENT,
                       SteamAppId='0',SteamGameId='0',PROTON_LOG='1',PROTON_LOG_DIR=str(work),WINEDEBUG='-all,+seh',WINEDLLOVERRIDES='mscoree,mshtml=')
            result = subprocess.run([str(COMMON/'SteamLinuxRuntime_4/_v2-entry-point'),'--verb=waitforexitandrun','--',
                         str(COMMON/'Proton - Experimental/proton'),'waitforexitandrun',str(binary),'Z:'+str(events).replace('/','\\')],
                         env=env,capture_output=True,text=True,timeout=60,umask=0o077)
            self.assertEqual(result.returncode,0,result.stdout[-2000:]+result.stderr[-2000:])
            rows=[json.loads(line) for line in events.read_text().splitlines()]
            captured=[r for r in rows if 'data_hex' in r]
            self.assertEqual(len(captured),5)
            for record in captured:
                self.assertTrue(record['complete'])
                fields=inspect_profile.decode(record['event'],bytes.fromhex(record['data_hex']))
                self.assertEqual(fields['request_id'],129)
            self.assertEqual(rows[-1]['event'],'end')
            self.assertEqual(rows[-1]['resume_failures'],0)
            self.assertGreaterEqual(rows[-1]['debug_context_refreshes'],2)
            self.assertNotIn('Unhandled exception',(work/'steam-0.log').read_text(errors='replace'))


if __name__ == '__main__':
    unittest.main()
