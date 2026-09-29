"""Synthetic Windows observer under the user's actual Steam Runtime/Proton."""
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMON = Path(os.environ.get('ISAC_TEST_STEAM_COMMON', '/nonexistent/steamapps/common'))
STEAM_CLIENT = os.environ.get('ISAC_TEST_STEAM_CLIENT', '/nonexistent/Steam')


@unittest.skipUnless(os.environ.get('ISAC_TEST_RETAIL_PROTON') == '1', 'Opt-in actual Proton fixture')
class ProtonTests(unittest.TestCase):
    def test_actual_proton_observer(self):
        with tempfile.TemporaryDirectory(prefix='isac-type5-proton-') as directory:
            work = Path(directory)
            binary = work / 'type5-smoke.exe'
            subprocess.run(['x86_64-w64-mingw32-gcc', '-O2', '-Wall', '-Wextra', '-Werror',
                str(ROOT / 'tests/retail_type5_wine.c'), str(ROOT / 'tests/retail_service_name_fixture.S'),
                '-o', str(binary)], check=True, capture_output=True)
            env = {k: v for k, v in os.environ.items() if not k.startswith(('LD_', 'PYTHON', 'WINE', 'ISAC_', 'STEAM_COMPAT_'))}
            (work / 'compat').mkdir()
            env.update(STEAM_COMPAT_DATA_PATH=str(work / 'compat'),
                       STEAM_COMPAT_CLIENT_INSTALL_PATH=STEAM_CLIENT,
                       SteamAppId='0', SteamGameId='0', PROTON_LOG='1', PROTON_LOG_DIR=str(work),
                       WINEDEBUG='-all,+seh', WINEDLLOVERRIDES='mscoree,mshtml=')
            events = work / 'type5.jsonl'
            command = [str(COMMON / 'SteamLinuxRuntime_4/_v2-entry-point'), '--verb=waitforexitandrun', '--',
                       str(COMMON / 'Proton - Experimental/proton'), 'waitforexitandrun', str(binary),
                       'Z:' + str(events).replace('/', '\\')]
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90, umask=0o077)
            # Synthetic-only output: no account or real game is involved.
            details = result.stdout[-3000:] + result.stderr[-3000:]
            if result.returncode:
                saved = Path(tempfile.mkdtemp(prefix='type5-proton-failure-', dir=ROOT / 'private'))
                for path in (binary, events, work / 'steam-0.log'):
                    if path.is_file():
                        shutil.copyfile(path, saved / path.name)
                        (saved / path.name).chmod(0o600)
                log = work / 'steam-0.log'
                if log.exists():
                    details += '\n' + log.read_text(errors='replace')[-1500:]
                details += '\nSynthetic diagnostics: ' + str(saved)
            self.assertEqual(result.returncode, 0, details)
            self.assertNotIn('Unhandled exception', (work / 'steam-0.log').read_text(errors='replace'))
            records = [json.loads(line) for line in events.read_text().splitlines()]
            fields = [r for r in records if r['event'] == 'type5']
            self.assertEqual(len(fields), 2, records)
            self.assertTrue(all(r['complete_fields'] and r['copy_equal'] == 1 for r in fields))
            self.assertEqual(records[-1]['event'], 'end')
            self.assertEqual(records[-1]['resume_failures'], 0)
            self.assertGreaterEqual(records[-1]['debug_context_refreshes'], 2)


if __name__ == '__main__':
    unittest.main()
