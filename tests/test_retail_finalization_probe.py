import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import retail_finalization_probe as probe

spec = importlib.util.spec_from_file_location('inspect_profile', ROOT / 'tools/inspect-retail-profile.py')
inspect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspect)


class FinalizationProbeTests(unittest.TestCase):
    def test_steam_wrapper_is_executable(self):
        wrapper = ROOT / 'tools/steam-finalization-probe.sh'
        self.assertTrue(os.access(wrapper, os.X_OK))
        subprocess.run(['bash', '-n', str(wrapper)], check=True, capture_output=True)

    def test_core_and_static_signatures(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'core')
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'tests/retail_finalization_core.c'), '-o', binary],
                           check=True, capture_output=True)
            subprocess.run([binary], check=True, capture_output=True, timeout=5)
        snapshot = ROOT / 'private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin'
        if snapshot.exists():
            code = snapshot.read_bytes()
            for rva, signature in ((0x225cb10, bytes.fromhex('48895c2408574883ec20')),
                                   (0x2257db8, bytes.fromhex('488b742430488b5c2438b0014883c4205fc3')),
                                   (0x2258222, bytes.fromhex('b0014883c4385f5bc3')),
                                   (0xd6bbf, bytes.fromhex('ff5008488d4c2420e804151602'))):
                self.assertEqual(code[rva - 0x1000:rva - 0x1000 + len(signature)], signature)

    def test_capture_and_launcher_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'evidence').mkdir()
            with patch.object(probe.forward, 'ROOT', root), patch.object(probe.forward, 'digest', return_value='fixture'):
                capture = probe.prepare_capture()
            self.assertEqual(capture.stat().st_mode & 0o777, 0o700)
            self.assertEqual((capture / 'finalization-private').stat().st_mode & 0o777, 0o700)
            self.assertEqual((capture / 'metadata.json').stat().st_mode & 0o777, 0o600)
        with patch.object(sys, 'argv', ['probe', '--', '/steam wrapper']), \
             patch.dict(os.environ, {'STEAM_COMPAT_INSTALL_PATH': '/game', 'ISAC_SDK_ADAPTER': '1'}, clear=True), \
             patch.object(probe.forward, 'verify') as verify, \
             patch.object(probe, 'prepare_capture', return_value=Path('/private')), \
             patch.object(probe.os, 'execvpe') as execute:
            probe.main()
            verify.assert_called_once_with(Path('/game'), probe=probe.PROBE)
            _, _, env = execute.call_args.args
            self.assertEqual({key for key in env if key.startswith('ISAC_')},
                             {'ISAC_RETAIL_FINALIZATION', 'ISAC_RETAIL_CAPTURE_DIR'})

    def test_redacted_inspector(self):
        import contextlib
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'finalization.jsonl'
            marker = b'SECRET-ID-123456'
            path.write_text(json.dumps({'event': 'agent_submit', 'complete': True,
                'encoding': 'character-id-only-v1', 'data_hex': marker.hex()}) + '\n')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                inspect.summarize(path)
            self.assertIn('event=agent_submit', output.getvalue())
            self.assertNotIn('SECRET', output.getvalue())


if __name__ == '__main__':
    unittest.main()
