import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location(
    'sdk_client_presentation_trace', ROOT / 'tools/sdk_client_presentation_trace.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ClientPresentationTraceTests(unittest.TestCase):
    def test_local_handoff_releases_gate_before_arming_nodes(self):
        events = []

        class Breakpoint:
            def __init__(self, address):
                self.address = address

            def delete(self):
                events.append(('delete', self.address))

        class Gate:
            def __init__(self, base, read, register, make_breakpoint, **kwargs):
                self.base = base
                self.breakpoint = make_breakpoint(base + 0xd19ee0)
                self.closed = self.running_cleared = False

            def arm(self):
                pass

            def event_kind(self, breakpoints):
                return 'gate' if self.breakpoint in breakpoints else None

            def handle(self, kind):
                self.running_cleared = True

            def close(self, reason):
                self.breakpoint.delete()
                self.closed = True

        base = 0x100000000
        signatures = {base + rva: signature for rva, signature in module.SITES.values()}
        stack = base + 0x50000000

        def read(address, size):
            if address == stack:
                return (base + 0x12345).to_bytes(8, 'little')
            return signatures[address][:size]

        with patch.object(module, 'WeaponGateOverride', Gate):
            trace = module.ClientPresentationTrace(base, read,
                lambda name: base + module.SITES['objective_notification'][0] if name == 'rip' else stack,
                lambda address: events.append(('arm', address)) or Breakpoint(address),
                write=lambda *args: None, can_write=lambda *args: True,
                stage_marker='/unused', emit=lambda line: events.append(('log', line)),
                now=lambda: 10)
            trace.arm()
            self.assertFalse(trace.armed)
            trace.handle('gate')
            self.assertTrue(trace.armed)
            self.assertLess(events.index(('delete', base + 0xd19ee0)),
                            events.index(('arm', base + module.SITES['objective_notification'][0])))
            self.assertEqual(trace.stops, 1)
            self.assertEqual(trace.event_kind([trace.breakpoints['objective_notification']]),
                             'objective_notification')
            trace.handle('objective_notification')
            self.assertEqual(trace.counts['objective_notification'], 1)
            trace.close('test')
            self.assertEqual(len([event for event in events if event[0] == 'delete']), 3)

    def test_native_payload_free_core(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'presentation'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'tests/retail_presentation_core.c'), '-o', str(binary)],
                           check=True, capture_output=True)
            result = subprocess.run([str(binary)], check=True, capture_output=True,
                                    text=True, timeout=5)
            self.assertIn('payload-free', result.stdout)

    def test_node_sites_match_verified_text(self):
        snapshot = ROOT / 'private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin'
        if not snapshot.exists():
            self.skipTest('verified text unavailable')
        text = snapshot.read_bytes()
        for rva, signature in module.SITES.values():
            self.assertEqual(text[rva-0x1000:rva-0x1000+len(signature)], signature)


if __name__ == '__main__':
    unittest.main()
