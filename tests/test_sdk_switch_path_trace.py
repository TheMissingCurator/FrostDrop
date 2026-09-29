import runpy
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TRACE = runpy.run_path(str(ROOT / 'tools/sdk_switch_path_trace.py'))
SwitchPathTrace = TRACE['SwitchPathTrace']
SITES = TRACE['SITES']


class Breakpoint:
    def __init__(self, address):
        self.address = address
        self.deleted = False

    def delete(self):
        self.deleted = True


class SwitchPathTraceTests(unittest.TestCase):
    def test_sites_match_verified_runtime_text_when_available(self):
        path = ROOT / ('private/tctd-runtime-text-'
            'dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin')
        if not path.exists():
            self.skipTest('verified private runtime text unavailable')
        with path.open('rb') as stream:
            for rva, signature in SITES.values():
                stream.seek(rva - 0x1000)
                self.assertEqual(stream.read(len(signature)), signature)

    def test_attested_candidate_path_and_cleanup(self):
        base = 0x140000000
        memory = {base + rva: signature for rva, signature in SITES.values()}
        state = {'rip': 0, 'time': 0.0}
        output = []
        trace = SwitchPathTrace(base, lambda address, size: memory[address][:size],
            lambda name: state[name], Breakpoint, emit=output.append,
            thread=lambda: 17, now=lambda: state['time'])
        trace.arm()
        self.assertEqual(len(trace.breakpoints), 2)
        node = trace.breakpoints['request_node']
        request = trace.breakpoints['switch_request']
        self.assertEqual(trace.event_kind((node,)), 'request_node')
        state['rip'] = base + SITES['request_node'][0]
        trace.handle('request_node')
        state['time'] = 0.25
        state['rip'] = base + SITES['switch_request'][0]
        trace.handle('switch_request')
        self.assertEqual((trace.nodes, trace.requests, trace.paired), (1, 1, 1))
        trace.close('test')
        self.assertTrue(node.deleted and request.deleted)
        self.assertIn('paired=1 gate_value=unobserved', output[-1])

    def test_signature_mismatch_fails_before_breakpoint(self):
        base = 0x140000000
        made = []
        trace = SwitchPathTrace(base, lambda address, size: b'\x00' * size,
            lambda name: 0, lambda address: made.append(address), emit=lambda _: None)
        with self.assertRaisesRegex(ValueError, 'signature mismatch'):
            trace.arm()
        self.assertEqual(made, [])


if __name__ == '__main__':
    unittest.main()
