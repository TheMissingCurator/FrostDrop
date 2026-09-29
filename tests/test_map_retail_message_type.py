"""Build-specific static type mapping; emits addresses only."""

from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAPPER = runpy.run_path(str(ROOT / 'tools/map-retail-message-type.py'))


class StaticMessageMapTests(unittest.TestCase):
    def test_known_world_readers(self):
        if not MAPPER['TEXT'].exists() or not MAPPER['RDATA'].exists():
            self.skipTest('private verified runtime snapshots unavailable')
        text, rdata = MAPPER['load_snapshots']()
        initializers = MAPPER['initializer_globals'](text)
        self.assertEqual(MAPPER['map_type'](0x014d, text, rdata, initializers)[3][2], 0x17939e0)
        self.assertEqual(MAPPER['map_type'](0x0157, text, rdata, initializers)[3][2], 0xc4a690)
        self.assertEqual(MAPPER['map_type'](0x000c, text, rdata, initializers)[3],
                         (0x3198ce8, 0x18a6920, 0x1791a50))
        self.assertEqual(MAPPER['map_type'](0x015a, text, rdata, initializers)[3],
                         (0x31a01e8, 0x18a2030, 0x178cd30))


if __name__ == '__main__':
    unittest.main()
