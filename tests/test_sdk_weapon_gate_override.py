import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sdk_weapon_gate_override import GETTER_RVA, SIGNATURE, WeaponGateOverride


class Breakpoint:
    def __init__(self):
        self.deleted = False

    def delete(self):
        self.deleted = True


class WeaponGateTests(unittest.TestCase):
    def test_only_clears_positive_count_after_stage_marker(self):
        base, owner, pointer = 0x140000000, 0x50000000, 0x60000000
        sprint = 0x60001000
        running = 0x60002000
        cover_to_cover = 0x60003000
        firing = 0x60004000
        reload = 0x60005000
        memory = {}
        memory[base + GETTER_RVA] = SIGNATURE
        memory[owner + 0x380] = pointer.to_bytes(8, 'little')
        memory[owner + 0x2e0] = sprint.to_bytes(8, 'little')
        memory[owner + 0x2b8] = running.to_bytes(8, 'little')
        memory[owner + 0x308] = cover_to_cover.to_bytes(8, 'little')
        memory[owner + 0x2f8] = firing.to_bytes(8, 'little')
        memory[owner + 0x2d0] = reload.to_bytes(8, 'little')
        memory[pointer + 0x28] = (0).to_bytes(8, 'little')
        memory[pointer + 0x10] = (2).to_bytes(4, 'little', signed=True)
        memory[sprint + 0x28] = (0).to_bytes(8, 'little')
        memory[sprint + 0x10] = (1).to_bytes(4, 'little', signed=True)
        memory[running + 0x28] = (0).to_bytes(8, 'little')
        memory[running + 0x10] = (2).to_bytes(4, 'little', signed=True)
        memory[cover_to_cover + 0x28] = (0).to_bytes(8, 'little')
        memory[cover_to_cover + 0x10] = (3).to_bytes(4, 'little', signed=True)
        memory[firing + 0x28] = (0).to_bytes(8, 'little')
        memory[firing + 0x10] = (4).to_bytes(4, 'little', signed=True)
        memory[reload + 0x28] = (0).to_bytes(8, 'little')
        memory[reload + 0x10] = (0).to_bytes(4, 'little', signed=True)
        writes = []
        events = []
        breakpoint = Breakpoint()

        def read(address, size):
            return memory[address][:size]

        def write(address, data):
            writes.append((address, data))
            memory[address] = data

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'ready'
            gate = WeaponGateOverride(base, read, lambda name: {
                'rip': base + GETTER_RVA, 'rcx': owner}[name],
                lambda address: breakpoint, write=write,
                can_write=lambda address, size: True,
                stage_marker=marker, emit=events.append)
            gate.arm()
            self.assertEqual(gate.event_kind([breakpoint]), 'gate')
            gate.handle('gate')
            self.assertFalse(writes)
            marker.touch()
            gate.handle('gate')
            gate.handle('gate')
            (Path(directory) / 'weapon-gate-activity-closed.ready').touch()
            memory[sprint + 0x10] = (0).to_bytes(4, 'little', signed=True)
            gate.handle('gate')
            self.assertEqual(writes, [(pointer + 0x10, b'\0' * 4)])
            gate.close('test')
            self.assertTrue(breakpoint.deleted)
            self.assertTrue(any('cleared=1' in item for item in events))
            self.assertTrue(any('ISAC_ACTION_GATE_OBSERVED phase=shooting property=sprinting count=1 applied=0'
                                in item for item in events))
            self.assertTrue(any('ISAC_ACTION_GATE_OBSERVED phase=closed property=sprinting count=0 applied=0'
                                in item for item in events))
            self.assertTrue(any('ISAC_ACTION_GATE_OBSERVED phase=closed property=running count=2 applied=0'
                                in item for item in events))
            self.assertTrue(any('ISAC_ACTION_GATE_OBSERVED phase=closed property=cover-to-cover count=3 applied=0'
                                in item for item in events))
            self.assertTrue(any('ISAC_ACTION_GATE_OBSERVED phase=shooting property=firing count=4 applied=0'
                                in item for item in events))
            self.assertTrue(any('ISAC_ACTION_GATE_OBSERVED phase=shooting property=reload count=0 applied=0'
                                in item for item in events))

    def test_rejects_unbounded_count(self):
        base, owner, pointer = 0x140000000, 0x50000000, 0x60000000
        memory = {base + GETTER_RVA: SIGNATURE,
                  owner + 0x380: pointer.to_bytes(8, 'little'),
                  pointer + 0x28: (0).to_bytes(8, 'little'),
                  pointer + 0x10: (1000).to_bytes(4, 'little', signed=True)}
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'ready'
            marker.touch()
            gate = WeaponGateOverride(base, lambda address, size: memory[address][:size],
                lambda name: {'rip': base + GETTER_RVA, 'rcx': owner}[name],
                lambda address: Breakpoint(), write=lambda *_: self.fail('unsafe write'),
                can_write=lambda *_: True, stage_marker=marker, emit=lambda _: None)
            gate.arm()
            gate.handle('gate')
            self.assertEqual(gate.cleared, 0)

    def test_running_count_clears_once_only_after_tutorial_close_on_weapon_owner(self):
        base, owner, other = 0x140000000, 0x50000000, 0x50001000
        weapon, running = 0x60000000, 0x60001000
        memory = {
            base + GETTER_RVA: SIGNATURE,
            owner + 0x380: weapon.to_bytes(8, 'little'),
            owner + 0x2b8: running.to_bytes(8, 'little'),
            weapon + 0x28: (0).to_bytes(8, 'little'),
            weapon + 0x10: (1).to_bytes(4, 'little', signed=True),
            running + 0x28: (0).to_bytes(8, 'little'),
            running + 0x10: (1).to_bytes(4, 'little', signed=True),
            other + 0x380: weapon.to_bytes(8, 'little'),
            other + 0x2b8: running.to_bytes(8, 'little'),
        }
        current = {'owner': owner}
        writes, events = [], []
        def read(address, size):
            return memory[address][:size]
        def write(address, data):
            writes.append((address, data))
            memory[address] = data
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'ready'
            marker.touch()
            gate = WeaponGateOverride(base, read, lambda name: {
                'rip': base + GETTER_RVA, 'rcx': current['owner']}[name],
                lambda address: Breakpoint(), write=write,
                can_write=lambda address, size: True,
                stage_marker=marker, emit=events.append)
            gate.arm()
            gate.handle('gate')
            self.assertEqual(writes, [(weapon + 0x10, b'\0' * 4)])
            (Path(directory) / 'weapon-gate-activity-closed.ready').touch()
            current['owner'] = other
            gate.handle('gate')
            self.assertEqual(len(writes), 1)
            current['owner'] = owner
            gate.handle('gate')
            gate.handle('gate')
            self.assertEqual(writes, [(weapon + 0x10, b'\0' * 4),
                                      (running + 0x10, b'\0' * 4)])
            self.assertTrue(gate.running_cleared)
            self.assertTrue(any('ISAC_RUNNING_GATE_OVERRIDE prior_count=1 applied=1'
                                in item for item in events))
