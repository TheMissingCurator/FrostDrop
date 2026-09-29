"""Opt-in, local-only weapon and post-tutorial running-gate experiment.

The build-attested getter at RVA d19ee0 loads the named property pointer from
owner+0x380 and returns whether its signed count at pointer+0x10 is positive.
Only after the local backend sends the shooting stage may this observer clear
a small positive count. This is a diagnostic runtime override, not a decoded
server message or a general gameplay fix.

The same owner holds several movement-prevention properties. Only the running
count may be cleared, once, after the local backend closes Agent Activation
and only on the owner whose weapon-switch count was previously cleared.
"""

from pathlib import Path


GETTER_RVA = 0xD19EE0
SIGNATURE = bytes.fromhex('48 8b 91 80 03 00 00 33 c0 48 85 d2')
EMPTY_SENTINEL_RVA = 0x42BC6F0
ACTION_PROPERTIES = (
    ('running', 0x2b8),
    ('sprinting', 0x2e0),
    ('cover-to-cover', 0x308),
    ('cover', 0x320),
    ('exit-cover', 0x328),
    ('firing', 0x2f8),
    ('reload', 0x2d0),
)


class WeaponGateOverride:
    def __init__(self, base, read, register, make_breakpoint, *, write,
                 can_write, stage_marker, emit=print, maximum_stops=16384):
        self.base, self.read, self.register = base, read, register
        self.make_breakpoint, self.write, self.can_write = make_breakpoint, write, can_write
        self.stage_marker, self.emit = Path(stage_marker), emit
        self.maximum_stops = maximum_stops
        self.breakpoints = {}
        self.stops = self.positive = self.cleared = 0
        self.active_reported = self.closed = False
        self.action_samples = {}
        self.action_reports = 0
        self.weapon_owner = None
        self.running_cleared = False

    def arm(self):
        if bytes(self.read(self.base + GETTER_RVA, len(SIGNATURE))) != SIGNATURE:
            raise ValueError('weapon-gate getter signature mismatch')
        self.breakpoints['gate'] = self.make_breakpoint(self.base + GETTER_RVA)
        self.emit('ISAC_WEAPON_GATE_READY mode=local-experimental '
                  'condition=shooting-stage-marker count=positive-to-zero')

    def event_kind(self, breakpoints):
        return 'gate' if self.breakpoints.get('gate') in breakpoints else None

    def handle(self, kind):
        if self.closed or kind != 'gate':
            return
        if not self.stage_marker.is_file():
            return
        self.stops += 1
        if self.stops > self.maximum_stops:
            self.close('limit')
            return
        if self.register('rip') != self.base + GETTER_RVA:
            raise ValueError('unexpected weapon-gate stop')
        if not self.active_reported:
            self.emit('ISAC_WEAPON_GATE_ACTIVE stage=shooting-sent')
            self.active_reported = True
        owner = self.register('rcx')
        if owner < 0x10000:
            return
        # Observe action-prevention properties on this same owner, without
        # installing another hot-path breakpoint or mutating any except the
        # bounded post-tutorial running experiment below.
        phase = ('closed' if (self.stage_marker.parent /
                  'weapon-gate-activity-closed.ready').is_file() else 'shooting')
        action_values = {}
        for name, offset in ACTION_PROPERTIES:
            try:
                property_pointer = int.from_bytes(self.read(owner + offset, 8), 'little')
                if property_pointer < 0x10000:
                    continue
                sentinel = int.from_bytes(self.read(property_pointer + 0x28, 8), 'little')
                if sentinel == self.base + EMPTY_SENTINEL_RVA:
                    continue
                count = int.from_bytes(self.read(property_pointer + 0x10, 4),
                                       'little', signed=True)
                action_values[name] = (property_pointer, count)
                key = (phase, name)
                if self.action_samples.get(key) != count:
                    self.action_samples[key] = count
                    self.action_reports += 1
                    if self.action_reports <= 56:
                        self.emit(f'ISAC_ACTION_GATE_OBSERVED phase={phase} '
                                  f'property={name} count={count} applied=0')
            except (KeyError, OSError, ValueError):
                continue
        if phase == 'closed' and owner == self.weapon_owner and not self.running_cleared:
            running = action_values.get('running')
            if running is not None and running[1] == 1 and self.can_write(running[0] + 0x10, 4):
                self.write(running[0] + 0x10, b'\0' * 4)
                self.running_cleared = True
                self.emit('ISAC_RUNNING_GATE_OVERRIDE prior_count=1 applied=1 '
                          'phase=closed owner=weapon-gate-owner')
        pointer = int.from_bytes(self.read(owner + 0x380, 8), 'little')
        if pointer < 0x10000:
            return
        sentinel = int.from_bytes(self.read(pointer + 0x28, 8), 'little')
        if sentinel == self.base + EMPTY_SENTINEL_RVA:
            return
        count = int.from_bytes(self.read(pointer + 0x10, 4), 'little', signed=True)
        if count <= 0:
            return
        self.positive += 1
        if not 1 <= count <= 32 or not self.can_write(pointer + 0x10, 4):
            if self.positive <= 8:
                self.emit('ISAC_WEAPON_GATE_OBSERVED positive=1 applied=0 reason=unsafe-count-or-page')
            return
        self.write(pointer + 0x10, b'\0\0\0\0')
        self.cleared += 1
        self.weapon_owner = owner
        if self.cleared <= 8:
            self.emit(f'ISAC_WEAPON_GATE_OVERRIDE prior_count={count} applied=1')

    def close(self, reason):
        if self.closed:
            return
        self.closed = True
        for breakpoint in self.breakpoints.values():
            breakpoint.delete()
        self.breakpoints.clear()
        self.emit(f'ISAC_WEAPON_GATE_SUMMARY reason={reason} stops={self.stops} '
                  f'positive={self.positive} cleared={self.cleared} '
                  f'running_cleared={int(self.running_cleared)}')
