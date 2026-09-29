"""Read-only client-node observation after the existing local tutorial gates.

The local gate experiment remains opt-in and unchanged through the first
tutorial. Once its running count has been cleared, its breakpoint is released
and two hardware execute breakpoints observe candidate UI/audio node methods.
No node arguments, text, audio identifiers, or payloads are logged.
"""

import time

from sdk_weapon_gate_override import WeaponGateOverride


SITES = {
    'objective_notification': (0x17A55C0, bytes.fromhex('48 89 4c 24 08 53 55 48 83 ec 78')),
    'post_dialogue_event': (0x632DC0, bytes.fromhex('48 89 5c 24 08 48 89 6c 24 18 56 57 41 54 41 56')),
}
TEXT_END_RVA = 0x2901000


class ClientPresentationTrace:
    def __init__(self, base, read, register, make_breakpoint, *, write,
                 can_write, stage_marker, emit=print, now=time.monotonic,
                 maximum_stops=16384):
        self.base, self.read, self.register = base, read, register
        self.make_breakpoint, self.emit, self.now = make_breakpoint, emit, now
        self.gate = WeaponGateOverride(base, read, register, make_breakpoint,
            write=write, can_write=can_write, stage_marker=stage_marker, emit=emit)
        self.breakpoints = {}
        self.started = now()
        self.counts = {name: 0 for name in SITES}
        self.stops = 0
        self.maximum_stops = maximum_stops
        self.closed = False
        self.armed = False

    def arm(self):
        for rva, signature in SITES.values():
            if bytes(self.read(self.base + rva, len(signature))) != signature:
                raise ValueError(f'client presentation signature mismatch at RVA {rva:#x}')
        self.gate.arm()
        self.emit('ISAC_CLIENT_PRESENTATION_READY phase=local-tutorial-gate '
                  'node_trace=after-known-running-gate hardware=1')

    def event_kind(self, breakpoints):
        if not self.gate.closed and self.gate.event_kind(breakpoints):
            return 'gate'
        return next((name for name, bp in self.breakpoints.items()
                     if bp in breakpoints), None)

    def handle(self, kind):
        if self.closed:
            return
        if kind == 'gate':
            self.stops += 1
            self.gate.handle('gate')
            if self.gate.running_cleared:
                self.gate.close('presentation-handoff')
                try:
                    for name, (rva, _) in SITES.items():
                        self.breakpoints[name] = self.make_breakpoint(self.base + rva)
                except BaseException:
                    self.close('node-breakpoint-unavailable')
                    raise
                self.armed = True
                self.emit('ISAC_CLIENT_PRESENTATION_ARMED phase=safe-house-handoff '
                          'nodes=objective-notification,post-dialogue-event '
                          'observes=evaluation-entry result=unobserved')
            return
        if kind not in SITES or self.register('rip') != self.base + SITES[kind][0]:
            raise ValueError('unexpected client presentation stop')
        self.stops += 1
        if sum(self.counts.values()) >= self.maximum_stops:
            self.close('limit')
            return
        self.counts[kind] += 1
        if self.counts[kind] <= 128:
            caller = int.from_bytes(bytes(self.read(self.register('rsp'), 8)), 'little')
            caller_rva = caller - self.base if self.base <= caller < self.base + TEXT_END_RVA else 0
            self.emit(f'ISAC_CLIENT_NODE node={kind} count={self.counts[kind]} '
                      f'since_trace_start_ms={int((self.now()-self.started)*1000)} '
                      f'caller_rva={caller_rva:#x} result=unobserved')

    def close(self, reason):
        if self.closed:
            return
        self.closed = True
        if not self.gate.closed:
            self.gate.close(reason)
        for breakpoint in self.breakpoints.values():
            try:
                breakpoint.delete()
            except Exception:
                pass
        self.breakpoints.clear()
        self.emit(f'ISAC_CLIENT_PRESENTATION_SUMMARY reason={reason} '
                  f'armed={int(self.armed)} stops={self.stops} '
                  f'objective_notification={self.counts["objective_notification"]} '
                  f'post_dialogue_event={self.counts["post_dialogue_event"]} '
                  'interpretation=node-evaluation-only')
