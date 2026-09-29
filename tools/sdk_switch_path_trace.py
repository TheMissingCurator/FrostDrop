"""Read-only, build-attested switch-request path observer.

These two sites are a candidate script-node request path, not the underlying
PreventWeaponSwitchingRefCount value or a proven keyboard-input handler. No
game bytes, payloads, identifiers, or memory values are logged or changed.
"""

import time


SITES = {
    "request_node": (0x12F4860, bytes.fromhex("40 53 48 83 ec 20 48 8b 0d bb 42 39 03")),
    "switch_request": (0x14CDEC0, bytes.fromhex("48 89 5c 24 08 48 89 6c 24 18 48 89 74 24 20 57")),
}


class SwitchPathTrace:
    def __init__(self, base, read, register, make_breakpoint, emit=print,
                 thread=lambda: 0, now=time.monotonic, maximum_stops=4096,
                 maximum_events=32, seconds=900):
        self.base, self.read, self.register = base, read, register
        self.make_breakpoint, self.emit, self.thread, self.now = (
            make_breakpoint, emit, thread, now)
        self.maximum_stops, self.maximum_events, self.seconds = (
            maximum_stops, maximum_events, seconds)
        self.started = now()
        self.breakpoints = {}
        self.pending = {}
        self.stops = self.events = self.nodes = self.requests = self.paired = 0
        self.closed = False

    def arm(self):
        for rva, signature in SITES.values():
            if bytes(self.read(self.base + rva, len(signature))) != signature:
                raise ValueError(f"switch-path signature mismatch at RVA {rva:#x}")
        try:
            for name, (rva, _) in SITES.items():
                self.breakpoints[name] = self.make_breakpoint(self.base + rva)
        except BaseException:
            self.close("arm-failed")
            raise
        self.emit("ISAC_SWITCH_PATH_READY hardware_slots=2 mode=read-only "
                  "scope=request-node-and-switch-request gate_value=unobserved")

    def event_kind(self, breakpoints):
        return next((name for name, bp in self.breakpoints.items()
                     if bp in breakpoints), None)

    def handle(self, kind):
        if self.closed:
            return
        self.stops += 1
        if (self.stops > self.maximum_stops or self.now() - self.started > self.seconds
                or self.events >= self.maximum_events):
            self.close("limit")
            return
        if kind not in SITES or self.register("rip") != self.base + SITES[kind][0]:
            raise ValueError("unexpected switch-path stop")
        tid = self.thread()
        if kind == "request_node":
            self.nodes += 1
            self.pending[tid] = self.now()
            self.emit(f"ISAC_SWITCH_PATH_NODE thread={tid} sequence={self.nodes} "
                      "gate=upstream-or-passed request=unconfirmed")
        else:
            self.requests += 1
            started = self.pending.pop(tid, None)
            paired = started is not None and 0 <= self.now() - started <= 2
            self.paired += int(paired)
            if paired or self.requests <= 8:
                self.emit(f"ISAC_SWITCH_PATH_REQUEST thread={tid} sequence={self.requests} "
                          f"paired_node={int(paired)} wire_submission=unconfirmed")
        self.events += int(kind == "request_node" or paired)

    def close(self, reason):
        if self.closed:
            return
        self.closed = True
        for breakpoint in self.breakpoints.values():
            breakpoint.delete()
        self.breakpoints.clear()
        self.emit(f"ISAC_SWITCH_PATH_SUMMARY reason={reason} nodes={self.nodes} "
                  f"requests={self.requests} paired={self.paired} "
                  "gate_value=unobserved")
