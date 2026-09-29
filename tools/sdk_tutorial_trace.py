"""Read-only observer for the analyzed build's 0x00e6 queue handoff.

Confirm whether the five-row object is appended to the generic receive queue,
then whether that queue is transferred at a receive-batch flush. This does not
establish gameplay application. No payload bytes or identifiers are emitted.
"""

import time


SITES = {
    "reader": (0x178F2C0, bytes.fromhex("40 55 56 57 48 8b ec 48 83 ec 60")),
    "completion": (0x178F667, bytes.fromhex("4c 8b 7c 24 50 48 8b 9c 24 88 00 00 00")),
    "enqueue": (0xF844EF, bytes.fromhex("e9 0c fe ff ff")),
    "flush": (0xF84422, bytes.fromhex("e9 d9 fe ff ff")),
}
WRAPPER = (0x17937C0, bytes.fromhex("48 83 c1 20 e9 f7 ba ff ff"))
VTABLE_RVA = 0x319BDE8
READER_SLOT = 0x38
TEXT_END_RVA = 0x2901000


class ActivityTrace:
    def __init__(self, base, read, register, make_breakpoint, emit=print,
                 make_return_breakpoint=None, thread=lambda: 0,
                 now=time.monotonic, maximum_stops=4096,
                 maximum_events=128, seconds=300):
        self.base, self.read, self.register = base, read, register
        self.make_breakpoint, self.emit, self.thread, self.now = (
            make_breakpoint, emit, thread, now)
        self.make_return_breakpoint = make_return_breakpoint
        self.maximum_stops, self.maximum_events, self.seconds = (
            maximum_stops, maximum_events, seconds)
        self.started = now()
        self.stops = self.events = self.entered = self.completed = self.succeeded = 0
        self.parser_returns = self.enqueues = self.producer_returns = self.flushes = 0
        self.breakpoints = {}
        self.pending = {}
        self.target = None
        self.producer = None
        self.queue = None
        self.closed = False

    def arm(self):
        for rva, signature in (*SITES.values(), WRAPPER):
            if bytes(self.read(self.base + rva, len(signature))) != signature:
                raise ValueError(f"tutorial reader signature mismatch at RVA {rva:#x}")
        reader = int.from_bytes(bytes(self.read(self.base + VTABLE_RVA + READER_SLOT, 8)), "little")
        if reader != self.base + WRAPPER[0]:
            raise ValueError("tutorial reader vtable slot mismatch")
        try:
            for name in ("reader", "completion"):
                self.breakpoints[name] = self.make_breakpoint(self.base + SITES[name][0])
        except BaseException:
            self.close("arm-failed")
            raise
        self.emit("ISAC_TUTORIAL_TRACE_READY profile=activity hardware_slots=2 "
                  "mode=read-only payloads=none post_parser=queue-append")

    def event_kind(self, breakpoints):
        return next((name for name, bp in self.breakpoints.items() if bp in breakpoints), None)

    def handle(self, kind):
        if self.closed:
            return
        self.stops += 1
        if self.stops > self.maximum_stops or self.now() - self.started > self.seconds:
            self.close("limit")
            return
        if self.events >= self.maximum_events:
            self.close("event-limit")
            return
        tid = self.thread()
        if kind == "reader":
            self.entered += 1
            destination = self.register("rcx")
            vtable = int.from_bytes(bytes(self.read(destination - 0x20, 8)), "little")
            if vtable != self.base + VTABLE_RVA:
                raise ValueError("unexpected tutorial message object")
            return_address = int.from_bytes(bytes(self.read(self.register("rsp"), 8)), "little")
            if not self.base <= return_address < self.base + TEXT_END_RVA:
                raise ValueError("tutorial parser return is outside analyzed text")
            self.pending[tid] = (destination, return_address)
            self.emit(f"ISAC_TUTORIAL_TRACE_READER thread={tid} sequence={self.entered} "
                      "type=0x00e6 result=pending")
        elif kind == "completion":
            pending = self.pending.pop(tid, None)
            if pending is None or pending[0] != self.register("rsi"):
                self.emit(f"ISAC_TUTORIAL_TRACE_COMPLETION thread={tid} matched=0 "
                          "result=uncorrelated")
            else:
                destination, return_address = pending
                self.completed += 1
                success = bool(self.register("eax") & 0xff)
                self.succeeded += int(success)
                # The repeated-row count resides at destination+0x28 in this
                # build. Only a bounded scalar is logged, never row contents.
                count = int.from_bytes(bytes(self.read(destination + 0x28, 4)), "little")
                rows = str(count) if count <= 1024 else "out-of-range"
                self.emit(f"ISAC_TUTORIAL_TRACE_COMPLETION thread={tid} matched=1 "
                          f"parser_success={int(success)} rows={rows} "
                          "retention=unobserved")
                if success and count == 5 and self.make_return_breakpoint is not None:
                    self.target = (destination - 0x20, return_address)
                    if self._replace_with("return", return_address):
                        self.emit("ISAC_TUTORIAL_TRACE_WATCH armed=1 seam=parser-return "
                                  "next=receive-queue-append scope=decoder-thread payloads=none")
        elif kind == "return":
            if self.target is None or self.register("rip") != self.target[1]:
                raise ValueError("unexpected tutorial parser return site")
            self.parser_returns += 1
            rva = self.target[1] - self.base
            success = bool(self.register("eax") & 0xff)
            self.emit(f"ISAC_TUTORIAL_TRACE_HANDOFF thread={tid} return_rva={rva:#x} "
                      f"parser_result={int(success)} dispatch=unconfirmed")
            if not success:
                self.close("parser-return-failed")
                return
            self._replace_with("enqueue", self.base + SITES["enqueue"][0])
        elif kind == "enqueue":
            if self.target is None or self.register("rip") != self.base + SITES["enqueue"][0]:
                raise ValueError("unexpected queue append site")
            obj = self.register("rdi")
            if obj != self.target[0]:
                # The receive loop can parse more than one message.
                self.events += 1
                return
            queue = self.register("rbx")
            slot = self.register("rdx")
            old_count = self.register("r8")
            new_count = self._u32(queue + 0x28)
            vector = self._u64(queue + 0x20)
            stored = self._u64(slot) if slot else 0
            valid = (slot != 0 and old_count < 4096 and
                     slot == vector + old_count * 8 and
                     new_count == old_count + 1 and stored == obj and
                     self._u64(obj) == self.base + VTABLE_RVA and
                     self._u32(obj + 0x48) == 5)
            self.enqueues += int(valid)
            self.emit(f"ISAC_TUTORIAL_TRACE_ENQUEUE thread={tid} "
                      f"object=decoded-five-row stored={int(valid)} "
                      "queue=generic-receive application=unproven")
            if not valid:
                self.close("enqueue-not-confirmed")
                return
            # f84280 pushes five registers and reserves 0x60 bytes.
            parent = self._u64(self.register("rsp") + 0x88)
            if not self.base <= parent < self.base + TEXT_END_RVA:
                self.close("producer-return-outside-text")
                return
            self.producer = parent
            self.queue = queue
            if self._replace_with("producer_return", parent):
                try:
                    self.breakpoints["flush"] = self.make_breakpoint(
                        self.base + SITES["flush"][0])
                except BaseException:
                    self.close("flush-breakpoint-unavailable")
                    return
                self.emit(f"ISAC_TUTORIAL_TRACE_PRODUCER_CALLER thread={tid} "
                          f"return_rva={parent - self.base:#x} queue=confirmed "
                          "next=receive-batch-flush")
        elif kind == "producer_return":
            if self.producer is None or self.register("rip") != self.producer:
                raise ValueError("unexpected producer return site")
            self.producer_returns += 1
            self.emit(f"ISAC_TUTORIAL_TRACE_PRODUCER_RETURN thread={tid} "
                      f"return_rva={self.producer - self.base:#x} "
                      "flush=pending consumer=unidentified")
            self.breakpoints.pop("producer_return").delete()
            return
        elif kind == "flush":
            if self.register("rip") != self.base + SITES["flush"][0]:
                raise ValueError("unexpected receive flush site")
            if self.register("rbx") != self.queue:
                return
            batch = self.register("rdi")
            vector = self._u64(batch)
            count = self._u32(batch + 8)
            if count > 4096:
                self.close("flush-count-out-of-range")
                return
            found = bool(vector) and any(
                self._u64(vector + index * 8) == self.target[0]
                for index in range(count))
            self.flushes += int(found)
            self.emit(f"ISAC_TUTORIAL_TRACE_FLUSH thread={tid} "
                      f"same_queue=1 transferred={int(found)} "
                      f"batch_count={count} application=unproven")
            if found:
                self.close("target-flushed")
            return
        else:
            raise ValueError("unexpected tutorial trace site")
        self.events += 1

    def _replace_with(self, name, address):
        # All later sites are thread-scoped hardware execute breakpoints.
        # Creation fails closed rather than falling back to a software trap.
        for breakpoint in self.breakpoints.values():
            breakpoint.delete()
        self.breakpoints.clear()
        try:
            self.breakpoints[name] = self.make_return_breakpoint(address)
        except BaseException:
            self.close("handoff-breakpoint-unavailable")
            return False
        return True

    def _u32(self, address):
        return int.from_bytes(bytes(self.read(address, 4)), "little")

    def _u64(self, address):
        return int.from_bytes(bytes(self.read(address, 8)), "little")

    def close(self, reason):
        if self.closed:
            return
        self.closed = True
        for breakpoint in self.breakpoints.values():
            try:
                breakpoint.delete()
            except Exception:
                pass  # Inferior may already have exited during trace teardown.
        self.breakpoints.clear()
        self.emit(f"ISAC_TUTORIAL_TRACE_END reason={reason} entered={self.entered} "
                  f"completed={self.completed} parser_success={self.succeeded} "
                  f"parser_returns={self.parser_returns} enqueues={self.enqueues} "
                  f"producer_returns={self.producer_returns} flushes={self.flushes} "
                  f"pending={len(self.pending)} "
                  "application=unproven")
