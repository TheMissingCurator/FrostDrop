"""Synthetic-only relocations. Never loaded by the retail Steam wrapper."""
import os
from pathlib import Path
import sys
import gdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import retail_service_name_gdb as driver
import sdk_backend_trace as names
import service_name_producer_trace as producer

binary = Path(os.environ.get("ISAC_FIXTURE_BINARY", gdb.current_progspace().filename))
if binary.name != "retail-name-fixture":
    raise RuntimeError("Synthetic fixture binary required")
if Path(gdb.current_progspace().filename).resolve() != binary.resolve():
    if not binary.is_absolute() or any(c.isspace() for c in str(binary)):
        raise RuntimeError("Invalid synthetic fixture symbols")
    gdb.execute("symbol-file " + str(binary), to_string=True)
if os.environ.get("ISAC_FIXTURE_LIFECYCLE") == "1":
    gdb.execute("maintenance set show-debug-regs 1", to_string=True)
    def inferior_event(event):
        print("FIXTURE_NEW_INFERIOR", event.inferior.num, "pid", event.inferior.pid,
              "selected", gdb.selected_inferior().num, flush=True)
    gdb.events.new_inferior.connect(inferior_event)

def address(name):
    return int(gdb.parse_and_eval("&fixture_" + name))

for mapping in (names.NAME_SITES, producer.SITES):
    for name in mapping:
        mapping[name] = (address(name), b"\x90")
names.NAME_AUXILIARY = producer.AUXILIARY = {address("auxiliary"): b"\x90"}

class FixtureDriver(driver.Driver):
    base = 0
    def breakpoint(self, address):
        if self.architecture() != "i386:x86-64":
            raise ValueError("PE64 guard must not be armed in an i386 launcher")
        bp = super().breakpoint(address)
        scoped = [item for item in gdb.breakpoints() if item.type == gdb.BP_HARDWARE_BREAKPOINT
                  and item.inferior == bp.inferior]
        if len(scoped) > 4:
            raise ValueError("Fixture exceeded four hardware slots in one inferior")
        return bp
    def stop(self):
        event = self.last_event
        if type(event) is gdb.StopEvent or (isinstance(event, gdb.SignalEvent) and event.stop_signal == "SIGTRAP"):
            count = getattr(self, "fixture_trap_count", 0)
            self.fixture_trap_count = count + 1
            if count < 12:
                print("FIXTURE_TRAP", count, type(event).__name__, event.details,
                      "si_code", int(gdb.parse_and_eval("$_siginfo.si_code")),
                      "tf", int(gdb.parse_and_eval("$eflags")) & 0x100, flush=True)
        if isinstance(event, gdb.BreakpointEvent) and any(
                bp in event.breakpoints for bp in self.exec_syscall_catches.values()):
            if os.environ.get("ISAC_FIXTURE_LIFECYCLE") == "1":
                print("FIXTURE_SYSCALL_DETAILS", event.details,
                      "architecture", gdb.selected_frame().architecture().name(), flush=True)
            number = event.details.get("syscall-number")
            if gdb.selected_frame().architecture().name() == "i386:x86-64" and number == 11:
                raise ValueError("i386 exec observer falsely stopped at x86-64 munmap")
        if os.environ.get("ISAC_FIXTURE_LIFECYCLE") == "1":
            print("FIXTURE_STOP", type(event).__name__,
                  [bp.number for bp in event.breakpoints] if isinstance(event, gdb.BreakpointEvent) else [],
                  "reason", getattr(event, "details", {}).get("reason"),
                  "inferior", gdb.selected_inferior().num,
                  "bootstrap_valid", self.bootstrap.is_valid() if self.bootstrap is not None else None, flush=True)
        result = super().stop()
        return result
    def verify_bootstrap(self, inferior):
        if Path(gdb.current_progspace().filename).resolve() != binary.resolve():
            raise ValueError("Unexpected fixture inferior")
        if bytes(inferior.read_memory(address("owner_constructed"), 1)) != b"\x90":
            raise ValueError("fixture anchor mismatch")

FixtureDriver(os.environ["ISAC_RETAIL_PROBE_CAPTURE"]).run()
