"""Retail-only execution-hardware observer. No adapter or certificate override."""
import os
from pathlib import Path
import signal
import sys

import gdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sdk_backend_trace import NameLineageTrace, NAME_SITES, archive_service_name
from service_name_producer_trace import ProducerTrace, archive_fields


def register(name):
    return int(gdb.parse_and_eval("$" + name)) & ((1 << 64) - 1)


class Driver:
    base = 0x140000000
    exec_numbers = {"i386": {11, 358}, "i386:x86-64": {59, 322}}

    def __init__(self, capture):
        self.capture = Path(capture)
        self.last_event = None
        self.bootstraps = {}
        self.exited_inferiors = set()
        self.exec_catch = None
        self.exec_syscall_catches = {}
        self.exec_syscall_arches = {}
        self.syscalls_ready = False
        self.lifecycle_error = False
        self.fork_catches = []
        self.game = None
        self.traces = []
        self.started = False
        self.trace_trap_inferiors = set()
        gdb.events.stop.connect(self.stopped)
        gdb.events.exited.connect(self.exited)
        gdb.events.new_thread.connect(self.new_thread)

    def stopped(self, event):
        self.last_event = event

    def exited(self, event):
        self.last_event = None  # Never replay an old exec/fork stop on exit.
        self.exited_inferiors.add(event.inferior.num)

    def architecture(self):
        architecture = gdb.selected_frame().architecture().name()
        if architecture not in self.exec_numbers:
            raise ValueError("unsupported native launcher architecture")
        return architecture

    def install_exec_syscalls(self):
        number = gdb.selected_inferior().num
        architecture = self.architecture()
        old = self.exec_syscall_catches.get(number)
        if old is not None and old.is_valid():
            if self.exec_syscall_arches[number] == architecture:
                return old
            old.delete()
        # Names are resolved to ABI-specific numbers at CREATION, not exec.
        # Catchpoints do not support .inferior, and GDB 17.2's .thread setter
        # asserts while rebuilding their dummy location. Use an inferior
        # condition instead: another process's i386 #11 must not become an
        # x86-64 munmap stop in the observer loop.
        before = set(gdb.breakpoints() or ())
        gdb.execute("catch syscall execve execveat", to_string=True)
        bp = next(bp for bp in gdb.breakpoints() if bp not in before)
        bp.condition = f"$_inferior == {number}"
        self.exec_syscall_catches[number] = bp
        self.exec_syscall_arches[number] = architecture
        print(f"ISAC_RETAIL_PROBE_NATIVE_ABI inferior={number} architecture={architecture} "
              f"exec_numbers={','.join(str(value) for value in sorted(self.exec_numbers[architecture]))}", flush=True)
        return bp

    def new_thread(self, event):
        # Linux syscall tracing is per process. A forked inferior received exec
        # catchpoints but NO syscall-entry stops in the regression. Install its
        # own kernel catchpoint before GDB resumes it. Selecting debugger context
        # here is only for configuration: never resume, step, call or edit regs.
        if not self.syscalls_ready:
            return  # Initial new-thread event has no readable frame yet.
        number = event.inferior_thread.inferior.num
        existing = self.exec_syscall_catches.get(number)
        if existing is not None and existing.is_valid():
            return  # New threads share this process's ABI and syscall observer.
        previous = gdb.selected_inferior().num
        thread = gdb.selected_thread()
        try:
            event.inferior_thread.switch()
            self.install_exec_syscalls()
        except (gdb.error, RuntimeError, ValueError) as error:
            self.lifecycle_error = True
            print(f"ISAC_RETAIL_PROBE_REFUSED reason=child-syscall-observer-setup kind={type(error).__name__}", flush=True)
        finally:
            if thread is not None and thread.is_valid():
                thread.switch()
            else:
                gdb.execute(f"inferior {previous}", to_string=True)

    @property
    def bootstrap(self):
        return self.bootstraps.get(gdb.selected_inferior().num)

    def breakpoint(self, address):
        bp = gdb.Breakpoint(f"*{address:#x}", type=gdb.BP_HARDWARE_BREAKPOINT, internal=False)
        bp.silent = True
        bp.inferior = self.game.num if self.game is not None else gdb.selected_inferior().num
        return bp

    def verify_bootstrap(self, inferior):
        # A single address-only bootstrap slot can be armed before PE loading.
        # Attest on hit; do not treat this unverified guard as producer evidence.
        signature = NAME_SITES["owner_constructed"][1]
        if bytes(inferior.read_memory(self.base + NAME_SITES["owner_constructed"][0], len(signature))) != signature:
            raise ValueError("bootstrap signature mismatch")
        if (Path(f"/proc/{inferior.pid}/comm").read_text().strip().lower() != "thedivision.exe"
                or bytes(inferior.read_memory(self.base, 2)) != b"MZ"):
            raise ValueError("unexpected bootstrap process")

    def initialize(self, inferior):
        self.drop_bootstrap(inferior.num)
        self.verify_bootstrap(inferior)
        self.game = inferior
        for number in list(self.bootstraps):
            self.drop_bootstrap(number)
        options = dict(thread=lambda: gdb.selected_thread().global_num,
                       seconds=180, maximum_stops=12000, maximum_events=256)
        name = NameLineageTrace(self.base, inferior.read_memory, register, self.breakpoint,
            archive_name=lambda data: archive_service_name(self.capture / "producer-private", data), **options)
        producer = ProducerTrace(self.base, inferior.read_memory, register, self.breakpoint,
            archive_fields=lambda data: archive_fields(self.capture / "producer-private", data), **options)
        self.traces = [name, producer]
        try:
            name.arm()
            producer.arm()
            name.handle("owner_constructed")
        except BaseException:
            self.retire("arm-refused")
            raise
        self.started = True
        print("ISAC_RETAIL_PROBE_READY slots=4 mode=read-only adapter=none certificate_override=none", flush=True)

    def retire(self, reason):
        for trace in self.traces:
            try:
                trace.close(reason)
            except gdb.error:
                pass  # exec can already have deleted internal breakpoints.
        for number in list(self.bootstraps):
            self.drop_bootstrap(number)

    def drop_bootstrap(self, number=None):
        if number is None:
            number = gdb.selected_inferior().num
        bp = self.bootstraps.pop(number, None)
        if bp is not None and bp.is_valid():
            bp.delete()

    def arm_bootstrap(self):
        number = gdb.selected_inferior().num
        # PE64 addresses cannot be represented by a native i386 helper. Never
        # truncate the game guard to a different address in its address space.
        if self.architecture() != "i386:x86-64":
            self.drop_bootstrap()
            return
        if self.bootstrap is not None and self.bootstrap.is_valid():
            return
        self.bootstraps[number] = self.breakpoint(self.base + NAME_SITES["owner_constructed"][0])

    def stop(self):
        if self.lifecycle_error:
            raise ValueError("child syscall observer setup failed")
        for number in self.exited_inferiors:
            self.drop_bootstrap(number)
            bp = self.exec_syscall_catches.pop(number, None)
            self.exec_syscall_arches.pop(number, None)
            if bp is not None and bp.is_valid():
                bp.delete()
        self.exited_inferiors.clear()
        for number, bp in list(self.exec_syscall_catches.items()):
            if not bp.is_valid():
                del self.exec_syscall_catches[number]
                del self.exec_syscall_arches[number]
        inferior = gdb.selected_inferior()
        event = self.last_event
        self.last_event = None  # Every recorded stop is consumed exactly once.
        if isinstance(event, gdb.BreakpointEvent):
            if any(bp in event.breakpoints for bp in self.exec_syscall_catches.values()):
                # Defense in depth: syscall names printed by GDB can describe
                # the old ABI. Trust the actual stop's number and current ABI.
                if event.details.get("syscall-number") not in self.exec_numbers[self.architecture()]:
                    raise ValueError("unexpected syscall for native architecture")
                reason = event.details.get("reason")
                if reason == "syscall-entry":
                    # Delete in the OLD address space. Deletion after exec left
                    # stale x86 debug-register mirror references in the tested
                    # GDB build, even with just one visible breakpoint.
                    if self.game is not None and inferior.num == self.game.num:
                        self.retire("game-exec-attempt")
                        self.game = None
                    if self.game is None:
                        self.drop_bootstrap()
                elif reason == "syscall-return":
                    if self.game is None:
                        self.arm_bootstrap()  # Also covers a failed exec syscall.
                else:
                    raise ValueError("exec syscall event has no entry/return classification")
                return "continue"
            if self.exec_catch in event.breakpoints or any(bp in event.breakpoints for bp in self.fork_catches):
                # Kernel catchpoints do not patch instructions or consume x86
                # hardware slots. exec-entry has already removed the old guard.
                if self.exec_catch in event.breakpoints:
                    self.install_exec_syscalls()  # Re-resolve after a 32/64-bit transition.
                    if self.game is not None and inferior.num == self.game.num:
                        self.retire("game-exec-replaced-image")
                        self.game = None
                if self.game is None:
                    self.arm_bootstrap()
                return "continue"
            if self.bootstrap is not None and self.bootstrap in event.breakpoints:
                try:
                    self.initialize(inferior)
                except (gdb.error, OSError, ValueError):
                    self.retire("bootstrap-refused")
                    print("ISAC_RETAIL_PROBE_REFUSED reason=bootstrap-or-anchor-mismatch", flush=True)
                return "continue"
            if self.game is not None and inferior.num == self.game.num:
                for trace in self.traces:
                    kind = trace.event_kind(event.breakpoints)
                    if kind is None:
                        continue
                    context = trace.producer_context if kind == "producer_written" else None
                    before = trace.producer_results
                    try:
                        trace.handle(kind)
                        if context is not None and trace.producer_results > before:
                            self.traces[1].assignment(context, trace.string_name(context["record"] + 0x358, record=True))
                    except (gdb.error, ValueError):
                        self.retire("observation-refused")
                        print("ISAC_RETAIL_PROBE_REFUSED reason=unreadable-or-inconsistent-field", flush=True)
                    return "continue"
        if isinstance(event, gdb.SignalEvent):
            if event.stop_signal == "SIGINT":
                raise KeyboardInterrupt
            if event.stop_signal == "SIGTRAP":
                return "signal SIGTRAP"
        if type(event) is gdb.StopEvent and inferior.pid:
            try:
                # GDB 17.2 emits a generic StopEvent (empty details) for native
                # INT3 and program-owned single-step traps. Under nopass a
                # plain continue silently discards them. Recognized observer
                # breakpoints were consumed above; preserve a real TRAP_TRACE
                # so Wine/the program can clear TF through its normal handler.
                signo = int(gdb.parse_and_eval("$_siginfo.si_signo"))
                code = int(gdb.parse_and_eval("$_siginfo.si_code"))
                if signo == signal.SIGTRAP and code == 2 and register("eflags") & 0x100:
                    if inferior.num not in self.trace_trap_inferiors:
                        self.trace_trap_inferiors.add(inferior.num)
                        print(f"ISAC_RETAIL_PROBE_TRAP_PASSTHROUGH inferior={inferior.num} "
                              f"architecture={self.architecture()} source=generic-stop si_code=2", flush=True)
                    return "signal SIGTRAP"
                pc = "rip" if self.architecture() == "i386:x86-64" else "eip"
                if signo == signal.SIGTRAP and code in (1, 128) and bytes(inferior.read_memory(register(pc) - 1, 1)) == b"\xcc":
                    return "signal SIGTRAP"
            except gdb.error:
                pass
        if not inferior.pid:
            for candidate in gdb.inferiors():
                if candidate.pid and candidate.threads():
                    candidate.threads()[0].switch()
                    break
        return "continue"

    def cleanup(self):
        # Only inferiors launched/traced by THIS debugger; never scan/kill Wine
        # by name, a namespace-local PID, or Steam's remembered process list.
        for inferior in gdb.inferiors():
            if inferior.pid:
                try:
                    os.kill(inferior.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def run(self):
        for command in (
            "set pagination off", "set confirm off", "set auto-load off", "set debuginfod enabled off",
            "set print thread-events off", "set print frame-arguments none", "set print entry-values no",
            "set startup-with-shell off", "set detach-on-fork off", "set follow-fork-mode parent",
            "set follow-exec-mode same",
            "set schedule-multiple on", "set non-stop off", "set breakpoint always-inserted off",
            "handle SIGTRAP stop print nopass", "handle SIGSEGV nostop noprint pass",
            "handle SIGBUS nostop noprint pass", "handle SIGUSR1 nostop noprint pass",
            "handle SIGUSR2 nostop noprint pass", "handle SIGPIPE nostop noprint pass"):
            gdb.execute(command, to_string=True)
        before = set(gdb.breakpoints() or ())
        gdb.execute("catch exec", to_string=True)
        self.exec_catch = next(bp for bp in gdb.breakpoints() if bp not in before)
        for command in ("catch fork", "catch vfork"):
            before = set(gdb.breakpoints() or ())
            gdb.execute(command, to_string=True)
            self.fork_catches.append(next(bp for bp in gdb.breakpoints() if bp not in before))
        code = 0
        try:
            # Linux GDB needs a live target before inserting execution hardware
            # breakpoints. starti stops at initial exec without a software entry
            # breakpoint, before env/Proton/Wine can run or initialize the game.
            gdb.execute("starti")
            self.syscalls_ready = True
            self.install_exec_syscalls()
            # The production inferior starts as /usr/bin/env. The first kernel
            # exec catchpoint arms the PE-address guard before Proton can run.
            gdb.execute("continue")
            while any(i.pid for i in gdb.inferiors()):
                if self.game is not None and not self.game.pid:
                    break  # Do not wait forever on a still-open Ubisoft helper.
                gdb.execute(self.stop())
            self.retire("game-exited" if self.started else "no-retail-bootstrap")
            print(f"ISAC_RETAIL_PROBE_FINISHED bootstrap_seen={int(self.started)}", flush=True)
            code = 0 if self.started else 2
        except BaseException as error:
            self.retire("debugger-interrupted-or-failed")
            print(f"ISAC_RETAIL_PROBE_ERROR reason=debugger-interrupted-or-failed kind={type(error).__name__}", flush=True)
            code = 1
        finally:
            self.cleanup()
        gdb.execute(f"quit {code}")


if __name__ == "__main__":
    Driver(os.environ["ISAC_RETAIL_PROBE_CAPTURE"]).run()
