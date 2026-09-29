"""GDB-only driver for the isolated, opt-in SDK adapter. No software game patch.

Run through steam-sdk-adapter-wrapper.sh, not by attaching to a live session.
The fixture entry point is separate and never admitted by the production wrapper.
"""
import os
from pathlib import Path
import signal
import struct
import sys
import gdb

READY = 0x4953414300010001
DONE = 0x4953414300010002
FAIL = 0x4953414300010003
ACK = 0x49534143000100AA
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def register(name):
    return int(gdb.parse_and_eval("$" + name)) & ((1 << 64) - 1)


def word(inferior, address):
    return struct.unpack("<Q", inferior.read_memory(address, 8))[0]


def private_rw(pid, address, size):
    if not address or address % 8 or size <= 0 or address + size >= 1 << 64:
        return False
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        low, high = (int(x, 16) for x in fields[0].split("-"))
        name = fields[5] if len(fields) == 6 else ""
        if low <= address and address + size <= high:
            return fields[1] == "rw-p" and (not name or name.startswith(("[heap]", "[anon:")))
    return False


def verify_isolation(inferior):
    import importlib.util
    spec = importlib.util.spec_from_file_location("isac_netns", ROOT / "tools/isac-netns.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.check_member(module.STATE_DIR)
    if os.stat(f"/proc/{inferior.pid}/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino:
        raise RuntimeError("game left the isolated network namespace")


class Driver:
    def __init__(self, isolation_check=verify_isolation, fixture=False):
        self.configs = {}
        self.last_event = None
        self.isolation_check = isolation_check
        self.fixture = fixture
        self.installed = 0
        self.transport_chain = None
        self.transport_record = None
        self.loader_record = None
        self.routing_policy = None
        self.backend_trace_requested = False
        self.backend_trace_profile = "startup"
        if not fixture and os.environ.get("ISAC_SDK_ADAPTER") == "1":
            import sdk_adapter_test as runner
            record = runner.active_record()
            if record.get("loader_overlay", False):
                self.loader_record = record
        if not fixture and os.environ.get("ISAC_SDK_TRANSPORT") == "1":
            import sdk_adapter_test as runner
            import sdk_adapter_transport as transport
            record = runner.active_record()
            if record.get("mode") != "transport":
                raise RuntimeError("Transport mode/session mismatch")
            capture = Path(record["capture"])
            if (runner.digest(capture / "hosts") != record["hosts_sha256"] or
                    runner.digest(capture / "nsswitch.conf") != record["nss_sha256"] or
                    runner.digest(capture / "bootstrap-cert.pem") != record["certificate_sha256"]):
                raise RuntimeError("Transport mount source or pinned certificate changed")
            self.transport_record = record
            self.transport_chain = transport.local_certificate_chain(capture / "bootstrap-cert.pem")
            self.backend_trace_requested = record.get("backend_trace", False) is True
            self.backend_trace_profile = record.get("backend_trace_profile", "startup")
            if self.backend_trace_profile not in ("startup", "handoff", "channel", "name-lineage", "activity", "switch-path", "weapon-gate", "presentation"):
                raise RuntimeError("Invalid backend trace profile")
        gdb.events.stop.connect(self.stopped)

    def stopped(self, event):
        self.last_event = event  # No context mutation inside event/stop callbacks.

    def verify(self, inferior):
        self.isolation_check(inferior)
        if self.loader_record is not None:
            import sdk_adapter_transport as transport
            transport.verify_loader_view(inferior.pid, self.loader_record)
        if self.transport_record is not None:
            import sdk_adapter_transport as transport
            policy = transport.verify_mount_view(inferior.pid, self.transport_record)
            if policy != self.routing_policy:
                print(f"ISAC_TRANSPORT_ROUTING hosts=pinned nss={policy}", flush=True)
                self.routing_policy = policy

    def stop(self):
        inferior = gdb.selected_inferior()
        if not inferior.pid:
            # Steam/Proton launch helpers can exit while a followed game child
            # is still alive. Resume a live inferior, not the exited selection.
            for candidate in gdb.inferiors():
                if candidate.pid and candidate.threads():
                    candidate.threads()[0].switch()
                    self.last_event = None
                    break
            return "continue"
        event = self.last_event
        config = self.configs.get(inferior.num)
        if isinstance(event, gdb.BreakpointEvent) and config and config.get("backend_trace"):
            trace = config["backend_trace"]
            kind = trace.event_kind(event.breakpoints)
            if kind:
                if config.get("busy"):
                    raise RuntimeError("backend trace hit during adapter installation")
                if trace.stops % 64 == 0:
                    self.verify(inferior)
                try:
                    trace.handle(kind)
                except (gdb.error, ValueError, RuntimeError):
                    # Diagnostic failure must not change the game's behavior.
                    # No raw memory, argument contents or exception text logged.
                    trace.close("unreadable-or-unexpected-state")
                return "continue"
        if (isinstance(event, gdb.BreakpointEvent) and config and
                config.get("certificate_breakpoint") in event.breakpoints):
            import sdk_adapter_transport as transport
            self.verify(inferior)
            if config.get("busy") or register("rip") != config["base"] + transport.CERT_RVA:
                raise RuntimeError("Unexpected local certificate stop")
            if bytes(inferior.read_memory(register("rip"), len(transport.CERT_SIGNATURE))) != transport.CERT_SIGNATURE:
                raise RuntimeError("Local certificate verifier signature changed")
            config["certificate_stops"] += 1
            if config["certificate_stops"] > 256:
                raise RuntimeError("Local certificate stop limit reached")
            matched = False
            try:
                matched = transport.certificate_matches(inferior.read_memory,
                    chain=self.transport_chain, end=register("rdi"), total=register("r14d"),
                    consumed=register("r15d"), zero=register("r13d"))
                mode = int.from_bytes(inferior.read_memory(register("rbp") + 0x140, 4), "little")
            except gdb.MemoryError:
                mode = 0  # Never relax trust if the complete pin cannot be checked.
            result = register("eax") & 0xffffffff
            failed = result == 0 or bool(result & 0x80000000)
            applied = matched and mode != 0 and failed
            if applied:
                gdb.execute("set $rax = 1", to_string=True)
            print(f"ISAC_TRANSPORT_CERTIFICATE pinned={int(matched)} applied={int(applied)}", flush=True)
            return "continue"
        if isinstance(event, gdb.BreakpointEvent) and config and config["breakpoint"] in event.breakpoints:
            self.verify(inferior)
            if config.get("busy") or register("rip") != config["pc"] or register("rsp") % 16:
                raise RuntimeError("unexpected publication stop/stack alignment")
            facade, owner, wrapper = register("r14"), register("rbx"), register("rdi")
            for pointer, size in ((facade, 0x98), (wrapper, 0x18)):
                if not private_rw(inferior.pid, pointer, size):
                    raise RuntimeError("publication owner/wrapper is not private writable memory")
            original = word(inferior, wrapper + 16)
            if (owner != facade + 0x50 or word(inferior, owner) or word(inferior, wrapper + 8) != facade or
                    not private_rw(inferior.pid, original, 0x30)):
                raise RuntimeError("publication lifetime/ownership mismatch")
            if not self.fixture:
                base = config["base"]
                if (bytes(inferior.read_memory(config["pc"], 2)) != b"\xeb\x03" or
                        word(inferior, wrapper) != base + 0x346CF68 or word(inferior, original) != base + 0x346D628):
                    raise RuntimeError("publication instruction/vtable mismatch")
            config["busy"] = gdb.selected_thread().global_num
            config["wrapper"] = wrapper
            config["original"] = original
            gdb.execute("set scheduler-locking on", to_string=True)
            config["breakpoint"].enabled = False
            gdb.execute(f"set $rip = {config['entry']}", to_string=True)
            if bytes(inferior.read_memory(config["entry"], 1)) != b"\x90":
                raise RuntimeError("entry thunk lacks its safe single-step instruction")
            # GDB 17 otherwise mistakes a later int3 for a delayed hardware
            # trap. Step a NOP, not pushfq (which would save the debugger's TF).
            gdb.execute("stepi", to_string=True)
            if register("rip") != config["entry"] + 1:
                raise RuntimeError("entry single-step failed")
            return "continue"
        # Native int3 can be a generic StopEvent on GDB 17. Verify the actual
        # opcode rather than depending solely on SignalEvent classification.
        explicit_trap = (type(event) is gdb.StopEvent and
                         bytes(inferior.read_memory(register("rip") - 1, 1)) == b"\xcc")
        if explicit_trap or (isinstance(event, gdb.SignalEvent) and event.stop_signal == "SIGTRAP"):
            magic = register("rax")
            if magic == READY:
                if config:
                    raise RuntimeError("duplicate adapter rendezvous")
                self.verify(inferior)
                pc, entry, base = register("rcx"), register("rdx"), register("r8")
                if not pc or not entry or (not self.fixture and pc != base + 0x20FA7FF):
                    raise RuntimeError("invalid adapter rendezvous")
                if not self.fixture and word(inferior, base + 0x4849630):
                    raise RuntimeError("SDK initialized before the held bootstrap stop")
                # Explicit hardware breakpoint: no executable-byte fallback.
                bp = gdb.Breakpoint(f"*{pc:#x}", type=gdb.BP_HARDWARE_BREAKPOINT, internal=True)
                bp.inferior = inferior.num
                self.configs[inferior.num] = {"pc": pc, "entry": entry, "base": base, "breakpoint": bp}
                if self.transport_chain is not None:
                    import sdk_adapter_transport as transport
                    site = base + transport.CERT_RVA
                    if bytes(inferior.read_memory(site, len(transport.CERT_SIGNATURE))) != transport.CERT_SIGNATURE:
                        raise RuntimeError("Local certificate verifier signature mismatch")
                    cert_bp = gdb.Breakpoint(f"*{site:#x}", type=gdb.BP_HARDWARE_BREAKPOINT, internal=True)
                    cert_bp.inferior = inferior.num
                    self.configs[inferior.num].update(certificate_breakpoint=cert_bp, certificate_stops=0)
                    print("ISAC_TRANSPORT_READY trust=exact-local-certificate-pin hosts=private-overlay", flush=True)
                if self.backend_trace_requested:
                    import sdk_backend_trace
                    import sdk_tutorial_trace
                    import sdk_switch_path_trace
                    import sdk_weapon_gate_override
                    import sdk_client_presentation_trace
                    def make_trace_breakpoint(address):
                        trace_bp = gdb.Breakpoint(f"*{address:#x}", type=gdb.BP_HARDWARE_BREAKPOINT, internal=True)
                        trace_bp.inferior = inferior.num
                        return trace_bp
                    def make_trace_return_breakpoint(address):
                        trace_bp = gdb.Breakpoint(f"*{address:#x}",
                            type=gdb.BP_HARDWARE_BREAKPOINT, internal=True)
                        trace_bp.thread = gdb.selected_thread().global_num
                        return trace_bp
                    trace_class = {"handoff": sdk_backend_trace.HandoffTrace,
                                   "channel": sdk_backend_trace.ChannelTrace,
                                   "name-lineage": sdk_backend_trace.NameLineageTrace,
                                   "activity": sdk_tutorial_trace.ActivityTrace,
                                   "switch-path": sdk_switch_path_trace.SwitchPathTrace,
                                   "weapon-gate": sdk_weapon_gate_override.WeaponGateOverride,
                                   "presentation": sdk_client_presentation_trace.ClientPresentationTrace}.get(
                                       self.backend_trace_profile, sdk_backend_trace.StartupTrace)
                    options = ({"thread": lambda: gdb.selected_thread().global_num}
                               if self.backend_trace_profile in ("handoff", "channel", "name-lineage", "activity", "switch-path") else {})
                    if self.backend_trace_profile in ("weapon-gate", "presentation"):
                        if self.transport_record is None:
                            raise RuntimeError('weapon gate requires isolated transport capture')
                        private = Path(self.transport_record["capture"]) / "transport-private"
                        options.update(write=inferior.write_memory,
                                       can_write=lambda address, size: private_rw(inferior.pid, address, size),
                                       stage_marker=private / 'weapon-gate-shooting-stage.ready')
                    if self.backend_trace_profile == "name-lineage" and self.transport_record is not None:
                        private = Path(self.transport_record["capture"]) / "transport-private"
                        options["archive_name"] = lambda value: sdk_backend_trace.archive_service_name(private, value)
                    if self.backend_trace_profile == "activity":
                        options["make_return_breakpoint"] = make_trace_return_breakpoint
                    trace = trace_class(base, inferior.read_memory, register, make_trace_breakpoint,
                        emit=lambda line: print(line, flush=True), **options)
                    self.configs[inferior.num]["backend_trace"] = trace
                    trace.arm()
                gdb.execute(f"set $rax = {ACK}", to_string=True)
                print("ISAC_ADAPTER_DEBUGGER_READY hardware=1 external-ip=isolated", flush=True)
                return "continue"
            if magic == DONE:
                if (not config or config.get("busy") != gdb.selected_thread().global_num or
                        register("rdx") != config["wrapper"] or register("r8") != config["base"] or
                        word(inferior, config["wrapper"] + 16) == config["original"] or
                        not 1 <= register("rcx") <= 8):
                    raise RuntimeError("unmatched installation completion")
                config["busy"] = None
                self.installed += 1
                gdb.execute(f"set $rax = {ACK}", to_string=True)
                config["breakpoint"].enabled = True
                gdb.execute("set scheduler-locking off", to_string=True)
                print(f"ISAC_ADAPTER_INSTALLED epoch={register('rcx')} before-publication=1", flush=True)
                return "continue"
            if magic == FAIL:
                raise RuntimeError("native adapter refused the stopped installation")
            if config and config.get("busy"):
                raise RuntimeError("unexpected trap during installation")
            return "signal SIGTRAP"  # Preserve unrelated Wine/game traps.
        if config and config.get("busy"):
            raise RuntimeError("installation did not complete normally")
        return "continue"

    def run(self):
        for command in (
            "set pagination off", "set confirm off", "set auto-load off", "set debuginfod enabled off",
            "set print thread-events off", "set print frame-arguments none", "set print entry-values no",
            "set startup-with-shell off", "set detach-on-fork off", "set follow-fork-mode parent",
            "set schedule-multiple on", "set non-stop off", "set breakpoint always-inserted on",
            "handle SIGTRAP stop print nopass", "handle SIGSEGV nostop noprint pass",
            "handle SIGBUS nostop noprint pass", "handle SIGUSR1 nostop noprint pass",
            "handle SIGUSR2 nostop noprint pass", "handle SIGPIPE nostop noprint pass"):
            gdb.execute(command, to_string=True)
        try:
            gdb.execute("run")
            while any(i.pid for i in gdb.inferiors()):
                gdb.execute(self.stop())
            for config in self.configs.values():
                if config.get("backend_trace"):
                    config["backend_trace"].close("inferior-exited")
            if not self.installed:
                raise RuntimeError("no adapter installation observed; inspect SDK_ADAPTER_ERROR in the shim log")
            print(f"ISAC_ADAPTER_DEBUGGER_FINISHED installs={self.installed}", flush=True)
        except BaseException as error:
            # Never leave a stopped, partially installed child running untraced.
            # These are exclusively descendants launched by this GDB session.
            print(f"ISAC_ADAPTER_DEBUGGER_ERROR {error}", flush=True)
            for inferior in gdb.inferiors():
                if inferior.pid:
                    try:
                        os.kill(inferior.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            gdb.execute("quit 1")


if __name__ == "__main__":
    Driver().run()
