"""Read-only, two-slot startup trace for the hash-attested main client.

Addresses/signatures from runtime text dc921cc2...eefb74. No code writes,
inferior calls, return-address breakpoints, general payload reads or register edits.
Name lineage reads only the identified bounded service-name fields, not tickets.
The GDB driver supplies memory/register access and hardware-only breakpoints.
"""
import time
import hashlib
import os
import stat

NAME_SITES = {
    "owner_constructed": (0x2F765, bytes.fromhex("48 8b 6c 24 78 48 8b b4")),
    "name_init": (0x5FC1B, bytes.fromhex("48 85 f6 0f 84 cf 00 00")),
    "registry_count": (0x5FD20, bytes.fromhex("85 c0 0f 84 af 00 00 00")),
    "matched_count": (0x5FDD7, bytes.fromhex("8b 7d b8 85 ff 74 43 48")),
    "selected_source": (0x5FE04, bytes.fromhex("48 8b 08 48 81 c1 58 03")),
    "automatic_copy": (0x5FE1C, bytes.fromhex("e8 9f d9 fb ff 48 8b 4d")),
    "preferred_lookup": (0x5FC3B, bytes.fromhex("84 c0 0f 84 fb 01 00 00")),
    "preferred_parse": (0x5FC5E, bytes.fromhex("84 c0 0f 84 d8 01 00 00")),
    "preferred_resolve": (0x5FC88, bytes.fromhex("48 8b 8d 28 02 00 00 48")),
    "preferred_copy": (0x5FCCC, bytes.fromhex("e8 ef da fb ff e9 68 01")),
    "name_gate": (0x5FE48, bytes.fromhex("84 c0 74 04 32 db eb 28")),
    "producer_copy": (0x8B6D1, bytes.fromhex("e8 ea 20 f9 ff 48 8b 8d")),
    "producer_written": (0x8B6D6, bytes.fromhex("48 8b 8d 00 03 00 00 48")),
}


def archive_service_name(directory, data):
    """Preserve only a complete nonempty service identifier in private artifacts."""
    if not 1 <= len(data) <= 63 or b"\0" in data:
        raise ValueError("invalid bounded service name")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("unsafe private trace directory")
        try:
            os.mkdir("service-names", 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        folder = os.open("service-names", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(folder)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("unsafe service-name directory")
            filename = hashlib.sha256(data).hexdigest() + ".bin"
            try:
                fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
            except FileExistsError:
                fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=folder)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                            or stream.read(64) != data):
                        raise ValueError("unsafe or inconsistent service-name artifact")
            else:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
        finally:
            os.close(folder)
    finally:
        os.close(parent)

SITES = {
    "version": (0x22486D1, bytes.fromhex("84 c0 0f 85 31 ff ff ff")),
    "error": (0x22475E0, bytes.fromhex("48 89 5c 24 08 57 48 83 ec 20")),
    # Common dispatch entry: initial read AND subsequent drain-loop messages.
    # Reached only after the transport read returned true; parser is valid.
    "poll": (0x9A070, bytes.fromhex("48 8d 8f f0 00 00 00")),
    "settings": (0x9A0F3, bytes.fromhex("eb 12 48 8d 54 24 20")),
    "registration": (0xAF36D, bytes.fromhex("80 b9 3a 05 00 00 00")),
}
HANDOFF_SITES = {
    "frontend": (0x185DAF0, bytes.fromhex("80 be aa 29 00 00 00 0f")),
    "channel": (0x5C337, bytes.fromhex("8b 4d 38 ff c9 0f 84 b7")),
    "channel_result": (0x5C523, bytes.fromhex("48 8d 8c 24 10 01 00 00")),
}
CHANNEL_SITES = {
    "channel": HANDOFF_SITES["channel"],
    "channel_result": HANDOFF_SITES["channel_result"],
    "selector_count": (0x9C443, bytes.fromhex("85 c0 0f 84 dc 00 00 00")),
    "candidate": (0x9C461, bytes.fromhex("44 39 63 5c 0f 85 a2 00")),
    "candidate_filter": (0x9C48C, bytes.fromhex("84 c0 75 7d 4c 39 7b 60")),
    "selector_iteration": (0x9C518, bytes.fromhex("3b e8 0f 82 30 ff ff ff")),
    "selector_result": (0x5C355, bytes.fromhex("48 8b f8 48 85 c0 75 37")),
    "setup": (0x5FBAE, bytes.fromhex("49 8b 4d 50 48 85 c9 0f")),
    "transport_check": (0x5FBC1, bytes.fromhex("84 c0 0f 85 dd 02 00 00")),
    "prepared_name": (0x5FE48, bytes.fromhex("84 c0 74 04 32 db eb 28")),
    "registration": (0xAF36D, bytes.fromhex("80 b9 3a 05 00 00 00 4d")),
    "registration_result": (0x5FE75, bytes.fromhex("0f b6 d8 48 8b 4d 98 48")),
    "channel_check": (0x5C3DE, bytes.fromhex("84 c0 0f 84 3b 01 00 00")),
}
# Attest the stack adjustments used to correlate nested observations, and the
# empty-string predicate whose AL result is observed (never call it ourselves).
CHANNEL_AUXILIARY = {
    0x9C3E0: bytes.fromhex("48 8b c4 53 48 81 ec b0 00 00 00"),
    0x2F790: bytes.fromhex("48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 48 89 7c 24 20 41 54 41 56 41 57 48 83 ec 30"),
    0x5FB10: bytes.fromhex("4c 89 4c 24 20 4c 89 44 24 18 55 53 56 57 41 54 41 55 41 56 48 8d ac 24 20 fe ff ff 48 81 ec e0 02 00 00"),
    0xAF360: bytes.fromhex("4c 89 44 24 18 55 57 41 56 48 83 ec 40"),
    0x14C20: bytes.fromhex("48 83 ec 28 48 8b 01 ff 50 10 33 c9 38 08 0f 94 c0 48 83 c4 28 c3"),
}
GETTERS = {
    0x12920: (0x48, bytes.fromhex("48 8b 41 48 c3")),
    0x12940: (0x408, bytes.fromhex("48 8b 81 08 04 00 00 c3")),
    0x12960: (0x88, bytes.fromhex("48 8b 81 88 00 00 00 c3")),
    0x12980: (0x808, bytes.fromhex("48 8b 81 08 08 00 00 c3")),
}
NAME_AUXILIARY = {
    0x12920: GETTERS[0x12920][1],
    0x69160: bytes.fromhex("48 8b 41 30 c3"),
    0x5B9D0: bytes.fromhex("8b 41 08 c3"),
    0x2F500: bytes.fromhex("48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 41 56 41 57 48 83 ec 50"),
    0x5FB10: CHANNEL_AUXILIARY[0x5FB10],
    0x14C20: CHANNEL_AUXILIARY[0x14C20],
    0x225843A: bytes.fromhex("66 83 7a 10 05 48 8b da"),
    0x2258461: bytes.fromhex("41 b8 40 00 00 00 48 8b d7 48 8b cb e8 7e 93 dc fd"),
}
NAME_GETTER_RVAS = {"temporary": 0x12920, "record": 0x69160, "collection": 0x5B9D0}
ERROR_NAMES = {5: "length-header", 6: "header-read", 7: "type-read",
               8: "decompression", 14: "version-read", 15: "version-mismatch",
               16: "version-after-application"}


def number(read, address, size):
    data = bytes(read(address, size))
    if len(data) != size:
        raise ValueError("short trace memory read")
    return int.from_bytes(data, "little")


class StartupTrace:
    def __init__(self, base, read, register, make_breakpoint, emit=print,
                 now=time.monotonic, maximum_stops=4096, maximum_events=128, seconds=90):
        self.base, self.read, self.register = base, read, register
        self.make_breakpoint, self.emit, self.now = make_breakpoint, emit, now
        self.maximum_stops, self.maximum_events, self.seconds = maximum_stops, maximum_events, seconds
        self.started = now()
        self.stops = self.events = 0
        self.breakpoints = {}
        self.objects = {}
        self.last_poll = {}
        self.pending = {}
        self.settings_seen = False
        self.version_seen = False
        self.registrations = 0
        self.closed = False
        self.sites = SITES
        self.profile = "startup"
        self.initial_sites = ("error", "version")
        self.auxiliary_signatures = {}
        self.payload_policy = "none"

    def log(self, kind, fields):
        if self.events >= self.maximum_events:
            self.close("event-limit")
            return
        self.events += 1
        self.emit(f"ISAC_BACKEND_TRACE_{kind} {fields}")

    def identifier(self, address):
        if not address:
            raise ValueError("null trace object")
        if address not in self.objects:
            if len(self.objects) >= 32:
                raise ValueError("trace object limit")
            self.objects[address] = len(self.objects) + 1
        return self.objects[address]

    def arm(self):
        # Validate all possible relocation sites before enabling either slot.
        signatures = list(self.sites.values())
        signatures += list(self.auxiliary_signatures.items())
        if self.profile == "handoff":
            signatures += [(rva, signature) for rva, (_, signature) in GETTERS.items()]
        for rva, signature in signatures:
            if bytes(self.read(self.base + rva, len(signature))) != signature:
                raise ValueError(f"backend trace signature mismatch at RVA {rva:#x}")
        try:
            # Errors must be covered even if decompression/header parsing
            # fails before any version verdict or application dispatch.
            for site in self.initial_sites:
                self.replace(None, site)
        except BaseException:
            self.close("arm-failed")
            raise
        self.log("READY", f"profile={self.profile} hardware_slots=2 mode=read-only payloads={self.payload_policy} "
                 f"max_stops={self.maximum_stops} max_events={self.maximum_events} seconds={self.seconds}")

    def replace(self, old, new):
        # Delete first: adapter + certificate already occupy the other slots.
        if old is not None:
            self.breakpoints.pop(old).delete()
        self.breakpoints[new] = self.make_breakpoint(self.base + self.sites[new][0])

    def close(self, reason):
        if self.closed:
            return
        self.closed = True
        for bp in list(self.breakpoints.values()):
            bp.delete()
        self.breakpoints.clear()
        self.emit(f"ISAC_BACKEND_TRACE_END reason={reason} stops={self.stops} events={self.events} "
                  f"profile={self.profile} " + self.completion_fields())

    def completion_fields(self):
        return (f"main_version_seen={int(self.version_seen)} settings_seen={int(self.settings_seen)} "
                f"registration_calls={self.registrations}")

    def event_kind(self, breakpoints):
        return next((name for name, bp in self.breakpoints.items() if bp in breakpoints), None)

    def snapshot(self, owner):
        read = self.read
        transport = number(read, owner + 0x50, 8)
        return (self.identifier(owner), self.identifier(transport),
                number(read, owner + 0x53A, 1), number(read, owner + 0x53B, 1),
                number(read, transport + 0xB8, 4), number(read, transport + 0xBC, 4),
                number(read, transport + 0xD0, 4), number(read, transport + 0x15C, 1),
                number(read, transport + 0x15D, 1))

    @staticmethod
    def fields(state):
        owner, transport, waiting, policy, status, version, error, compression, alternate = state
        return (f"owner={owner} transport={transport} waiting_settings={waiting} policy_enabled={policy} "
                f"transport_state={status} expected_version={version} stored_error={error} "
                f"compression={compression} alternate_transport={alternate}")

    def begin(self, kind):
        if self.closed:
            return False
        self.stops += 1
        if self.stops > self.maximum_stops or self.now() - self.started >= self.seconds:
            self.close("stop-or-time-limit")
            return False
        rva, signature = self.sites[kind]
        if self.register("rip") != self.base + rva or bytes(self.read(self.base + rva, len(signature))) != signature:
            raise ValueError("unexpected backend trace site")
        return True

    def handle(self, kind):
        if not self.begin(kind):
            return
        reg, read = self.register, self.read
        if kind == "version":
            transport = reg("rbx")
            expected = number(read, transport + 0xBC, 4)
            actual = number(read, reg("rsp") + 0x30, 4)
            accepted = reg("rax") & 255
            self.log("VERSION", f"transport={self.identifier(transport)} expected={expected} received={actual} accepted={int(bool(accepted))}")
            if expected == 2056 and not self.closed:
                self.version_seen = True
                self.replace("version", "poll")
        elif kind == "error":
            code = reg("rdx") & 0xffffffff
            transport = reg("rcx")
            expected = number(read, transport + 0xBC, 4)
            self.log("ERROR", f"transport={self.identifier(transport)} expected_version={expected} "
                     f"code={code} name={ERROR_NAMES.get(code, 'unmapped')}")
        elif kind == "poll":
            owner = reg("rdi")
            state = self.snapshot(owner)
            type_id = number(read, reg("rsp") + 0x30, 2)
            key = (*state, type_id)
            if self.last_poll.get(owner) != key:
                self.log("POLL", self.fields(state) + f" message_available=1 type={type_id}")
                self.last_poll[owner] = key
            if type_id == 7 and not self.closed:
                self.pending[owner] = state[2]
                self.replace("poll", "settings")
        elif kind == "settings":
            owner = reg("rdi")
            state = self.snapshot(owner)
            before = self.pending.pop(owner, None)
            result = bool(reg("rax") & 255)
            self.settings_seen = True
            self.log("SETTINGS", self.fields(state) + f" consumer_result={int(result)} waiting_before={before}")
            if not self.closed:
                # After the startup gate is observed open, use that same slot
                # to see actual registration attempts, not just infer readiness.
                self.replace("settings", "registration" if result and not state[2] else "poll")
        elif kind == "registration":
            self.registrations += 1
            self.log("REGISTRATION", self.fields(self.snapshot(reg("rcx"))) +
                     " arguments=not-read result=not-observed")


class HandoffTrace(StartupTrace):
    """Frontend plus paired channel gate/result, from launch; no transport edits."""

    def __init__(self, *args, thread=lambda: 0, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = "handoff"
        self.sites = HANDOFF_SITES
        self.initial_sites = ("frontend", "channel")
        self.thread = thread
        self.last_frontend = {}
        self.channel_pending = {}
        self.frontend_stops = self.channel_calls = self.channel_results = 0

    def completion_fields(self):
        return (f"frontend_stops={self.frontend_stops} channel_calls={self.channel_calls} "
                f"channel_results={self.channel_results} pending_results={len(self.channel_pending)}")

    def scalar(self, address, size):
        if not address or address < 0 or address + size >= 1 << 64:
            return -1
        try:
            return number(self.read, address, size)
        except Exception:
            return -1  # Unknown is not false; never print exception/payload text.

    def pointer(self, owner, offset):
        return self.scalar(owner + offset, 8) if owner > 0 else -1

    def field(self, owner, offset, size=4):
        return self.scalar(owner + offset, size) if owner > 0 else -1

    def present(self, owner, offset):
        value = self.pointer(owner, offset)
        return -1 if value < 0 else int(bool(value))

    def nonempty(self, owner, offset):
        if owner <= 0:
            return -1
        table = self.pointer(owner, offset)
        getter = self.pointer(table, 0x10)
        layout = GETTERS.get(getter - self.base)
        if layout is None:
            return -1
        data = self.pointer(owner, offset + layout[0])
        first = self.scalar(data, 1)
        return -1 if first < 0 else int(bool(first))

    def handle(self, kind):
        if not self.begin(kind):
            return
        reg = self.register
        if kind == "frontend":
            self.frontend_stops += 1
            owner = reg("rsi")
            services = self.pointer(owner, 0x60)
            auth = self.pointer(owner, 0x68)
            client = self.pointer(auth, 0x1128)
            manager = self.pointer(client, 0)
            state = {
                "frontend": self.identifier(owner),
                "services_state": self.field(services, 0x220),
                "auth_state": self.field(auth, 0x1124),
                "services330_nonempty": self.nonempty(services, 0x330),
                "services_ticket_present": self.nonempty(services, 0x228),
                "auth_ticket_present": self.nonempty(auth, 0xF50),
                "auth_ea0_nonempty": self.nonempty(auth, 0xEA0),
                "auth_flag10": self.field(auth, 0x10, 1),
                "ticket_changed": self.field(auth, 0xFA8, 1),
                "auth_flag1120": self.field(auth, 0x1120, 1),
                "suppress_auth": self.field(owner, 0x29A8, 1),
                "suppress_copy": self.field(owner, 0x29AA, 1),
                "auth_client_present": self.present(auth, 0x1128),
                "pending_ticket_login": self.present(client, 0x28),
                "channel_present": self.present(client, 8),
                "manager_state": self.field(manager, 0x38),
            }
            if self.last_frontend.get(owner) != state:
                self.log("FRONTEND", " ".join(f"{key}={value}" for key, value in state.items()))
                self.last_frontend[owner] = state
        elif kind == "channel":
            self.channel_calls += 1
            manager = reg("rbp")
            output = reg("r14")
            key = (self.thread(), reg("rsp"))
            self.channel_pending[key] = (manager, output, reg("r15") & 0xffffffff, reg("r12") & 0xffffffff)
            state = self.channel_pending[key]
            self.log("CHANNEL", f"manager={self.identifier(manager)} manager_state={self.field(manager, 0x38)} "
                     f"kind={state[2]} channel_param={state[3]} thread={key[0]}")
            if not self.closed:
                self.replace("channel", "channel_result")
        elif kind == "channel_result":
            self.channel_results += 1
            key = (self.thread(), reg("rsp"))
            context = self.channel_pending.pop(key, None)
            if context is None:
                self.log("CHANNEL_RESULT", f"thread={key[0]} paired=0 result={int(bool(reg('rbx') & 255))} "
                         "output_present=-1")
            else:
                manager, output, selector, parameter = context
                channel = self.scalar(output, 8)
                linked_owner = self.pointer(channel, 0x58)
                self.log("CHANNEL_RESULT", f"manager={self.identifier(manager)} manager_state={self.field(manager, 0x38)} "
                         f"kind={selector} channel_param={parameter} paired=1 "
                         f"result={int(bool(reg('rbx') & 255))} output_present={-1 if channel < 0 else int(bool(channel))} "
                         f"channel_state={self.field(channel, 0x90)} channel_error={self.field(channel, 0x94)} "
                         f"channel_owner_present={-1 if linked_owner < 0 else int(bool(linked_owner))} thread={key[0]}")
            if context is not None and not self.closed:
                # Fixed function tail, not an inferred stack return address.
                self.replace("channel_result", "channel")


class ChannelTrace(HandoffTrace):
    """One paired call at a time: selection, preparation, and final result.

    The fixed outer tail stays armed; the other slot follows attested branches.
    Other threads/stack frames cannot advance that slot. A paired tail recovers
    even if an intermediate checkpoint was not reached. Only numeric/presence
    observations are retained, and identical complete decisions are suppressed.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = "channel"
        self.sites = CHANNEL_SITES
        self.auxiliary_signatures = CHANNEL_AUXILIARY
        self.initial_sites = ("channel_result", "channel")
        self.context = None
        self.last_routes = {}
        self.routes = self.ignored = self.unpaired_results = 0
        self.slot = "channel"

    def completion_fields(self):
        return (f"channel_calls={self.channel_calls} channel_results={self.channel_results} "
                f"changed_routes={self.routes} pending_results={int(self.context is not None)} "
                f"ignored_hits={self.ignored} unpaired_results={self.unpaired_results}")

    def follow(self, site):
        if not self.closed and site != self.slot:
            self.replace(self.slot, site)
            self.slot = site

    def paired(self, kind):
        context = self.context
        if context is None or self.thread() != context["thread"]:
            return False
        offset = (0xC0 if kind in ("selector_count", "candidate", "candidate_filter", "selector_iteration")
                  else 0x3D0 if kind == "registration"
                  else 0x370 if kind in ("setup", "transport_check", "prepared_name", "registration_result")
                  else 0)
        return self.register("rsp") == context["stack"] - offset

    def owner_state(self, owner):
        transport = self.pointer(owner, 0x50)
        return {"transport_present": -1 if transport < 0 else int(bool(transport)),
                "transport_state": self.field(transport, 0xB8),
                "expected_version": self.field(transport, 0xBC),
                "transport_error": self.field(transport, 0xD0),
                "waiting_settings": self.field(owner, 0x53A, 1),
                "policy_enabled": self.field(owner, 0x53B, 1)}

    def handle(self, kind):
        if not self.begin(kind):
            return
        reg = self.register
        if kind == "channel":
            self.channel_calls += 1
            state = {"manager": self.identifier(reg("rbp")),
                     "manager_state": self.field(reg("rbp"), 0x38),
                     "kind": reg("r15") & 0xffffffff, "channel_param": reg("r12") & 0xffffffff,
                     "candidate_count": -1, "candidates_seen": 0, "kind_matches": 0,
                     "kind_mismatches": 0, "filter_rejections": 0, "eligible_new": 0,
                     "reusable_seen": 0, "selector_present": -1, "selected_port": -1,
                     "selected_kind": -1, "linked_owner_present": -1,
                     "setup_seen": 0, "transport_present": -1, "transport_state": -1,
                     "expected_version": -1, "transport_error": -1, "waiting_settings": -1,
                     "policy_enabled": -1, "transport_rejected": -1, "prepared_name_empty": -1,
                     "registration_seen": 0, "registration_result": -1,
                     "channel_rejected": -1, "channel_state": -1, "channel_error": -1}
            self.context = {"thread": self.thread(), "stack": reg("rsp"), "output": reg("r14"),
                            "manager": reg("rbp"), "owner": -1, "candidate": -1, "state": state}
            self.follow("selector_count" if state["manager_state"] == 2 else "channel_check")
            return
        if not self.paired(kind):
            self.ignored += 1
            if kind == "channel_result":
                self.unpaired_results += 1
            return
        context, state = self.context, self.context["state"]
        if kind == "channel_result":
            self.channel_results += 1
            channel = self.scalar(context["output"], 8)
            state.update(result=int(bool(reg("rbx") & 255)),
                         output_present=-1 if channel < 0 else int(bool(channel)))
            # If construction's check was not reached, do not turn unknown
            # channel fields into a fabricated failure state.
            key = (state["manager"], state["kind"], state["channel_param"])
            self.context = None  # The paired result has been observed, even if logging retires us.
            if self.last_routes.get(key) != state:
                self.routes += 1
                self.log("CHANNEL_ROUTE", " ".join(f"{k}={v}" for k, v in state.items()) +
                         f" paired=1 thread={context['thread']}")
                self.last_routes[key] = state.copy()
            self.follow("channel")
        elif kind == "selector_count":
            if reg("r13") != context["manager"]:
                self.ignored += 1
                return
            state["candidate_count"] = reg("rax") & 0xffffffff
            self.follow("candidate" if state["candidate_count"] else "selector_result")
        elif kind == "candidate":
            context["candidate"] = reg("rbx")
            state["candidates_seen"] += 1
            candidate_kind = self.field(context["candidate"], 0x5C)
            if candidate_kind < 0:
                self.follow("selector_result")
            elif candidate_kind == state["kind"]:
                state["kind_matches"] += 1
                self.follow("candidate_filter")
            else:
                state["kind_mismatches"] += 1
                self.follow("selector_iteration")
        elif kind == "candidate_filter":
            if reg("rbx") != context["candidate"]:
                self.ignored += 1
                return
            rejected = bool(reg("rax") & 255)
            connection = self.pointer(context["candidate"], 0x60)
            if rejected:
                state["filter_rejections"] += 1
                self.follow("selector_iteration")
            elif connection > 0:
                state["reusable_seen"] += 1
                self.follow("selector_result")
            elif connection == 0:
                state["eligible_new"] += 1
                self.follow("selector_iteration")
            else:
                self.follow("selector_result")
        elif kind == "selector_iteration":
            self.follow("candidate" if (reg("rbp") & 0xffffffff) < (reg("rax") & 0xffffffff)
                        else "selector_result")
        elif kind == "selector_result":
            selected = reg("rax")
            state["selector_present"] = int(bool(selected))
            state["selected_port"] = self.field(selected, 0x58, 2)
            state["selected_kind"] = self.field(selected, 0x5C)
            context["owner"] = self.pointer(selected, 0x60)
            state["linked_owner_present"] = -1 if context["owner"] < 0 else int(bool(context["owner"]))
            self.follow("setup" if selected else "channel_check")
        elif kind == "setup":
            if reg("r13") != context["owner"]:
                self.ignored += 1
                return
            state["setup_seen"] = 1
            state.update(self.owner_state(context["owner"]))
            self.follow("transport_check" if state["transport_present"] == 1 else "channel_check")
        elif kind == "transport_check":
            state["transport_rejected"] = int(bool(reg("rax") & 255))
            self.follow("channel_check" if state["transport_rejected"] else "prepared_name")
        elif kind == "prepared_name":
            state["prepared_name_empty"] = int(bool(reg("rax") & 255))
            self.follow("channel_check" if state["prepared_name_empty"] else "registration")
        elif kind == "registration":
            if reg("rcx") != context["owner"]:
                self.ignored += 1
                return
            state["registration_seen"] = 1
            state.update(self.owner_state(context["owner"]))
            self.follow("registration_result")
        elif kind == "registration_result":
            state["registration_result"] = int(bool(reg("rax") & 255))
            self.follow("channel_check")
        elif kind == "channel_check":
            channel = self.scalar(context["output"], 8)
            state["channel_rejected"] = int(bool(reg("rax") & 255))
            state["channel_state"] = self.field(channel, 0x90)
            state["channel_error"] = self.field(channel, 0x94)
            # Stay here until the permanent outer tail; never guess a return PC.


class NameLineageTrace(HandoffTrace):
    """Observe the two name-copy sites and their normal type-5 producer.

    Slot A follows the temporary string's initialization -> source -> gate.
    Slot B pairs the record+0x358 assignment before/after from launch. These
    are assignment-path breakpoints, not patches, and no virtual calls are made.
    Only the identified name fields are read (max 63 bytes plus terminator).
    Public output uses hashes; optional private archival preserves exact names.
    """

    def __init__(self, *args, archive_name=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = "name-lineage"
        self.payload_policy = "service-name-fields-only"
        self.sites = NAME_SITES
        self.initial_sites = ("owner_constructed", "producer_copy")
        self.auxiliary_signatures = NAME_AUXILIARY
        self.name_slot, self.producer_slot = self.initial_sites
        self.name_context = self.producer_context = None
        self.archive_name = archive_name
        self.last_names = {}
        self.name_calls = self.name_results = self.producer_calls = self.producer_results = self.ignored = 0

    def completion_fields(self):
        return (f"name_calls={self.name_calls} name_results={self.name_results} "
                f"producer_calls={self.producer_calls} producer_results={self.producer_results} "
                f"pending_name={int(self.name_context is not None)} "
                f"pending_producer={int(self.producer_context is not None)} ignored_hits={self.ignored}")

    def follow_name(self, site):
        if not self.closed and site != self.name_slot:
            self.replace(self.name_slot, site)
            self.name_slot = site

    def follow_producer(self, site):
        if not self.closed and site != self.producer_slot:
            self.replace(self.producer_slot, site)
            self.producer_slot = site

    def name_data_pointer(self, string, getter_rva, offset):
        table = self.pointer(string, 0)
        if self.pointer(table, 0x10) != self.base + getter_rva:
            return -1
        return self.pointer(string, offset)

    def bounded_name(self, pointer):
        if pointer <= 0:
            return None
        data = bytearray()
        for offset in range(64):
            byte = self.scalar(pointer + offset, 1)
            if byte < 0:
                return None
            if not byte:
                return bytes(data)
            data.append(byte)
        return None  # Never record a truncated name as the actual value.

    def string_name(self, string, record=False):
        return self.bounded_name(self.name_data_pointer(string, NAME_GETTER_RVAS["record" if record else "temporary"],
                                                       0x30 if record else 0x48))

    def name_fields(self, data):
        if data is None:
            return {"length": -1, "sha256": "unknown"}
        return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def archive(self, data):
        if data and self.archive_name is not None:
            try:
                self.archive_name(data)
            except OSError:
                # The driver retires the observer on ValueError; an artifact
                # failure must not escape into its fatal game-error handler.
                raise ValueError("service-name archival unavailable") from None

    def registry_count(self, owner):
        collection = owner + 0xB8 if owner > 0 else -1
        table = self.pointer(collection, 0)
        if self.pointer(table, 0x70) != self.base + NAME_GETTER_RVAS["collection"]:
            return -1
        return self.field(collection, 8)

    def paired(self, context):
        return (context is not None and context["thread"] == self.thread()
                and context["stack"] == self.register("rsp"))

    def handle(self, kind):
        if not self.begin(kind):
            return
        reg = self.register
        if kind == "owner_constructed":
            owner = reg("rbx")
            self.log("NAME_OWNER", f"owner={self.identifier(owner)} initialized_registry_count={self.registry_count(owner)}")
            self.follow_name("name_init")
            return
        if kind == "producer_copy":
            self.producer_calls += 1
            record, owner = reg("rcx") - 0x358, reg("r14")
            # Consumer-local slot must identify the same destination record.
            if self.scalar(reg("rbp") + 0x300, 8) != record:
                self.ignored += 1
                return
            source = self.bounded_name(reg("rdx"))
            self.producer_context = {"thread": self.thread(), "stack": reg("rsp"),
                                     "record": record, "owner": owner, "source": source,
                                     "before": self.string_name(record + 0x358, record=True)}
            self.follow_producer("producer_written")
            return
        if kind == "producer_written":
            context = self.producer_context
            if not self.paired(context) or self.scalar(reg("rbp") + 0x300, 8) != context["record"]:
                self.ignored += 1
                return
            self.producer_results += 1
            value = self.string_name(context["record"] + 0x358, record=True)
            fields = self.name_fields(value)
            equal = -1 if context["source"] is None or value is None else int(context["source"] == value)
            before = -1 if context["before"] is None else int(not context["before"])
            self.archive(value)
            self.producer_context = None
            self.log("NAME_PRODUCER", f"owner={self.identifier(context['owner'])} record={self.identifier(context['record'])} "
                     f"root_type=5 field_offset=856 before_empty={before} copy_equal={equal} "
                     + " ".join(f"{key}={val}" for key, val in fields.items()))
            self.follow_producer("producer_copy")
            return
        if kind == "name_init":
            self.name_calls += 1
            owner, temporary = reg("r13"), reg("rsp") + 0x50
            initial = self.string_name(temporary)
            state = {"owner": self.identifier(owner), "initial_empty": -1 if initial is None else int(not initial),
                     "channel_param": self.field(reg("r14") - 8, 0x50),
                     "registry_count": self.registry_count(owner), "preferred_present": int(bool(reg("rsi"))),
                     "matched_count": -1, "preferred_lookup": -1, "preferred_parse": -1,
                     "source_record": 0, "source_copy_seen": 0, "source_pointer_equal": -1,
                     "source_length": -1, "source_sha256": "unknown"}
            self.name_context = {"thread": self.thread(), "stack": reg("rsp"), "owner": owner,
                                 "temporary": temporary, "record": -1, "source": None, "state": state}
            self.follow_name("preferred_lookup" if state["preferred_present"] else "registry_count")
            return
        context = self.name_context
        if not self.paired(context):
            self.ignored += 1
            return
        state = context["state"]
        if kind == "registry_count":
            state["registry_count"] = reg("rax") & 0xffffffff
            self.follow_name("matched_count" if state["registry_count"] else "name_gate")
        elif kind == "matched_count":
            state["matched_count"] = self.field(reg("rbp"), -0x48)
            self.follow_name("selected_source" if state["matched_count"] > 0 else "name_gate")
        elif kind == "preferred_lookup":
            state["preferred_lookup"] = int(bool(reg("rax") & 255))
            self.follow_name("preferred_parse" if state["preferred_lookup"] else "name_gate")
        elif kind == "preferred_parse":
            state["preferred_parse"] = int(bool(reg("rax") & 255))
            self.follow_name("preferred_resolve" if state["preferred_parse"] else "name_gate")
        elif kind in ("selected_source", "preferred_resolve"):
            record = (self.scalar(reg("rax"), 8) if kind == "selected_source"
                      else self.scalar(reg("rbp") + 0x228, 8))
            context["record"] = record
            state["source_record"] = self.identifier(record) if record > 0 else -1
            self.follow_name("automatic_copy" if kind == "selected_source" else "preferred_copy")
        elif kind in ("automatic_copy", "preferred_copy"):
            if reg("rcx") != context["temporary"]:
                self.ignored += 1
                return
            expected = self.name_data_pointer(context["record"] + 0x358, NAME_GETTER_RVAS["record"], 0x30) if context["record"] > 0 else -1
            state["source_pointer_equal"] = -1 if expected < 0 else int(expected == reg("rdx"))
            source = self.bounded_name(reg("rdx")) if state["source_pointer_equal"] == 1 else None
            context["source"] = source
            state["source_copy_seen"] = 1
            fields = self.name_fields(source)
            state.update(source_length=fields["length"], source_sha256=fields["sha256"])
            self.archive(source)
            self.follow_name("name_gate")
        elif kind == "name_gate":
            self.name_results += 1
            value = self.string_name(context["temporary"])
            state["gate_empty"] = int(bool(reg("rax") & 255))
            source = context["source"]
            state["copy_equal"] = -1 if source is None or value is None else int(source == value)
            fields = self.name_fields(value)
            state.update(final_length=fields["length"], final_sha256=fields["sha256"])
            key = (state["owner"], state["preferred_present"])
            self.name_context = None
            if self.last_names.get(key) != state:
                self.log("NAME_LINEAGE", " ".join(f"{key}={val}" for key, val in state.items()))
                self.last_names[key] = state.copy()
            self.follow_name("name_init")
