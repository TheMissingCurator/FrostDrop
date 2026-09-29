#!/usr/bin/env python3
"""Isolated SDK adapter test, optionally with encrypted transport bootstrap."""
import argparse
from datetime import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
ACTIVE = ROOT / "private/sdk-adapter-session.json"
TUTORIAL_PROFILE_STORE = ROOT / "private/local-profiles/tutorial-characters.sqlite3"
MODES = ("sdk", "transport", "transport-trace", "transport-handoff", "transport-channel", "transport-name-lineage", "transport-world-start", "transport-tutorial-start", "transport-tutorial-fresh", "transport-tutorial-objective", "transport-tutorial-objective-fresh", "transport-tutorial-cover", "transport-tutorial-cover-fresh", "transport-tutorial-stages", "transport-tutorial-stages-fresh", "transport-tutorial-stages-gate", "transport-tutorial-stages-gate-fresh", "transport-tutorial-stages-gate-presentation", "transport-tutorial-stages-gate-presentation-fresh", "transport-tutorial-stages-gate-dialogue", "transport-tutorial-stages-gate-dialogue-fresh")


def mode_record(mode):
    if mode not in MODES:
        raise ValueError("Invalid adapter mode")
    stages = mode in ('transport-tutorial-stages', 'transport-tutorial-stages-fresh',
                      'transport-tutorial-stages-gate', 'transport-tutorial-stages-gate-fresh',
                      'transport-tutorial-stages-gate-presentation', 'transport-tutorial-stages-gate-presentation-fresh',
                      'transport-tutorial-stages-gate-dialogue', 'transport-tutorial-stages-gate-dialogue-fresh')
    cover = stages or mode in ('transport-tutorial-cover', 'transport-tutorial-cover-fresh')
    objective = cover or mode in ('transport-tutorial-objective', 'transport-tutorial-objective-fresh')
    tutorial = objective or mode in ('transport-tutorial-start', 'transport-tutorial-fresh')
    record = {"mode": "sdk" if mode == "sdk" else "transport",
            "backend_trace": mode in ("transport-trace", "transport-handoff", "transport-channel", "transport-name-lineage", "transport-world-start") or tutorial,
            "backend_trace_profile": {"transport-handoff": "handoff", "transport-channel": "channel",
                                      "transport-name-lineage": "name-lineage",
                                      "transport-world-start": "name-lineage",
                                      "transport-tutorial-start": "activity",
                                      "transport-tutorial-fresh": "activity",
                                      "transport-tutorial-objective": "activity",
                                      "transport-tutorial-objective-fresh": "activity",
                                      "transport-tutorial-cover": "activity",
                                      "transport-tutorial-cover-fresh": "activity",
                                      "transport-tutorial-stages": "switch-path",
                                      "transport-tutorial-stages-fresh": "switch-path",
                                      "transport-tutorial-stages-gate": "weapon-gate",
                                      "transport-tutorial-stages-gate-fresh": "weapon-gate",
                                      "transport-tutorial-stages-gate-presentation": "presentation",
                                      "transport-tutorial-stages-gate-presentation-fresh": "presentation",
                                      "transport-tutorial-stages-gate-dialogue": "weapon-gate",
                                      "transport-tutorial-stages-gate-dialogue-fresh": "weapon-gate"}.get(mode, "startup"),
            "experimental_world_start": mode == 'transport-world-start' or tutorial,
            "experimental_tutorial_start": tutorial,
            "experimental_first_objective": objective,
            "experimental_cover_completion": cover,
            "experimental_stage_progression": stages}
    if 'gate-dialogue' in mode:
        record['experimental_dialogue_015a'] = True
    return record


def tutorial_profile_path(mode, capture):
    if mode in ('transport-tutorial-start', 'transport-tutorial-objective', 'transport-tutorial-cover',
                'transport-tutorial-stages', 'transport-tutorial-stages-gate',
                'transport-tutorial-stages-gate-presentation',
                'transport-tutorial-stages-gate-dialogue'):
        return TUTORIAL_PROFILE_STORE
    if mode in ('transport-tutorial-fresh', 'transport-tutorial-objective-fresh',
                'transport-tutorial-cover-fresh', 'transport-tutorial-stages-fresh',
                'transport-tutorial-stages-gate-fresh', 'transport-tutorial-stages-gate-presentation-fresh',
                'transport-tutorial-stages-gate-dialogue-fresh'):
        return Path(capture) / 'tutorial-profiles.sqlite3'
    return None


DLL = ROOT / "dist/uplay_sdk_adapter/uplay_r1_loader64.dll"
GDB = Path("/usr/bin/gdb")
GAME_HASH = "31c74abfedb52fa2ef8342e8f434d766184eca32d85ea9419bcbb46c09a6e379"
RETAIL_DLL_HASH = "df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8"
spec = importlib.util.spec_from_file_location("isac_netns", ROOT / "tools/isac-netns.py")
netns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netns)
spec = importlib.util.spec_from_file_location("sdk_adapter_transport", ROOT / "tools/sdk_adapter_transport.py")
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
spec = importlib.util.spec_from_file_location("steam_launch_environment", ROOT / "tools/steam_launch_environment.py")
launch_env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch_env)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_game(game, compat, loader_overlay=False):
    if digest(game / "thedivision.exe") != GAME_HASH:
        raise RuntimeError("Unsupported game executable")
    if not (compat / "pfx").is_dir():
        raise RuntimeError("Missing game Proton prefix")
    loader = game / "uplay_r1_loader64.dll"
    if loader_overlay:
        if loader.is_symlink() or digest(loader) != RETAIL_DLL_HASH:
            raise RuntimeError("Overlay mode requires the verified retail DLL on disk; restore or verify game files first")
        if DLL.is_symlink() or not DLL.is_file():
            raise RuntimeError("Missing regular adapter build; run build-uplay-local.sh --sdk-adapter")
    elif digest(loader) != digest(DLL):
        raise RuntimeError("Experimental adapter DLL is not installed; use manage-sdk-adapter.py install")


def active_record():
    fd = os.open(ACTIVE, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("Unsafe adapter-session record")
        record = json.loads(stream.read(8192))
    capture = Path(record["capture"]).resolve()
    if capture.parent != ROOT / "evidence" or not capture.name.endswith("-sdk-adapter-linux"):
        raise RuntimeError("Invalid adapter capture directory")
    if record["net"] != os.stat("/proc/self/ns/net").st_ino:
        raise RuntimeError("Adapter launch is outside its capture namespace")
    if record.get("mode", "sdk") not in ("sdk", "transport"):
        raise RuntimeError("Invalid adapter mode")
    if record.get("backend_trace_profile", "startup") not in ("startup", "handoff", "channel", "name-lineage", "activity", "switch-path", "weapon-gate"):
        raise RuntimeError("Invalid backend trace profile")
    if type(record.get("loader_overlay", False)) is not bool:
        raise RuntimeError("Invalid loader overlay setting")
    if type(record.get('experimental_world_start', False)) is not bool:
        raise RuntimeError('Invalid world startup setting')
    if (type(record.get('experimental_tutorial_start', False)) is not bool
            or record.get('experimental_tutorial_start', False)
            and not record.get('experimental_world_start', False)):
        raise RuntimeError('Invalid tutorial activation setting')
    if (type(record.get('experimental_first_objective', False)) is not bool
            or record.get('experimental_first_objective', False)
            and not record.get('experimental_tutorial_start', False)):
        raise RuntimeError('Invalid first-objective setting')
    if (type(record.get('experimental_cover_completion', False)) is not bool
            or record.get('experimental_cover_completion', False)
            and not record.get('experimental_first_objective', False)):
        raise RuntimeError('Invalid cover-completion setting')
    if (type(record.get('experimental_stage_progression', False)) is not bool
            or record.get('experimental_stage_progression', False)
            and not record.get('experimental_cover_completion', False)):
        raise RuntimeError('Invalid stage-progression setting')
    if (type(record.get('experimental_dialogue_015a', False)) is not bool
            or record.get('experimental_dialogue_015a', False)
            and not record.get('experimental_stage_progression', False)):
        raise RuntimeError('Invalid dialogue test setting')
    return record


def has_nonisolated_interfaces(process):
    """Prove a protected task cannot belong to an ISAC loopback-only netns.

    /proc/PID/ns/net needs ptrace permission, whereas net/dev can remain
    readable for non-dumpable desktop processes. Names alone are never used
    to exempt a process. Missing/ambiguous data and PID reuse fail closed.
    """
    try:
        birth = netns.process_start_time(process)
        with (process / "net/dev").open() as stream:
            data = stream.read(65537)
        if len(data) > 65536 or birth <= 0 or netns.process_start_time(process) != birth:
            return False
        lines = data.splitlines()
        if (len(lines) < 3 or not lines[0].startswith("Inter-|")
                or not lines[1].lstrip().startswith("face |")):
            return False
        interfaces = set()
        for line in lines[2:]:
            name, fields = line.rsplit(":", 1)
            name, counters = name.strip(), fields.split()
            if not name or name in interfaces or len(counters) != 16 or not all(x.isdecimal() for x in counters):
                return False
            interfaces.add(name)
        return "lo" in interfaces and bool(interfaces - {"lo"})
    except (OSError, ValueError, IndexError):
        return False


def archive_stale_session(proc=None):
    """Called under the isolation supervisor's exclusive session lock.

    Never replace a live or unverifiable record. Use the host /proc view,
    since the private PID namespace cannot see an earlier capture's tasks.
    """
    try:
        fd = os.open(ACTIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > 8192):
            raise RuntimeError("Unsafe existing adapter-session record; refusing recovery")
        previous = json.loads(stream.read(8193))
    if not isinstance(previous, dict):
        raise RuntimeError("Invalid existing adapter-session record; refusing recovery")
    old_net = previous.get("net")
    if type(old_net) is not int or old_net <= 0:
        raise RuntimeError("Invalid existing adapter-session namespace; refusing recovery")
    if old_net == os.stat("/proc/self/ns/net").st_ino:
        raise RuntimeError("An adapter session already exists in this namespace")
    host_proc = Path(proc if proc is not None else os.environ.get("ISAC_HOST_PROC", "/proc"))
    # Check the trusted host view is usable before interpreting absence.
    (host_proc / "self/ns/net").stat()
    for process in host_proc.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            # ISAC forbids a root launcher; managed capture tasks retain the
            # desktop UID. Unrelated system services aren't capture owners.
            if process.stat().st_uid != os.getuid():
                continue
            present = (process / "ns/net").stat().st_ino
        except FileNotFoundError:
            continue  # task exited (or has no network namespace)
        except PermissionError as error:
            if has_nonisolated_interfaces(process):
                continue
            raise RuntimeError(f"Cannot verify previous adapter-session lifetime for PID {process.name}; refusing recovery") from error
        if present == old_net:
            raise RuntimeError("Previous adapter-session namespace still has processes; close it first")
    current = ACTIVE.lstat()
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
        raise RuntimeError("Adapter-session record changed during recovery")
    archive = Path(tempfile.mkdtemp(prefix="sdk-session-stale-", dir=ACTIVE.parent)) / ACTIVE.name
    ACTIVE.rename(archive)
    print(f"Archived stale adapter-session record: {archive}", flush=True)
    return archive


def inside(game, compat, mode="sdk", command=None):
    netns.check(netns.STATE_DIR)
    overlay = command is not None
    verify_game(game, compat, loader_overlay=overlay)
    archive_stale_session()
    capture = ROOT / "evidence" / (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-sdk-adapter-linux")
    capture.mkdir(mode=0o700, parents=True)
    settings = mode_record(mode)
    world_template = None
    world_continuation = None
    agent_response = None
    character_template = None
    tutorial_activation = None
    first_objective = None
    cover_completion = None
    stage_progression = None
    next_activity = None
    dialogue_015a = None
    tutorial_profile_store = tutorial_profile_path(mode, capture)
    if settings['experimental_world_start']:
        # Freeze the validated, private template in this capture. Never infer
        # opt-in from file existence or inherit an environment toggle.
        sys.path.insert(0, str(ROOT / 'src'))
        from isac_backend.world_startup import read_template
        template = read_template(ROOT / 'private/tutorial-startup.isacwst')
        world_template = capture / 'experimental-startup.isacwst'
        fd = os.open(world_template, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(template.to_bytes())
        from isac_backend.world_continuation import read_continuation
        continuation = read_continuation(ROOT / 'private/tutorial-first-gate.isacwct')
        world_continuation = capture / 'experimental-first-gate.isacwct'
        fd = os.open(world_continuation, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(continuation.to_bytes())
        from isac_backend.world_agent import read_agent_response
        agent = read_agent_response(ROOT / 'private/tutorial-agent.isacaut')
        agent_response = capture / 'experimental-agent.isacaut'
        fd = os.open(agent_response, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(agent.to_bytes())
        from isac_backend.character_template import read_character_template
        finalization = read_character_template(ROOT / 'private/tutorial-character.isacchr')
        character_template = capture / 'experimental-character.isacchr'
        fd = os.open(character_template, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(finalization.to_bytes())
        if settings['experimental_tutorial_start']:
            from isac_backend.world_tutorial import read_tutorial_activation
            activity = read_tutorial_activation(ROOT / 'private/tutorial-start.isactsa')
            tutorial_activation = capture / 'experimental-tutorial-start.isactsa'
            fd = os.open(tutorial_activation, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(activity.to_bytes())
            if settings['experimental_first_objective']:
                source = (ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/'
                          'tutorial-private/tutorial-1200.bin')
                objective = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-first-objective.py'))['prepare'](source)
                first_objective = capture / 'experimental-first-objective.isacobj'
                fd = os.open(first_objective, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(objective.to_bytes())
                if settings['experimental_cover_completion']:
                    cover = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-cover-completion.py'))['prepare'](source)
                    cover_completion = capture / 'experimental-cover-completion.isaccvr'
                    fd = os.open(cover_completion, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(cover.to_bytes())
                    if settings['experimental_stage_progression']:
                        stage = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-stage-progression.py'))['prepare'](source)
                        stage_progression = capture / 'experimental-stage-progression.isacstg'
                        fd = os.open(stage_progression, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(fd, 'wb') as stream:
                            stream.write(stage.to_bytes())
                        handoff = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-next-activity.py'))['prepare'](source)
                        next_activity = capture / 'experimental-next-activity.isacnxt'
                        fd = os.open(next_activity, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(fd, 'wb') as stream:
                            stream.write(handoff.to_bytes())
                        if settings.get('experimental_dialogue_015a', False):
                            dialogue_body = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-next-activity.py'))['prepare_dialogue_015a'](source)
                            dialogue_015a = capture / 'experimental-dialogue-015a.bin'
                            fd = os.open(dialogue_015a, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                            with os.fdopen(fd, 'wb') as stream:
                                stream.write(dialogue_body)
    bundle = transport.prepare(capture) if settings["mode"] == "transport" else None
    record = {"game": str(game), "compat": str(compat), "capture": str(capture),
              "net": os.stat("/proc/self/ns/net").st_ino, "dll_sha256": digest(DLL),
              **settings}
    if overlay:
        shutil.copyfile(DLL, capture / "adapter-loader.dll")
        (capture / "adapter-loader.dll").chmod(0o600)
        if digest(capture / "adapter-loader.dll") != record["dll_sha256"]:
            raise RuntimeError("Adapter build changed while preparing launch")
        record["loader_overlay"] = True
    if bundle:
        record.update(hosts_sha256=digest(capture / "hosts"),
                      nss_sha256=digest(capture / "nsswitch.conf"),
                      certificate_sha256=digest(capture / "bootstrap-cert.pem"))
    fd = os.open(ACTIVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(record, stream)
    game_log = game / "project-isac-uplay-local.log"
    old_size = game_log.stat().st_size if game_log.exists() else 0
    previous_signals = {}
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    try:
        if overlay:
            for signum in (signal.SIGTERM, signal.SIGHUP):
                previous_signals[signum] = signal.signal(signum, interrupted)
        with transport.services(capture, transport.service_specs(bundle,
                                                                 profile_store=tutorial_profile_store,
                                                                 world_template=world_template,
                                                                 world_continuation=world_continuation,
                                                                 agent_response=agent_response,
                                                                 character_template=character_template,
                                                                 tutorial_activation=tutorial_activation,
                                                                 first_objective=first_objective,
                                                                 cover_completion=cover_completion,
                                                                 stage_progression=stage_progression,
                                                                 next_activity=next_activity,
                                                                 dialogue_015a=dialogue_015a)) as children:
            (capture / "integration.json").write_text(json.dumps({**record,
                "scope": ("Experimental tutorial completion, known-good close and capture-derived next safe-house activity; optional single post-handoff 0x015a candidate; close companions disabled; no side-mission unlock, rewards or simulation"
                          if stage_progression is not None else
                          "Experimental cover-gated first completion state; no later progression or simulation"
                          if cover_completion is not None else
                          "Experimental first objective display state; no trigger, progression or simulation"
                          if first_objective is not None else
                          "Experimental first tutorial activity activation; no progression or simulation"
                          if tutorial_activation is not None else
                          "Experimental typed startup, first-gate burst, agent response and local profile finalization; no simulation"
                          if world_template is not None else
                          "SDK plus certificate/directory/latency/main-channel setup; no world replay"
                          if bundle else "SDK session/configuration only; legacy world probes disabled"),
                "external_ip": "isolated", "steam_ipc": "fixed host Steam relay; not an air gap"}, indent=2))
            print(f"SDK adapter test ready. Capture: {capture}", flush=True)
            print("Local SDK backend is listening on 127.0.0.1:55003. Desktop networking can stay on.", flush=True)
            if bundle:
                print("Transport ready: certificate 27015, directory 51000, channels 55001, latency 55002.", flush=True)
            if world_template is not None:
                print('Experimental world startup enabled: known identities rebound locally; '
                      'private first-gate, agent response and profile finalization enabled; '
                      'unknown fields capture-derived; '
                      'gameplay simulation absent.', flush=True)
            if tutorial_activation is not None:
                print('First tutorial activity activation enabled after authenticated appearance '
                      'submission; objective progression is not implemented. '
                      + ('This probe uses a fresh capture-private profile database; the saved character is untouched.'
                         if mode in ('transport-tutorial-fresh', 'transport-tutorial-objective-fresh',
                                     'transport-tutorial-cover-fresh', 'transport-tutorial-stages-fresh',
                                     'transport-tutorial-stages-gate-fresh',
                                     'transport-tutorial-stages-gate-presentation-fresh',
                                     'transport-tutorial-stages-gate-dialogue-fresh') else
                         'This run reuses a dedicated local tutorial profile database.'), flush=True)
            if first_objective is not None:
                print('First-objective display test enabled: one extra dictionary update, '
                      'row-1-active update and batch flush; no timer, completion or rewards.', flush=True)
            if cover_completion is not None:
                print('Cover-completion test enabled: after a matching character/cover-entry report, '
                      'send row-1-complete/row-2-active once.', flush=True)
            if stage_progression is not None:
                print('Stage-progression test enabled: compact cover echo, bounded 0x006a replies '
                      'with per-reply flush, paired local-item equipment echoes, first-switch '
                      'acceptance, secondary-shot final row and activity closure; '
                      'no rewards.', flush=True)
            if next_activity is not None:
                print('Experimental safe-house activity handoff enabled after first tutorial closure; '
                      'known-good close and capture-derived four-row start; close companions disabled; '
                      'later PC interaction and side-mission unlock not implemented.', flush=True)
            if dialogue_015a is not None:
                print('Opt-in dialogue experiment enabled: one pinned retail 0x015a after safe-house '
                      'activity start; meaning unknown; local effect must be observed.', flush=True)
            if record["backend_trace"]:
                if record["backend_trace_profile"] == "weapon-gate":
                    print('Experimental local weapon gate override enabled after the shooting stage; '
                          'after Agent Activation closes, a later weapon-gate check may also '
                          'clear the same owner\'s running count once. These are memory-only '
                          'diagnostic overrides.', flush=True)
                elif record["backend_trace_profile"] == "switch-path":
                    print('Read-only switch-request path trace enabled; gate value is not observed.', flush=True)
                elif record["backend_trace_profile"] == "activity":
                    print("Read-only 0x00e6 parser trace enabled; retention is not observed.", flush=True)
                elif record["backend_trace_profile"] == "name-lineage":
                    print("Read-only name lineage enabled: exact temporary/source fields and type-5 assignment; nonempty service names archived privately, public logs hash-only. Local service advertisements enabled.", flush=True)
                elif record["backend_trace_profile"] == "channel":
                    print("Read-only channel trace enabled: selection, transport, service-name preparation, registration and final result; identical retries suppressed.", flush=True)
                elif record["backend_trace_profile"] == "handoff":
                    print("Read-only handoff trace enabled: frontend ticket/auth state and paired channel creation result.", flush=True)
                else:
                    print("Read-only backend startup trace enabled: version, settings result, registration gate, transport errors.", flush=True)
            if command is None:
                input("Launch the game now. Exit at the first stable result, then press Enter: ")
                result = 0
            else:
                print("Launching with a private read-only DLL overlay; retail files on disk are unchanged.", flush=True)
                result = launch(command)
            if any(child.poll() is not None for child, _ in children):
                raise RuntimeError("A local listener stopped during capture; inspect service logs")
            return result
    finally:
        for signum, handler in previous_signals.items():
            signal.signal(signum, handler)
        try:
            if game_log.exists():
                with game_log.open("rb") as stream:
                    stream.seek(old_size if game_log.stat().st_size >= old_size else 0)
                    with (capture / game_log.name).open("wb") as output:
                        shutil.copyfileobj(stream, output)
        finally:
            ACTIVE.unlink()
            print(f"Saved: {capture}", flush=True)


def debugger_invocation(command, environment, driver):
    # Steam's loader paths/preloads belong to Proton, not the host debugger.
    # Python overrides can likewise break GDB's embedded system Python. Restore
    # these only in the inferior, via argv (no shell expansion or GDB quoting).
    environment = launch_env.game_environment(environment)
    game_only = {key: value for key, value in environment.items()
                 if key.startswith(("LD_", "PYTHON"))}
    debugger_environment = {key: value for key, value in environment.items()
                            if key not in game_only}
    argv = [str(GDB), "-nx", "-nh", "--batch", "-q", "-ex",
            "source " + str(driver), "--args", "/usr/bin/env", "--",
            *(f"{key}={value}" for key, value in game_only.items()), *command]
    return argv, debugger_environment


def launch(command):
    netns.check(netns.STATE_DIR)
    record = active_record()
    game, compat, capture = Path(record["game"]), Path(record["compat"]), Path(record["capture"])
    if netns.launch_prefix() != netns.directory_identity(compat / "pfx"):
        raise RuntimeError("Steam command is using a different Proton prefix")
    overlay = record.get("loader_overlay", False)
    verify_game(game, compat, loader_overlay=overlay)
    if record["dll_sha256"] != digest(DLL):
        raise RuntimeError("Adapter build changed during capture")
    if not command:
        raise RuntimeError("Missing Steam command")
    restored = launch_env.game_environment(netns.clean_environment())
    environment = {k: v for k, v in restored.items() if not k.startswith("ISAC_")}
    environment.update(ISAC_SDK_ADAPTER="1", PROTON_LOG="1", PROTON_LOG_DIR=str(capture),
                       WINEDEBUG="+timestamp,+pid,+tid,+seh")
    if overlay:
        # Auto-launch remains in the supervisor's private PID namespace,
        # unlike the legacy join-game wrapper. Its owner record uses a host
        # PID, so retain only this trusted read-only host-/proc bind for GDB's
        # lifetime check (never an inherited legacy instrumentation value).
        environment["ISAC_HOST_PROC"] = str(netns.STATE_DIR / "host-proc")
    combined = record.get("mode", "sdk") == "transport"
    if combined:
        for file, key in (("hosts", "hosts_sha256"), ("nsswitch.conf", "nss_sha256"),
                          ("bootstrap-cert.pem", "certificate_sha256")):
            if digest(capture / file) != record[key]:
                raise RuntimeError("Transport routing/certificate changed during capture")
        environment["ISAC_SDK_TRANSPORT"] = "1"
    argv, debugger_environment = debugger_invocation(
        command, environment, ROOT / "tools/sdk_adapter_gdb.py")
    if combined or overlay:
        # Set up the mount view before tracing. Tracking this extra bwrap
        # across Steam's nested runtime helpers crashes the installed GDB.
        # The driver checks current namespace identity and supervisor lifetime,
        # without requiring ptrace access to the ancestor's namespace symlinks.
        loader = None
        if overlay:
            source = capture / "adapter-loader.dll"
            if source.is_symlink() or digest(source) != record["dll_sha256"]:
                raise RuntimeError("Frozen adapter overlay changed during capture")
            loader = (source, game / "uplay_r1_loader64.dll")
        argv = transport.mount_command(capture / "hosts" if combined else None, argv, loader=loader)
    with (capture / "adapter-launch.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (capture / "sdk-adapter-debugger.log").open("a") as log:
            result = subprocess.call(argv, env=debugger_environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "_inside", "launch", "auto", "_auto-inside"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    values = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    try:
        if args.action == "launch":
            return launch(values)
        automatic = args.action in ("auto", "_auto-inside")
        command = None
        if automatic:
            if len(values) < 5 or values[3] != "--":
                raise RuntimeError("Expected GAME_DIRECTORY COMPATDATA_DIRECTORY MODE -- STEAM_COMMAND")
            command, values = values[4:], values[:3]
        if len(values) not in (2, 3) or (len(values) == 3 and values[2] not in MODES):
            raise RuntimeError("Expected GAME_DIRECTORY COMPATDATA_DIRECTORY [" + "|".join(MODES) + "]")
        mode = values[2] if len(values) == 3 else "sdk"
        game, compat = (Path(x).resolve(strict=True) for x in values[:2])
        verify_game(game, compat, loader_overlay=automatic)
        if args.action in ("_inside", "_auto-inside"):
            return inside(game, compat, mode, command=command)
        if not os.access(GDB, os.X_OK):
            raise RuntimeError("Missing required system debugger: /usr/bin/gdb")
        for name in ("bwrap",):
            if not shutil.which(name):
                raise RuntimeError(f"Missing required executable: {name}")
        if automatic:
            if netns.launch_prefix() != netns.directory_identity(compat / "pfx"):
                raise RuntimeError("Steam command is using a different Proton prefix")
            # Inspect host /proc before the private PID namespace hides host
            # Wine processes. A shared wineserver must not bridge launch modes.
            netns.reject_external_wine(-1, netns.launch_prefix())
            netns.close_inherited_sockets()
        argv = [sys.executable, str(ROOT / "tools/isac-netns.py"), "--steam-ipc", "--recover-sdk-session", "run", "--",
                sys.executable, str(SELF), "_auto-inside" if automatic else "_inside",
                str(game), str(compat), mode, *(["--", *command] if automatic else [])]
        return netns.launch(argv, launch_env.helper_environment(netns.clean_environment())) if automatic else subprocess.call(argv)
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError, KeyError, EOFError, subprocess.CalledProcessError) as error:
        print(f"SDK adapter test refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
