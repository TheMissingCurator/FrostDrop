#!/usr/bin/env python3
"""Shared, unprivileged, loopback-only network namespace for ISAC.

No host routes, interfaces, firewall rules or global namespaces are modified.
This isolates IP networking, not the filesystem or desktop IPC.
"""
import argparse
from contextlib import nullcontext
import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "private/network-isolation"
SELF = str(Path(__file__).resolve())
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000


def inode(path):
    return os.stat(path).st_ino


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("Isolation state directory must be owned by you and mode 0700")


def read_state(directory):
    fd = os.open(directory / "session.json", os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("Unsafe isolation state file")
        value = json.loads(stream.read(4096))
    if not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] <= 0
           for key in ("pid", "net", "user", "host_net", "uid")):
        raise RuntimeError("Invalid isolation state")
    if value["uid"] != os.getuid() or value["net"] == value["host_net"]:
        raise RuntimeError("Isolation state does not identify a private network")
    return value


def check_network():
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Expected loopback only; refusing a network with other interfaces")
    # Actual bind verifies that loopback is usable, not merely listed.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
    # These documentation-only destinations cannot have a route in this netns.
    for family, target in ((socket.AF_INET, ("192.0.2.1", 443)),
                           (socket.AF_INET6, ("2001:db8::1", 443))):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.25)
                result = probe.connect_ex(target)
        except OSError as error:
            if family == socket.AF_INET6 and error.errno == errno.EAFNOSUPPORT:
                continue
            raise
        if result not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL):
            raise RuntimeError(f"External-network negative control failed: family={family}, result={result}")


def check(directory):
    private_directory(directory)
    state = read_state(directory)
    pid = state["pid"]
    proc = Path(os.environ.get("ISAC_HOST_PROC", "/proc"))
    if (proc / str(pid)).stat().st_uid != os.getuid():
        raise RuntimeError("Namespace owner changed")
    if inode(proc / str(pid) / "ns/net") != state["net"] or inode(proc / str(pid) / "ns/user") != state["user"]:
        raise RuntimeError("Namespace owner is stale")
    if inode("/proc/self/ns/net") != state["net"]:
        raise RuntimeError("This process is outside the ISAC network namespace")
    check_network()
    return state


def process_start_time(process):
    # /proc/PID/stat field 22; comm may itself contain spaces or parentheses.
    tail = (Path(process) / "stat").read_text().rsplit(")", 1)[1].split()
    return int(tail[19])


def check_member(directory):
    """Validate an already-joined member without ptrace access to its owner.

    Nested mount sandboxes may create a child user namespace. Their processes
    can inspect their own network namespace but not an ancestor's ns symlinks.
    The held current namespace cannot recycle its inode. Pin supervisor birth
    time as well as PID/UID to reject a stale or reused supervisor record.
    Joining still uses check() and validated open namespace handles.
    """
    private_directory(directory)
    state = read_state(directory)
    birth = state.get("owner_start_time")
    if type(birth) is not int or birth <= 0:
        raise RuntimeError("Missing namespace owner lifetime identity; restart capture")
    proc = Path(os.environ.get("ISAC_HOST_PROC", "/proc")) / str(state["pid"])
    if proc.stat().st_uid != os.getuid() or process_start_time(proc) != birth:
        raise RuntimeError("Namespace owner lifetime changed")
    if inode("/proc/self/ns/net") != state["net"]:
        raise RuntimeError("This process is outside the ISAC network namespace")
    check_network()
    return state


def directory_identity(path):
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("Wine prefix is not a directory")
    return info.st_dev, info.st_ino


def launch_prefix():
    # Proton derives WINEPREFIX from STEAM_COMPAT_DATA_PATH, overriding any
    # inherited WINEPREFIX. Follow that same precedence; never guess a prefix.
    compatdata = os.environ.get("STEAM_COMPAT_DATA_PATH")
    prefix = Path(compatdata) / "pfx" if compatdata else Path(os.environ.get("WINEPREFIX", ""))
    if not prefix.is_absolute():
        raise RuntimeError("Cannot identify game prefix; STEAM_COMPAT_DATA_PATH or absolute WINEPREFIX is required")
    return directory_identity(prefix)


def process_prefix(process):
    # Read only to identify the prefix; never log process environments. Resolve
    # through the process root so Flatpak/container paths and bind mounts are
    # compared by actual directory identity, not spelling or process name.
    with (process / "environ").open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise RuntimeError("Process environment exceeds inspection limit")
    environment = {}
    for entry in data.split(b"\0"):
        key, separator, value = entry.partition(b"=")
        if separator and key in (b"WINEPREFIX", b"STEAM_COMPAT_DATA_PATH", b"HOME"):
            environment[key] = os.fsdecode(value)
    # For an already-running Wine process its actual WINEPREFIX takes priority.
    if environment.get(b"WINEPREFIX"):
        prefix = Path(environment[b"WINEPREFIX"])
    elif environment.get(b"STEAM_COMPAT_DATA_PATH"):
        prefix = Path(environment[b"STEAM_COMPAT_DATA_PATH"]) / "pfx"
    elif environment.get(b"HOME"):
        prefix = Path(environment[b"HOME"]) / ".wine"
    else:
        raise RuntimeError("Process prefix cannot be identified")
    if not prefix.is_absolute():
        raise RuntimeError("Process prefix is not absolute")
    return directory_identity(process / "root" / str(prefix).lstrip("/"))


def reject_external_wine(net, prefix_identity):
    names = {"wineserver", "wineserver64", "wine", "wine64", "thedivision.exe", "upc.exe"}
    conflicts = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
            name = (process / "comm").read_text().strip()
        except FileNotFoundError:
            continue
        if name not in names:
            continue
        try:
            if process_prefix(process) != prefix_identity:
                continue  # Positively identified as another prefix: irrelevant.
            if inode(process / "ns/net") != net:
                conflicts.append(f"{name} (PID {process.name}, game prefix outside isolation)")
        except FileNotFoundError:
            if process.exists():
                conflicts.append(f"{name} (PID {process.name}, prefix/namespace unavailable)")
        except (PermissionError, RuntimeError):
            conflicts.append(f"{name} (PID {process.name}, prefix/namespace unreadable or unidentified)")
    if conflicts:
        raise RuntimeError("Game-prefix isolation check blocked launch: " + ", ".join(conflicts))


def clean_environment():
    environment = {key: value for key, value in os.environ.items()
                   if not key.lower().endswith("_proxy")}
    environment["NO_PROXY"] = "*"
    return environment


def close_inherited_sockets():
    # Passed-in host sockets retain their old network namespace. Do not carry
    # extra descriptors from Steam/terminal helpers across the boundary.
    for entry in Path("/proc/self/fd").iterdir():
        fd = int(entry.name)
        try:
            if fd > 2:
                os.close(fd)
            elif stat.S_ISSOCK(os.fstat(fd).st_mode):
                raise RuntimeError("Refusing inherited socket on stdin/stdout/stderr")
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def launch(command, environment):
    # Same foreground process group preserves interactive capture prompts.
    child = subprocess.Popen(command, env=environment, close_fds=True)
    previous = {}
    def forward(signum, _frame):
        if child.poll() is None:
            child.send_signal(signum)
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, forward)
    try:
        return child.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run(directory, command, steam_ipc=False, recover_sdk_session=False):
    private_directory(directory)
    if os.getuid() == 0:
        raise RuntimeError("Run as your desktop user, not sudo/root")
    fd = os.open(directory / "session.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("An isolated capture is already running") from None
        if recover_sdk_session:
            # Recover in the host view BEFORE allocating a new namespace:
            # Linux can reuse a dead namespace inode for our new namespace.
            # The same exclusive lock protects recovery and the whole launch.
            from sdk_adapter_test import archive_stale_session
            archive_stale_session(proc="/proc")
        host_net = inode("/proc/self/ns/net")
        host_proc = directory / "host-proc"
        private_directory(host_proc)
        (directory / "session.json").unlink(missing_ok=True)
        try:
            from steam_ipc_relay import broker
            with broker(directory) if steam_ipc else nullcontext():
                options = ["--steam-ipc"] if steam_ipc else []
                return launch(["bwrap", "--unshare-user", "--unshare-net", "--unshare-pid", "--die-with-parent",
                               "--dev-bind", "/", "/", "--ro-bind", "/proc", str(host_proc),
                               "--proc", "/proc", "--", sys.executable, SELF,
                               "--state-dir", str(directory), *options, "_inside", str(host_net), "--", *command],
                              clean_environment())
        finally:
            (directory / "session.json").unlink(missing_ok=True)


def inside(directory, host_net, command, steam_ipc=False):
    net = inode("/proc/self/ns/net")
    if net == host_net:
        raise RuntimeError("Network namespace was not created")
    check_network()
    # Normal /proc must match the PID namespace (procps otherwise fails).
    # A separate read-only host view supplies the ID used by Steam's launcher.
    host_proc = directory / "host-proc"
    state = {"pid": int(os.readlink(host_proc / "self")), "uid": os.getuid(), "net": net,
             "user": inode("/proc/self/ns/user"), "host_net": host_net}
    state["owner_start_time"] = process_start_time(host_proc / str(state["pid"]))
    fd = os.open(directory / "session.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream)
    environment = clean_environment()
    environment["ISAC_NETNS_INNER"] = "1"
    environment["ISAC_HOST_PROC"] = str(host_proc)
    print(f"ISAC_NETNS_READY net={net} interfaces=lo external_ipv4=blocked external_ipv6=blocked", flush=True)
    from steam_ipc_relay import frontend
    with frontend(directory) if steam_ipc else nullcontext():
        return launch(command, environment)


def join(directory, command, game=False):
    private_directory(directory)
    state = read_state(directory)
    # Open both handles before entering either namespace. Validate handles, not
    # just a PID that could disappear/recycle between inspection and setns.
    pid = state["pid"]
    if os.stat(f"/proc/{pid}").st_uid != os.getuid():
        raise RuntimeError("Namespace owner changed")
    user_fd = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY)
    try:
        net_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
        try:
            if os.fstat(user_fd).st_ino != state["user"] or os.fstat(net_fd).st_ino != state["net"]:
                raise RuntimeError("Stale namespace handles")
            if game:
                reject_external_wine(state["net"], launch_prefix())
            if inode("/proc/self/ns/user") != state["user"]:
                os.setns(user_fd, CLONE_NEWUSER)
            if inode("/proc/self/ns/net") != state["net"]:
                os.setns(net_fd, CLONE_NEWNET)
        finally:
            os.close(net_fd)
    finally:
        os.close(user_fd)
    check(directory)
    environment = clean_environment()
    environment["ISAC_NETNS_JOINED"] = "1"
    print(f"ISAC_NETNS_JOINED net={state['net']} interfaces=lo", flush=True)
    close_inherited_sockets()
    os.execvpe(command[0], command, environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--steam-ipc", action="store_true", help="Relay only the verified local Steam IPC endpoint")
    parser.add_argument("--recover-sdk-session", action="store_true",
                        help="Verify/archive stale SDK state under the launch lock before isolation")
    parser.add_argument("action", choices=("run", "join", "join-game", "check", "_inside"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.recover_sdk_session and (args.action != "run" or args.state_dir.resolve() != STATE_DIR.resolve()):
        parser.error("SDK recovery requires run with the default isolation lock")
    command = args.arguments
    host_net = None
    if args.action == "_inside":
        host_net = int(command.pop(0))
    if command[:1] == ["--"]:
        command = command[1:]
    if args.action != "check" and not command:
        parser.error("A command is required after --")
    try:
        if args.action == "run":
            return run(args.state_dir, command, args.steam_ipc, args.recover_sdk_session)
        if args.action == "_inside":
            return inside(args.state_dir, host_net, command, args.steam_ipc)
        if args.action in ("join", "join-game"):
            return join(args.state_dir, command, game=args.action == "join-game")
        check(args.state_dir)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"ISAC network isolation refused: {error}. No non-isolated fallback.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
