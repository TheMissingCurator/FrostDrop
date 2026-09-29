#!/usr/bin/env python3
"""Deliberately connected, retail-only type-5 startup capture from Steam."""
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

import sdk_adapter_test as runner
from steam_isac_mode import steam_paths


def verify_retail(game, compat):
    if (game / "uplay_r1_loader64.dll").is_symlink() or runner.digest(game / "uplay_r1_loader64.dll") != runner.RETAIL_DLL_HASH:
        raise RuntimeError("Probe requires the restored retail loader; verify installed files first")
    if runner.digest(game / "thedivision.exe") != runner.GAME_HASH:
        raise RuntimeError("Unsupported executable")
    prefix = runner.netns.directory_identity(compat / "pfx")
    if prefix != runner.netns.launch_prefix():
        raise RuntimeError("Steam prefix mismatch")
    # A shared existing Wine session would not be a child of this debugger.
    # Reject EVERY existing game-prefix Wine process, not only other netns.
    runner.netns.reject_external_wine(-1, prefix)


def capture(command, environment):
    game, compat = steam_paths()
    verify_retail(game, compat)
    if not runner.GDB.is_file():
        raise RuntimeError("Missing /usr/bin/gdb")
    directory = runner.ROOT / "evidence" / (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-retail-service-name-linux")
    directory.mkdir(mode=0o700, parents=True)
    (directory / "producer-private").mkdir(mode=0o700)
    for name, data in (("metadata.json", {"mode": "retail-service-name", "network": "normal-retail-online",
            "adapter": False, "responses_changed": False, "game_sha256": runner.GAME_HASH,
            "retail_loader_sha256": runner.RETAIL_DLL_HASH}),):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, sort_keys=True)
    environment = runner.launch_env.helper_environment(environment)
    environment.update(ISAC_RETAIL_PROBE_CAPTURE=str(directory), PROTON_LOG="1",
                       PROTON_LOG_DIR=str(directory), WINEDEBUG="-all,+seh")
    argv, debugger_environment = runner.debugger_invocation(command, environment,
        runner.ROOT / "tools/retail_service_name_gdb.py")
    log_fd = os.open(directory / "producer-trace.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    print(f"Retail producer capture: {directory}", flush=True)
    print("Online retail startup only. Reach character/menu, then quit; no gameplay needed.", flush=True)
    with os.fdopen(log_fd, "w") as log:
        child = subprocess.Popen(argv, env=debugger_environment, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        previous = {}
        def stop(_signum, _frame):
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, stop)
        try:
            try:
                code = child.wait(timeout=300)
            except subprocess.TimeoutExpired:
                stop(None, None)
                try:
                    code = child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    code = child.wait()
                print("Probe stopped at its five-minute launch limit.", flush=True)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    print(f"Saved: {directory} (debugger exit {code})", flush=True)
    return code


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        print("Launch through Steam with -- %command%.", file=sys.stderr)
        return 2
    # Serialise only this new probe, independent of stale custom-mode records.
    lock_fd = os.open(runner.ROOT / "private/retail-service-name.lock",
                      os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        try:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise RuntimeError("Unsafe retail probe lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return capture(sys.argv[2:], dict(os.environ))
        except (OSError, RuntimeError, ValueError) as error:
            print(f"Retail probe refused: {error}. No custom-mode fallback.", file=sys.stderr)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
