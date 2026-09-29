#!/usr/bin/env python3
"""Read only SDK markers and selected /proc mappings; never dump memory/paths."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading

spec = importlib.util.spec_from_file_location("route_identity", Path(__file__).with_name("audit-game-routes.py"))
routes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routes)
HEADER = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) ([0-9a-f]+:[0-9a-f]+) (\d+)(?:\s+(.*))?$")


def marker(line):
    if not line.startswith("SDK_PROTECT_CALL ") or " detail=" not in line:
        return None
    values = dict(item.split("=", 1) for item in line.strip().split(" detail=", 1)[1].split(",") if "=" in item)
    if values.get("phase") not in {"begin", "write-failed", "write-succeeded", "restore-failed", "restored"}:
        return None
    parsed = {"phase": values["phase"]}
    for key in ("unix_ms", "target", "length", "requested", "win32_error", "virtual_protect", "nt_protect"):
        parsed[key] = int(values[key], 0)
    if parsed["target"] <= 0 or not 0 < parsed["length"] <= 4096:
        return None
    return parsed


def selected_mapping(lines, address, length):
    for line in lines:
        matched = HEADER.fullmatch(line.rstrip("\n"))
        if not matched:
            continue
        start, end = int(matched[1], 16), int(matched[2], 16)
        if start <= address and address + length <= end:
            path = matched[7] or ""
            kind = "memfd" if "memfd:" in path else "special" if path.startswith("[") else "file" if path else "anonymous"
            return {"start": start, "end": end, "permissions": matched[3], "offset": int(matched[4], 16),
                    "device": matched[5], "inode": int(matched[6]), "backing_class": kind,
                    "deleted": path.endswith(" (deleted)")}
    return None


def snapshot(process, call):
    with (process / "maps").open() as stream:
        mapping = selected_mapping(stream, call["target"], call["length"])
    if mapping is None:
        return None
    vmflags = []
    try:
        with (process / "smaps").open() as stream:
            selected = False
            for line in stream:
                if HEADER.fullmatch(line.rstrip("\n")):
                    selected = selected_mapping([line], call["target"], call["length"]) is not None
                elif selected and line.startswith("VmFlags:"):
                    vmflags = [value for value in line.split()[1:33] if re.fullmatch(r"[a-z]{2}", value)]
                    break
    except OSError:
        pass
    security = {}
    try:
        for line in (process / "status").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in {"NoNewPrivs", "Seccomp", "Seccomp_filters", "TracerPid"} and value.strip().isdigit():
                security[key] = int(value.strip())
    except OSError:
        pass
    tasks = sorted(int(item.name) for item in (process / "task").iterdir() if item.name.isdigit())[:1024]
    return {"event": "mapping", "at": routes.utc_now(), "linux_pid": int(process.name),
            "thread_ids": tasks, "target": call["target"], "length": call["length"],
            "mapping": mapping, "vm_flags": vmflags, "security": security,
            "timing": "sampled-after-marker; not a synchronous before-call snapshot"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--stack-log", type=Path, required=True)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.offset < 0:
        parser.error("negative offset")
    prefix = routes.identity(args.prefix)
    proc = Path(os.environ.get("ISAC_HOST_PROC", "/proc"))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    offset, pending = args.offset, b""
    calls, seen = {}, set()
    with args.output.open("x") as stream:
        def emit(value):
            stream.write(json.dumps(value, sort_keys=True) + "\n")
            stream.flush()
        emit({"event": "ready", "interval_ms": 50, "memory_contents": "disabled", "paths": "redacted"})
        while not stop.is_set():
            try:
                if args.stack_log.exists():
                    if args.stack_log.stat().st_size < offset:
                        offset, pending = 0, b""
                    with args.stack_log.open("rb") as source:
                        source.seek(offset)
                        chunk = source.read(65536)
                        offset += len(chunk)
                    lines = (pending + chunk).split(b"\n")
                    pending = lines.pop()[-4096:]
                    for line in lines:
                        try:
                            call = marker(line[:4096].decode("ascii"))
                        except (UnicodeError, ValueError, KeyError):
                            continue
                        if call is not None and len(calls) < 32:
                            calls[call["target"]] = call
                            emit({"event": "marker", **call})
                if calls:
                    for process in proc.iterdir():
                        if not process.name.isdigit():
                            continue
                        try:
                            if process.stat().st_uid != os.getuid():
                                continue
                            metadata = routes.process_metadata(process)
                            if metadata is None or metadata[0].casefold() != "thedivision.exe":
                                continue
                            if routes.process_prefix(process) != prefix:
                                continue
                            for target, call in calls.items():
                                key = (int(process.name), metadata[1], target)
                                if key in seen or len(seen) >= 32:
                                    continue
                                value = snapshot(process, call)
                                if value:
                                    seen.add(key)
                                    emit(value)
                        except (OSError, ValueError, IndexError):
                            continue
            except OSError as error:
                emit({"event": "inspection-error", "type": type(error).__name__})
            stop.wait(0.05)
        emit({"event": "finished", "targets": len(calls), "mapping_snapshots": len(seen)})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print("SDK_MAP_WATCH_ERROR type=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
