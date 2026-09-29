#!/usr/bin/env python3
"""Bounded Wine SysCall/SysRet analysis, without dereferencing argument pointers."""
import argparse
from collections import Counter, defaultdict
from pathlib import Path
import re

APIS = {"NtProtectVirtualMemory": 5, "NtSetContextThread": 2, "NtGetContextThread": 2,
        "NtQueryVirtualMemory": 6}
PREFIX = r"(?P<seconds>\d{1,10}\.\d{1,9}):(?P<pid>[0-9a-f]{4,8}):(?P<tid>[0-9a-f]{4,8}):"
SYSCALL = re.compile(r"^" + PREFIX + r"(?:trace:syscall:(?:trace_sys(?:call|ret):)?)?"
                     r"(?P<kind>SysCall|SysRet)\s+(?P<api>[A-Za-z0-9_]{1,64})\((?P<args>[0-9a-f,]*)\)"
                     r"(?: retval=(?P<retval>[0-9a-f]{1,16}))?\s*$")
VIRTUAL = re.compile(r"^" + PREFIX + r"trace:virtual:NtProtectVirtualMemory "
                     r"(?:0x[0-9a-f]+|\(nil\)) (?P<address>0x[0-9a-f]+) "
                     r"(?P<length>[0-9a-f]+) (?P<protection>[0-9a-f]+)\s*$")
MARKER = re.compile(r"^(?P<tag>SDK_NATIVE_CONTEXT|SDK_NATIVE_PROTECT_BOUNDARY) "
                    r"tick_ms=(?P<tick>\d+) process=(?P<pid>\d+) thread=(?P<tid>\d+) detail=(?P<detail>[^\r\n]*)")
MAX_LINES, MAX_BYTES = 2000000, 128 * 1024 * 1024


def native_record(line):
    if len(line) > 2048:
        return None
    match = SYSCALL.fullmatch(line.rstrip("\n"))
    if not match or match["api"] not in APIS:
        return None
    value = {"kind": match["kind"], "api": match["api"], "pid": int(match["pid"], 16),
             "tid": int(match["tid"], 16), "tick_ms": round(float(match["seconds"]) * 1000)}
    if value["kind"] == "SysCall":
        arguments = match["args"].split(",")
        if match["retval"] is not None or len(arguments) != APIS[value["api"]] or any(
                not re.fullmatch(r"[0-9a-f]{1,16}", argument) for argument in arguments):
            return None
        value["args"] = [int(argument, 16) for argument in arguments]
    else:
        if match["args"] or match["retval"] is None:
            return None
        value["ntstatus"] = int(match["retval"], 16) & 0xffffffff
    return value


def marker_record(line):
    if len(line) > 2048:
        return None
    match = MARKER.fullmatch(line.rstrip("\r\n"))
    if not match:
        return None
    try:
        fields = dict(item.split("=", 1) for item in match["detail"].split(",") if "=" in item)
        value = {"tag": match["tag"], "pid": int(match["pid"]), "tid": int(match["tid"]),
                 "tick_ms": int(match["tick"]), "phase": fields["phase"]}
        if value["phase"] not in {"begin", "end"}:
            return None
        if value["tag"] == "SDK_NATIVE_CONTEXT":
            value["operation"] = fields["operation"]
            if value["operation"] not in {"get", "set", "verify"}:
                return None
            keys = ("context", "flags", "ok", "win32_error", "unchanged", "enabled_slots")
        else:
            keys = ("target", "length", "requested", "win32_error")
        for key in keys:
            value[key] = int(fields[key], 0)
            if not 0 <= value[key] <= 0xffffffffffffffff:
                return None
        if value["tag"] == "SDK_NATIVE_CONTEXT" and (
                value["flags"] != 0x100010 or not value["context"] or value["enabled_slots"] > 255
                or any(value[key] not in {0, 1} for key in ("ok", "unchanged"))):
            return None
        if value["tag"] == "SDK_NATIVE_PROTECT_BOUNDARY" and (not value["target"] or not 0 < value["length"] <= 4096):
            return None
        return value
    except (KeyError, ValueError):
        return None


def bounded_lines(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("log-size-limit")
    with path.open(errors="replace") as stream:
        for index, line in enumerate(stream):
            if index >= MAX_LINES:
                raise ValueError("log-line-limit")
            yield line if len(line) <= 2048 else ""


def collect(directory):
    markers, windows, pending_markers = [], [], {}
    stack = directory / "project-isac-stack-probe.log"
    if stack.exists():
        for line in bounded_lines(stack):
            marker = marker_record(line)
            if marker and len(markers) < 32:
                markers.append(marker)
                key = (marker["tag"], marker.get("operation"), marker["pid"], marker["tid"])
                if marker["phase"] == "begin":
                    pending_markers[key] = marker
                elif key in pending_markers:
                    begin = pending_markers.pop(key)
                    identities = ("context", "flags") if marker["tag"] == "SDK_NATIVE_CONTEXT" else ("target", "length", "requested")
                    if 0 <= marker["tick_ms"] - begin["tick_ms"] <= 10000 and all(marker[item] == begin[item] for item in identities):
                        windows.append({"begin": begin, "end": marker})
    threads = {(marker["pid"], marker["tid"]) for marker in markers}
    counts, records, entries, pending = Counter(), [], [], defaultdict(list)
    virtual, orphan_returns, matched_returns = [], 0, Counter()
    logs = sorted(directory.glob("steam-*.log"))[:8]
    for log in logs:
        pending.clear()  # Never pair across different log files.
        for line in bounded_lines(log):
            record = native_record(line)
            if record:
                if threads and (record["pid"], record["tid"]) not in threads:
                    continue
                key = (record["pid"], record["tid"], record["api"])
                counts[(record["api"], record["kind"])] += 1
                if record["kind"] == "SysCall":
                    if len(entries) < 256 and any(window["begin"]["pid"] == record["pid"] and window["begin"]["tid"] == record["tid"]
                            and window["begin"]["tick_ms"] - 2 <= record["tick_ms"] <= window["end"]["tick_ms"] + 2 for window in windows):
                        entries.append(record)
                    if len(pending) < 512 and len(pending[key]) < 16:
                        pending[key].append(record)
                elif pending.get(key):
                    entry = pending[key].pop()
                    if record["tick_ms"] >= entry["tick_ms"]:
                        matched_returns[record["api"]] += 1
                        entry = {**entry, "return_tick_ms": record["tick_ms"], "ntstatus": record["ntstatus"]}
                        relevant = any(window["begin"]["pid"] == entry["pid"] and window["begin"]["tid"] == entry["tid"]
                                       and window["begin"]["tick_ms"] - 2 <= entry["tick_ms"] <= window["end"]["tick_ms"] + 2
                                       for window in windows)
                        if len(records) < 256 and (relevant or not threads):
                            records.append(entry)
                else:
                    orphan_returns += 1
            match = VIRTUAL.fullmatch(line.rstrip("\n"))
            if match and len(virtual) < 256:
                item = {"pid": int(match["pid"], 16), "tid": int(match["tid"], 16),
                        "tick_ms": round(float(match["seconds"]) * 1000), "target": int(match["address"], 16),
                        "length": int(match["length"], 16), "requested": int(match["protection"], 16)}
                if any(window["begin"]["tag"] == "SDK_NATIVE_PROTECT_BOUNDARY" and
                       all(item[key] == window["begin"][key] for key in ("pid", "tid", "target", "length", "requested")) and
                       window["begin"]["tick_ms"] - 2 <= item["tick_ms"] <= window["end"]["tick_ms"] + 2 for window in windows):
                    virtual.append(item)
    return {"markers": markers, "windows": windows, "counts": counts, "records": records, "entries": entries,
            "virtual": virtual, "orphan_returns": orphan_returns, "matched_returns": matched_returns, "logs": len(logs)}


def analyze(directory):
    data = collect(directory)
    output = ["Wine native dispatcher entry/return diagnosis", "Observation only; no alternate protection route or forced success.",
              f"Proton logs: {data['logs']}; operation markers: {len(data['markers'])}; complete operation windows: {len(data['windows'])}"]
    for api in sorted(APIS):
        scope = "Calling-thread" if data["markers"] else "Unattributed startup"
        output.append(f"{scope} coverage {api}: entries={data['counts'][(api, 'SysCall')]} returns={data['counts'][(api, 'SysRet')]} paired={data['matched_returns'][api]}")
    if not data["markers"]:
        output.append("Missing native-operation markers: verify the installed DLL and --sdk-native-trace launch option. General startup calls are not the URL operation.")
    elif not data["windows"]:
        output.append("Incomplete operation windows: do not interpret absent correlated calls as an early return.")
    if not data["counts"]:
        output.append("No native dispatcher coverage: verify +syscall reached the runtime; absence is not evidence of interception.")
    for window in data["windows"]:
        begin, end = window["begin"], window["end"]
        api = ("NtSetContextThread" if begin.get("operation") == "set" else "NtGetContextThread") if begin["tag"] == "SDK_NATIVE_CONTEXT" else "NtProtectVirtualMemory"
        candidates = [record for record in data["records"] if record["api"] == api and
                      all(record[key] == begin[key] for key in ("pid", "tid")) and
                      begin["tick_ms"] - 2 <= record["tick_ms"] <= end["tick_ms"] + 2 and
                      record["return_tick_ms"] <= end["tick_ms"] + 2]
        operation = begin.get("operation", "protect")
        entries = [record for record in data["entries"] if record["api"] == api and
                   all(record[key] == begin[key] for key in ("pid", "tid")) and
                   begin["tick_ms"] - 2 <= record["tick_ms"] <= end["tick_ms"] + 2]
        if operation != "protect":
            candidates = [record for record in candidates if record["args"][1] == begin["context"]]
            entries = [record for record in entries if record["args"][1] == begin["context"]]
            output.append(f"Unchanged-context {operation}: Win32 success={end['ok']} error={end['win32_error']} native entries={len(entries)} native paired calls={len(candidates)}")
            if operation == "verify":
                output.append(f"Saved breakpoint addresses/control unchanged={end['unchanged']} (no repair/retry attempted).")
            for record in candidates:
                output.append(f"Observed {api} return NTSTATUS=0x{record['ntstatus']:08x} for the correlated context pointer.")
                if record["ntstatus"] == 0 and not end["ok"]:
                    output.append("Native success and Win32 failure differ; investigate the intervening return path/correlation rather than assuming Wine denied it.")
        else:
            candidates = [record for record in candidates if record["args"][3] == begin["requested"]]
            entries = [record for record in entries if record["args"][3] == begin["requested"]]
            output.append(f"URL protection: target=0x{begin['target']:x} Win32 error={end['win32_error']} native entries={len(entries)} native paired candidates={len(candidates)} decoded target entries={len(data['virtual'])}")
            # The dispatcher records pointer-valued address/size parameters.
            # Require a unique candidate plus decoded +virtual target entry.
            if len(candidates) == 1 and any(item["pid"] == begin["pid"] and item["tid"] == begin["tid"] and
                    candidates[0]["tick_ms"] <= item["tick_ms"] <= candidates[0]["return_tick_ms"] for item in data["virtual"]):
                output.append(f"Observed target-correlated native {api} return NTSTATUS=0x{candidates[0]['ntstatus']:08x}.")
            else:
                output.append("No uniquely target-correlated native protection return; pointer slots/nearby calls alone are insufficient.")
    output.append("Missing native calls may indicate an earlier return, but do not identify the hook owner or prove bypass. Matching Proton fixture coverage and complete markers are required to interpret absence.")
    output.append("The raw +syscall log includes other NT calls as numeric slots/returns; pointed-to buffers are not dumped by this channel. This report keeps four allowlisted APIs only. Logging can change timing.")
    return "\n".join(output) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument("--fixture-check", action="store_true")
    args = parser.parse_args()
    try:
        if args.fixture_check:
            data = collect(args.capture_dir)
            required = ("NtProtectVirtualMemory", "NtSetContextThread", "NtGetContextThread")
            if not all(data["matched_returns"][api] for api in required):
                raise ValueError("fixture-entry-return-coverage")
            print("Installed Proton native dispatcher entry/return coverage verified for protection/get/set context.")
        else:
            print(analyze(args.capture_dir), end="")
    except (OSError, ValueError) as error:
        print("Native analysis unavailable; error_type=" + type(error).__name__)
        raise SystemExit(1)
