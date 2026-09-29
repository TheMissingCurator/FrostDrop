#!/usr/bin/env python3
"""Correlate URL markers, prefix-owned Linux mappings and failed protection calls."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

CALL = re.compile(r"^\s*(?:\[pid\s+)?(?P<tid>\d+)(?:\])?\s+(?P<time>\d+\.\d+)\s+"
                  r"(?P<api>mprotect|pkey_mprotect)\((?P<address>0x[0-9a-f]+),\s*(?P<length>\d+),\s*"
                  r"(?P<protection>[A-Z0-9_x|]+)(?:,\s*-?\d+)?\)\s*=\s*-1\s+(?P<errno>[A-Z0-9_]+)")
EDGES = {"shim-to-kernel32", "kernel32-to-kernelbase", "kernelbase-to-ntdll", "kernel32-entry"}
PHASES = {"begin", "write-failed", "write-succeeded", "restore-failed", "restored"}
OWNERS = {"unknown", "kernel32", "kernelbase", "ntdll", "game", "other-image", "private", "other-mapping"}
STATUSES = {"ok", "unreadable-slot", "null-destination", "unreadable-header", "invalid-header",
            "import-not-found", "invalid-import-directory", "missing-original-thunk", "invalid-thunk",
            "thunk-limit", "descriptor-limit", "unreadable-entry", "entry-not-rip-indirect", "invalid-forward-slot"}
CODE_APIS = {"kernel32.VirtualProtect": 24, "kernelbase.VirtualProtect": 176, "ntdll.NtProtectVirtualMemory": 32}
CODE_STATUSES = {"ok", "invalid-window", "entry-owner-mismatch", "entry-not-executable", "invalid-code-image", "unreadable-code"}
JUMP_STATUSES = {"ok", "not-e9-entry", "invalid-branch", "unsupported-target", "unreadable-target"}
PATH_STATUSES = {"complete", "incomplete", "unsupported-path", "debug-registers-busy", "handler-unavailable",
                 "unexpected-call", "return-without-entry", "not-started", "context-unavailable", "arm-failed", "restore-failed", "native-only"}


def path_record(line):
    tag = line.split(" ", 1)[0]
    if tag not in {"SDK_JUMP_CODE", "SDK_PROTECT_PATH"} or " detail=" not in line:
        return None
    try:
        fields = dict(item.split("=", 1) for item in line.strip().split(" detail=", 1)[1].split(",") if "=" in item)
        value = {"tag": tag, "phase": fields["phase"], "status": fields["status"]}
        if value["phase"] not in {"begin", "write-failed", "write-succeeded"}:
            return None
        keys = ("entry", "target", "allocation", "protect", "memory_type", "length") if tag == "SDK_JUMP_CODE" else (
            "thread", "entry", "jump", "returned", "target", "length", "requested", "entered", "jumped", "completed", "ntstatus", "win32_error")
        for key in keys:
            value[key] = int(fields[key], 0)
            if not 0 <= value[key] <= 0xffffffffffffffff:
                return None
        if tag == "SDK_JUMP_CODE":
            if value["status"] not in JUMP_STATUSES or value["length"] not in {0, 128}:
                return None
            raw = fields["code_hex"]
            if len(raw) != value["length"] * 2 or not re.fullmatch(r"[0-9a-f]*", raw):
                return None
            if value["status"] == "ok":
                if (value["length"] != 128 or value["memory_type"] != 0x20000 or not value["allocation"]
                        or value["target"] < value["allocation"] or value["target"] > 0xffffffffffffffff - 128
                        or value["protect"] & 0x100 or value["protect"] & 0xff not in {0x20, 0x40, 0x80}):
                    return None
            elif value["length"] != 0:
                return None
            value["bytes"] = bytes.fromhex(raw)
        else:
            if (value["status"] not in PATH_STATUSES or value["phase"] == "begin"
                    or any(value[key] not in {0, 1} for key in ("entered", "jumped", "completed"))
                    or value["ntstatus"] > 0xffffffff or value["win32_error"] > 0xffffffff):
                return None
            if value["completed"] and (not value["entered"] or value["status"] != "complete"):
                return None
        return value
    except (KeyError, ValueError, TypeError):
        return None


def path_report(directory):
    jumps, paths, apis, calls = [], [], {}, []
    log = directory / "project-isac-stack-probe.log"
    if log.exists():
        with log.open() as source:
            for index, line in enumerate(source):
                if index >= 65536:
                    break
                line = line[:2048]
                value = path_record(line)
                if value and value["tag"] == "SDK_JUMP_CODE" and len(jumps) < 6:
                    jumps.append(value)
                elif value and len(paths) < 4:
                    paths.append(value)
                api = code_record(line)
                if api and api["phase"] == "begin":
                    apis.setdefault(api["api"], api)
                if line.startswith("SDK_PROTECT_CALL ") and " detail=" in line and len(calls) < 8:
                    try:
                        fields = dict(item.split("=", 1) for item in line.strip().split(" detail=", 1)[1].split(",") if "=" in item)
                        thread = re.search(r" thread=(\d+) ", line)
                        if fields["phase"] == "begin" and thread:
                            calls.append({key: int(fields[key], 0) for key in ("target", "length", "requested")} | {"thread": int(thread[1])})
                    except (KeyError, ValueError):
                        pass
    output = ["", f"NtProtect jump windows: {len(jumps)}; one-shot return observations: {len(paths)}"]
    nt = apis.get("ntdll.NtProtectVirtualMemory", {})
    kb = apis.get("kernelbase.VirtualProtect", {})
    expected_target = None
    data = nt.get("bytes", b"")
    if nt.get("status") == "ok" and len(data) == 32 and data[0] == 0xe9:
        expected_target = nt["entry"] + 5 + int.from_bytes(data[1:5], "little", signed=True)
    before_jump = None
    for value in jumps:
        output.append(f"Jump {value['phase']}: status={value['status']} target=0x{value['target']:x} allocation=0x{value['allocation']:x} length={value['length']}")
        if value["status"] != "ok":
            continue
        if value["entry"] != nt.get("entry") or value["target"] != expected_target:
            output.append("Jump/code correlation unavailable; do not treat these bytes as the observed NtProtect destination.")
            continue
        if value["phase"] == "begin":
            before_jump = value
            output.append("One-hop private executable target instructions (unreachable bytes/data may also disassemble):\n" + disassemble_code(value["bytes"], value["target"]))
        elif before_jump and value["bytes"] != before_jump["bytes"]:
            output.append("Jump destination window changed between sampling phases.")
    for value in paths:
        output.append(f"Path {value['phase']}: status={value['status']} entry_hit={value['entered']} jump_hit={value['jumped']} return_hit={value['completed']}")
        correlated = (before_jump is not None and value["entry"] == nt.get("entry")
                      and value["jump"] == before_jump["target"] and kb.get("status") == "ok"
                      and value["returned"] == kb.get("entry", 0) + 0x3d
                      and any(all(value[key] == call[key] for key in ("thread", "target", "length", "requested")) for call in calls))
        if value["completed"] and correlated:
            output.append(f"Observed raw NtProtect return NTSTATUS=0x{value['ntstatus']:08x}; unchanged VirtualProtect Win32 error={value['win32_error']}.")
            if value["ntstatus"] == 0xc0000022:
                output.append("The observed NtProtect call returned STATUS_ACCESS_DENIED. This does not identify who installed the jump or which deeper instruction produced the status.")
            if not value["jumped"]:
                output.append("Return observed but jump destination was not hit; do not infer that destination executed.")
        else:
            output.append("No validated raw return for the URL operation: incomplete/unsupported trace or missing correlation. Zero is not evidence of success.")
    if any(value["status"] == "native-only" for value in paths):
        output.append("Native dispatcher mode: hardware breakpoint arming is disabled. See sdk-native-analysis.txt for built-in SysCall/SysRet coverage; zero in SDK_PROTECT_PATH is not an observed return.")
    else:
        output.append("Execution observation is one-shot on the calling thread, using temporary hardware breakpoints; original debug registers are restored. No instruction, argument or return value is patched. Timing may change.")
    return output


def code_record(line):
    if not line.startswith("SDK_API_CODE ") or " detail=" not in line:
        return None
    try:
        fields = dict(item.split("=", 1) for item in line.strip().split(" detail=", 1)[1].split(",") if "=" in item)
        value = {key: fields[key] for key in ("phase", "api", "status")}
        if value["phase"] not in PHASES or value["api"] not in CODE_APIS or value["status"] not in CODE_STATUSES:
            return None
        for key in ("unix_ms", "entry", "allocation", "rva", "timestamp", "image_size", "length"):
            value[key] = int(fields[key], 0)
            if not 0 <= value[key] <= 0xffffffffffffffff:
                return None
        hex_data = fields["code_hex"]
        if len(hex_data) != value["length"] * 2 or not re.fullmatch(r"[0-9a-f]*", hex_data):
            return None
        if value["status"] == "ok":
            if (value["length"] != CODE_APIS[value["api"]] or not value["allocation"]
                    or value["entry"] != value["allocation"] + value["rva"]
                    or value["rva"] + value["length"] > value["image_size"]):
                return None
        elif value["length"] != 0:
            return None
        value["bytes"] = bytes.fromhex(hex_data)
        return value
    except (ValueError, KeyError):
        return None


def expected_code(reference, record):
    """Relocate only supported, wholly-contained PE base fixups."""
    if (reference.get("status") != "ok" or any(reference.get(key) != record[key]
            for key in ("timestamp", "image_size", "rva", "length"))):
        raise ValueError("reference identity mismatch")
    data = bytearray.fromhex(reference["code_hex"])
    if len(data) != record["length"]:
        raise ValueError("reference length")
    delta = record["allocation"] - reference["image_base"]
    touched = set()
    for relocation in reference["relocations"]:
        offset, width = relocation["offset"], relocation["width"]
        if width not in (4, 8) or offset < 0 or offset + width > len(data):
            raise ValueError("relocation bounds")
        indices = set(range(offset, offset + width))
        if touched & indices:
            raise ValueError("overlapping relocations")
        touched |= indices
        value = (int.from_bytes(data[offset:offset + width], "little") + delta) % (1 << (width * 8))
        data[offset:offset + width] = value.to_bytes(width, "little")
    return bytes(data)


def disassemble_code(data, address):
    objdump = shutil.which("objdump")
    if objdump is None:
        return "Disassembly unavailable: objdump not installed."
    try:
        with tempfile.NamedTemporaryFile(prefix="isac-sdk-api-", suffix=".bin") as file:
            file.write(data)
            file.flush()
            result = subprocess.run([objdump, "-D", "-b", "binary", "-m", "i386:x86-64",
                                     f"--adjust-vma={address:#x}", file.name],
                                    capture_output=True, text=True, timeout=5, check=True)
        return "\n".join(line for line in result.stdout.splitlines()
                         if re.match(r"\s*[0-9a-f]+:", line))[:12000]
    except (OSError, subprocess.SubprocessError):
        return "Disassembly unavailable: tool execution failed."


def code_report(directory):
    values, dispatch = [], []
    path = directory / "project-isac-stack-probe.log"
    if path.exists():
        with path.open() as source:
            for index, line in enumerate(source):
                if index >= 65536:
                    break
                if len(values) < 24:
                    value = code_record(line[:2048])
                    if value:
                        values.append(value)
                if line.startswith("SDK_WINE_DISPATCH ") and " detail=" in line and len(dispatch) < 8:
                    try:
                        fields = dict(item.split("=", 1) for item in line.strip().split(" detail=", 1)[1].split(",") if "=" in item)
                        phase, status = fields["phase"], fields["status"]
                        flag, target = int(fields["flag"], 0), int(fields["destination"], 0)
                        if phase in PHASES and status in {"ok", "unrecognized-stub", "dispatch-unreadable"} and 0 <= flag <= 255 and 0 <= target <= 0xffffffffffffffff:
                            dispatch.append(f"Wine dispatch {phase}: status={status} flag=0x{flag:x} destination=0x{target:x}")
                    except (KeyError, ValueError):
                        pass
    references = []
    for name in ("sdk-api-reference.json", "sdk-api-reference-after.json"):
        try:
            path = directory / name
            if path.stat().st_size > 65536:
                raise ValueError("reference limit")
            value = json.loads(path.read_text())
            if value.get("format") != 1 or not isinstance(value.get("apis"), dict):
                raise ValueError("reference format")
            references.append(value["apis"])
        except (OSError, ValueError, AttributeError):
            references.append({})
    output = ["", f"Live API code windows: {len(values)}"]
    missing = CODE_APIS.keys() - {value["api"] for value in values if value["phase"] == "begin"}
    if missing:
        output.append("Missing pre-call code coverage: " + ", ".join(sorted(missing)))
    first = {}
    for value in values:
        output.append(f"Code {value['phase']} {value['api']}: status={value['status']} rva=0x{value['rva']:x} length={value['length']}")
        if value["status"] != "ok":
            continue
        before = first.setdefault(value["api"], value["bytes"])
        if before != value["bytes"]:
            output.append("Entry window changed between sampling phases.")
        reference, after = references[0].get(value["api"], {}), references[1].get(value["api"], {})
        try:
            source_hash = reference["file_sha256"]
            if (not re.fullmatch(r"[0-9a-f]{64}", source_hash) or source_hash != after.get("file_sha256")
                    or after.get("status") != "ok"):
                raise ValueError("missing/changed reference file")
            expected = expected_code(reference, value)
            differences = [index for index, (live, disk) in enumerate(zip(value["bytes"], expected)) if live != disk]
            output.append(f"Reference file SHA-256={source_hash}; live window SHA-256={hashlib.sha256(value['bytes']).hexdigest()}")
            if differences:
                output.append(f"LIVE/REFERENCE DIFFERENCE: {len(differences)} bytes; first offset=0x{differences[0]:x}. "
                              "This does not establish Ubisoft/DRM involvement; legitimate loader changes must be considered.")
            else:
                output.append("Live window matches the stable prefix DLL reference after relocation adjustment.")
            if value["phase"] == "begin" or before != value["bytes"]:
                output.append("Live instructions:\n" + disassemble_code(value["bytes"], value["entry"]))
                if differences:
                    output.append("Reference instructions:\n" + disassemble_code(expected, value["entry"]))
        except (KeyError, ValueError, TypeError, AttributeError):
            output.append("Reference comparison unavailable: verify reference snapshots and matching PE metadata. "
                          "Do not attribute an unvalidated difference to interception.")
    output.extend(dispatch)
    output.append("Code snapshots are not an execution trace: matching sampled windows do not prove which path executed "
                  "or exclude changes elsewhere in Wine's dispatcher. No discovered code was called or patched.")
    return output


def binding(line):
    if not line.startswith("SDK_API_BINDING ") or " detail=" not in line:
        return None
    try:
        fields = dict(item.split("=", 1) for item in line.strip().split(" detail=", 1)[1].split(",") if "=" in item)
        value = {key: fields[key] for key in ("phase", "edge", "status", "owner")}
        if (value["phase"] not in PHASES or value["edge"] not in EDGES
                or value["status"] not in STATUSES or value["owner"] not in OWNERS):
            return None
        for key in ("unix_ms", "slot", "destination", "expected", "allocation", "rva", "protect",
                    "memory_type", "entry_slot"):
            value[key] = int(fields[key], 0)
            if not 0 <= value[key] <= 0xffffffffffffffff:
                return None
        # Derive comparisons from the addresses, not untrusted logged booleans.
        value["matches"] = bool(value["expected"] and value["destination"] == value["expected"])
        value["entry_slot_matches"] = bool(value["entry_slot"] and value["entry_slot"] == value["slot"])
        return value
    except (ValueError, KeyError):
        return None


def binding_report(directory):
    values = []
    path = directory / "project-isac-stack-probe.log"
    if path.exists():
        with path.open() as source:
            for index, line in enumerate(source):
                if index >= 65536 or len(values) >= 32:
                    break
                value = binding(line[:2048])
                if value is not None:
                    values.append(value)
    output = ["", f"Live API binding records: {len(values)}"]
    before = {value["edge"]: value for value in values if value["phase"] == "begin"}
    missing = EDGES - before.keys()
    if missing:
        output.append("Incomplete pre-call binding coverage: " + ", ".join(sorted(missing)) +
                      ". Verify the updated diagnostic DLL and trace flag.")
    for value in values:
        output.append(f"API {value['phase']} {value['edge']}: status={value['status']} "
                      f"slot=0x{value['slot']:x} destination=0x{value['destination']:x} "
                      f"reference=0x{value['expected']:x} matches={int(value['matches'])} "
                      f"owner={value['owner']} rva=0x{value['rva']:x}")
        if value["status"] == "ok" and value["expected"] and not value["matches"]:
            output.append("Destination differs from its exported reference; inspect forwarding/alias behavior before "
                          "attributing interception. No alternate API was called.")
        if value["edge"] == "kernel32-to-kernelbase" and value["entry_slot"] and not value["entry_slot_matches"]:
            output.append("Kernel32 entry's RIP-indirect slot differs from the named import slot.")
        initial = before.get(value["edge"])
        if initial and value["phase"] != "begin" and (value["slot"], value["destination"]) != (initial["slot"], initial["destination"]):
            output.append("Binding changed between pre-call and later sampling; this does not by itself establish the cause.")
    imports = EDGES - {"kernel32-entry"}
    if not missing and all(before[edge]["status"] == "ok" and before[edge]["matches"] for edge in imports):
        output.append("Pre-call import destinations match all export references. This does NOT prove entry code "
                      "is unchanged or identify the instruction producing access denied.")
    if "kernel32-entry" in before and before["kernel32-entry"]["status"] == "entry-not-rip-indirect":
        output.append("Kernel32 export is not the recognized FF25 thunk shape. Wine may already resolve the export "
                      "directly to kernelbase; this observation alone is not evidence of a hook.")
    return output


def syscall(line):
    match = CALL.match(line)
    if not match:
        return None
    result = match.groupdict()
    for key in ("tid", "length"):
        result[key] = int(result[key])
    result["address"] = int(result["address"], 16)
    result["time"] = float(result["time"])
    return result


def correlate(records, failures):
    markers = [item for item in records if item.get("event") == "marker"]
    mappings = [item for item in records if item.get("event") == "mapping"]
    matched = []
    for begin in markers:
        if begin["phase"] != "begin":
            continue
        target, length = begin["target"], begin["length"]
        ends = [item["unix_ms"] / 1000 for item in markers if item["target"] == target
                and item["phase"] in {"write-failed", "write-succeeded"}
                and item["unix_ms"] >= begin["unix_ms"]]
        if not ends:
            continue
        start, end = begin["unix_ms"] / 1000 - 0.1, min(ends) + 0.1
        tasks = {tid for item in mappings if item["target"] == target for tid in item["thread_ids"]}
        for failure in failures:
            if (failure["tid"] in tasks and start <= failure["time"] <= end
                    and failure["address"] <= target
                    and failure["address"] + failure["length"] >= target + length):
                matched.append(failure)
    return matched


def analyze(directory):
    native_mode = False
    stack = directory / "project-isac-stack-probe.log"
    if stack.exists():
        with stack.open() as source:
            for index, line in enumerate(source):
                if index >= 65536:
                    break
                record = path_record(line[:2048])
                if record and record["tag"] == "SDK_PROTECT_PATH" and record["status"] == "native-only":
                    native_mode = True
                    break
    records = []
    maps = directory / "sdk-protection-maps.jsonl"
    if maps.exists():
        with maps.open() as source:
            for index, line in enumerate(source):
                if index >= 512:
                    break
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    traces = sorted(directory.glob("sdk-protection-linux-*.log"))
    failures = []
    for path in traces:
        with path.open() as source:
            for index, line in enumerate(source):
                if index >= 65536:
                    break
                value = syscall(line[:1024])
                if value:
                    failures.append(value)
    matched = correlate(records, failures)
    output = ["SDK URL memory-protection diagnosis", "This is diagnostic evidence, not a repair or permission bypass.",
              f"Linux trace files: {len(traces)}; parsed failed permission calls: {len(failures)}",
              f"SDK call markers: {sum(item.get('event') == 'marker' for item in records)}",
              f"Linux mapping snapshots: {sum(item.get('event') == 'mapping' for item in records)}", ""]
    for item in records:
        if item.get("event") == "mapping":
            view = item["mapping"]
            output.append(f"URL target=0x{item['target']:x}, linux_pid={item['linux_pid']}, "
                          f"permissions={view['permissions']}, backing={view['backing_class']}, "
                          f"vm_flags={','.join(item['vm_flags'])}, security={json.dumps(item['security'], sort_keys=True)}")
    for item in matched:
        output.append(f"Correlated Linux refusal: tid={item['tid']} {item['api']} "
                      f"address=0x{item['address']:x} length={item['length']} "
                      f"protection={item['protection']} errno={item['errno']}")
    if native_mode:
        output.append("Linux strace is intentionally disabled in native dispatcher mode; see sdk-native-analysis.txt. No Linux-refusal conclusion can be drawn from its absence.")
    elif matched:
        output.append("A failed Linux permission change covers the URL in the recorded call window and a sampled game thread. "
                      "Use its errno and mapping permissions/flags to investigate the underlying restriction; "
                      "this alone does not identify a particular security policy.")
    else:
        output.append("No correlated Linux refusal found. This is NOT proof of API interception: "
                      "verify strace launch, call markers, mapping visibility/thread IDs and trace coverage first.")
    if not native_mode and not traces:
        output.append("Missing Linux syscall trace; verify the --sdk-protect-trace Steam option and strace availability.")
    if not any(item.get("event") == "mapping" for item in records):
        output.append("Missing target mapping; verify the diagnostic DLL/flag and SDK_PROTECT_HOLD marker.")
    output.extend(binding_report(directory))
    output.extend(code_report(directory))
    output.extend(path_report(directory))
    output.append("No packet payloads were logged. Code windows cover three named Wine APIs and one bounded private executable NtProtect jump destination of unknown origin. Tracing may change startup timing.")
    return "\n".join(output) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_dir", type=Path)
    arguments = parser.parse_args()
    print(analyze(arguments.capture_dir), end="")
