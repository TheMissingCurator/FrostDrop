#!/usr/bin/env python3
"""Summarize observational login checkpoints without inferring a successful login."""
import argparse
from collections import Counter
from pathlib import Path
import re


def summarize(text, expected_sweep=None):
    ready = sum(line.startswith("LOGIN_HANDOFF_READY ") for line in text.splitlines())
    counts = Counter()
    transitions = []
    signals = set()
    limits = 0
    coverage = []
    modes = set()
    exceptions = []
    zero_debug_resumes = sum(line.startswith("LOGIN_HANDOFF_ZERO_DEBUG_RESUMED ")
                             for line in text.splitlines())
    for line in text.splitlines():
        if line.startswith("LOGIN_HANDOFF_CONFIG "):
            mode = re.search(r"detail=sweep=(off|on),", line)
            if mode:
                modes.add(mode[1])
        if line.startswith("LOGIN_HANDOFF_EXCEPTION ") and "detail=" in line:
            fields = dict(part.split("=", 1) for part in line.split("detail=", 1)[1].split(",")
                          if "=" in part)
            names = ("sequence", "code", "tick-ms", "thread", "rip", "game-rva", "flags",
                     "access", "dr6", "dr7")
            exceptions.append(" ".join(f"{k}={fields[k].strip()}" for k in names
                if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", fields.get(k, "").strip())))
        if line.startswith("LOGIN_HANDOFF_COVERAGE ") and "detail=" in line:
            fields = dict(part.split("=", 1) for part in line.split("detail=", 1)[1].split(",")
                          if "=" in part)
            names = ("pass", "seen", "verified", "repaired", "conflicts", "unverified",
                     "resume-failed", "enumeration-error")
            coverage.append({k: int(fields[k]) for k in names
                             if re.fullmatch(r"\d{1,10}", fields.get(k, "").strip())})
        if line.startswith("LOGIN_HANDOFF_LIMIT "):
            limits += 1
        if not line.startswith("LOGIN_HANDOFF_CHECKPOINT "):
            continue
        match = re.search(r"detail=(.*)", line)
        if not match:
            continue
        fields = dict(part.split("=", 1) for part in match[1].split(",") if "=" in part)
        stage = fields.get("stage", "unknown")
        if stage not in ("services-poll", "frontend-before-sync", "channel-before-state-gate"):
            continue
        counts[stage] += 1
        # Only copy known numeric fields into the report, never arbitrary log data.
        names = {
            "services-poll": ("async-present", "async-state", "worker-flag108"),
            "frontend-before-sync": ("services-state", "auth-state", "services330-nonempty",
                "services-ticket-present", "auth-ticket-present", "auth-ea0-nonempty",
                "auth-flag10", "ticket-changed", "auth-flag1120", "suppress-auth", "suppress-copy",
                "auth-client-present", "pending-ticket-login", "channel-present", "manager-state"),
            "channel-before-state-gate": ("manager-state", "kind", "channel-param"),
        }[stage]
        numeric = {k: int(fields[k]) for k in names
                   if re.fullmatch(r"-?\d{1,10}", fields.get(k, ""))}
        transitions.append(stage + " " + " ".join(f"{k}={v}" for k, v in numeric.items()))
        if stage == "frontend-before-sync":
            for k in ("services-ticket-present", "auth-ticket-present", "pending-ticket-login",
                      "suppress-auth", "suppress-copy"):
                if numeric.get(k) == 1:
                    signals.add(k)
        if stage == "channel-before-state-gate" and numeric.get("kind") == 0:
            signals.add("kind-0-channel-attempt")
            if numeric.get("manager-state") == 2:
                signals.add("kind-0-manager-state-2")
    result = [f"Ready events: {ready}", f"Record-limit events: {limits}",
              "Unknown/unreadable fields are -1, not false."]
    if any(line.startswith("STACK_PROBE_LOG_ERROR ") for line in text.splitlines()):
        result.append("WARNING: status logging dropped a record due to formatting/size; observations are incomplete.")
    if not ready:
        result.append("WARNING: no ready marker; verify wrapper, installed DLL and signature errors.")
    result.append("Observed sweep mode: " + (", ".join(sorted(modes)) or "unknown"))
    result.append(f"Zero-debug checkpoint resume records: {zero_debug_resumes} (log capped at 16)")
    if expected_sweep is not None and modes != {expected_sweep}:
        result.append(f"WARNING: expected sweep={expected_sweep}; A/B label does not match confirmed configuration.")
    result.append(f"First-chance exception records: {len(exceptions)} (bounded; not proof of a fatal crash)")
    result.extend(exceptions[:32])
    result.append(f"Thread-coverage reports: {len(coverage)}")
    if not coverage and modes == {"off"}:
        result.append("Sweeping disabled intentionally; startup/socket-hook arming remains enabled.")
    elif not coverage:
        result.append("WARNING: no thread readback evidence; readiness does not establish coverage.")
    else:
        result.append("Latest coverage: " + " ".join(f"{k}={v}" for k, v in coverage[-1].items()))
        if not coverage[-1].get("verified", 0):
            result.append("WARNING: latest coverage report verifies no peer threads.")
        if any(any(c.get(k, 0) for k in ("conflicts", "unverified", "resume-failed",
                                        "enumeration-error")) for c in coverage):
            result.append("WARNING: coverage reported conflicts, failures or incomplete enumeration.")
        result.append("Coverage is sampled every 250 ms; short-lived threads/early calls may be missed.")
    if ready and not counts:
        result.append("WARNING: zero checkpoint hits; do not infer missing tickets from this capture.")
    for stage in ("services-poll", "frontend-before-sync", "channel-before-state-gate"):
        result.append(f"{stage}: {counts[stage]} recorded transitions")
    result.append("Observed positive signals: " + (", ".join(sorted(signals)) or "none"))
    result.append("Frontend records precede copying/dispatch; absence is not proof a path never ran.")
    result.append("Channel attempts/state 2 do not prove selection, TCP/TLS, login or world loading.")
    result.extend(transitions[:384])
    return "\n".join(result) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--expected-sweep", choices=("off", "on"))
    args = parser.parse_args()
    print(summarize(args.log.read_text(errors="replace"), args.expected_sweep), end="")


if __name__ == "__main__":
    main()
