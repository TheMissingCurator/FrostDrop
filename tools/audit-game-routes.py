#!/usr/bin/env python3
"""Read-only, prefix-scoped socket inventory. No packets, DNS queries or hooks.

/proc/PID/net is namespace-wide. Attribute by PID/fd socket inode, not by the
presence of a row in that table. Sampling is not an exhaustive connection trace.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import struct
import sys
import threading

LOCAL_PORTS = {27015, 51000, 55000, 55001, 55002, 55003}
TABLES = ("tcp", "tcp6", "udp", "udp6")
TCP_STATES = {1: "established", 2: "syn-sent", 3: "syn-recv", 4: "fin-wait-1",
              5: "fin-wait-2", 6: "time-wait", 7: "close", 8: "close-wait",
              9: "last-ack", 10: "listen", 11: "closing", 12: "new-syn-recv"}
LIMITATIONS = (
    "Sampled prefix-owned sockets, not an exhaustive connect/send trace. Short-lived sockets may be missed. "
    "Unconnected UDP sends and delegated host Steam/launcher traffic are not covered. "
    "No DNS lookups, hostname/URL reconstruction, payloads or account data. "
    "Non-loopback endpoints are replacement candidates, not proof of Ubisoft ownership. "
    "An observed TCP state is not proof of SDK/login/backend acceptance."
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def identity(path):
    value = path.stat()
    if not path.is_dir():
        raise ValueError("prefix-not-directory")
    return value.st_dev, value.st_ino


def process_prefix(process):
    with (process / "environ").open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("environment-limit")
    selected = {}
    for entry in data.split(b"\0"):
        key, separator, value = entry.partition(b"=")
        if separator and key in (b"WINEPREFIX", b"STEAM_COMPAT_DATA_PATH"):
            selected[key] = os.fsdecode(value)
    if selected.get(b"WINEPREFIX"):
        prefix = Path(selected[b"WINEPREFIX"])
    elif selected.get(b"STEAM_COMPAT_DATA_PATH"):
        prefix = Path(selected[b"STEAM_COMPAT_DATA_PATH"]) / "pfx"
    else:
        raise ValueError("unidentified-prefix")
    if not prefix.is_absolute():
        raise ValueError("relative-prefix")
    return identity(process / "root" / str(prefix).lstrip("/"))


def process_metadata(process):
    # comm is metadata only; never inspect or emit command lines/environments.
    name = (process / "comm").read_text()[:64].strip()
    folded = name.casefold()
    if not (folded.startswith("wine") or folded.endswith(".exe") or
            folded in {"proton", "python3", "python", "pressure-vessel", "pv-bwrap"}):
        return None
    data = (process / "stat").read_text()
    end = data.rfind(")")
    if end < 0:
        raise ValueError("invalid-stat")
    start = int(data[end + 1:].split()[19])
    # Strict single-field output even if a hostile comm contains delimiters.
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", name), start


def socket_inodes(process):
    values = set()
    for index, entry in enumerate((process / "fd").iterdir()):
        if index >= 65536:
            raise ValueError("fd-limit")
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            values.add(int(match[1]))
    return values


def endpoint(value, ipv6):
    raw, port = value.split(":")
    if len(raw) != (32 if ipv6 else 8) or not re.fullmatch(r"[0-9A-Fa-f]+", raw):
        raise ValueError("invalid-address")
    # Kernel /proc renders native-endian u32 words, including each IPv6 word.
    address = b"".join(struct.pack("=I", int(raw[i:i + 8], 16)) for i in range(0, len(raw), 8))
    number = int(port, 16)
    if not 0 <= number <= 65535:
        raise ValueError("invalid-port")
    return str(ipaddress.ip_address(address)), number


def parse_table(lines, table, inodes):
    for index, line in enumerate(lines):
        if index >= 65536:
            raise ValueError("table-limit")
        fields = line.split()
        if len(fields) < 10 or not fields[0].endswith(":") or not fields[0][:-1].isdigit():
            continue
        inode = int(fields[9])
        if inode not in inodes:
            continue  # Never record other processes' namespace-wide sockets.
        address, port = endpoint(fields[2], table.endswith("6"))
        state = int(fields[3], 16)
        ip = ipaddress.ip_address(address)
        effective = ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip
        if effective.is_unspecified or port == 0 or (table.startswith("tcp") and state == 10):
            continue  # Listener/unconnected sockets have no peer destination.
        yield {"protocol": "tcp" if table.startswith("tcp") else "udp", "family": ip.version,
               "destination": address, "port": port, "inode": inode,
               "state": TCP_STATES.get(state, "unknown") if table.startswith("tcp") else "udp-peer"}


def route_class(address, port):
    ip = ipaddress.ip_address(address)
    effective = ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip
    if effective.is_loopback:
        if port in LOCAL_PORTS:
            return "local-backend-port"
        if port == 57343:
            return "local-steam-ipc-port"
        return "other-loopback"
    return "non-loopback-candidate"


class RouteAudit:
    def __init__(self, prefix, emit, proc=Path("/proc"), limit=4096):
        self.prefix_identity = identity(Path(prefix))
        self.proc = Path(proc)
        self.emit = emit
        self.limit = limit
        self.samples = 0
        self.errors = {"prefix_unavailable": 0, "fd_unavailable": 0, "table_unavailable": 0,
                       "metadata_unavailable": 0, "scan_unavailable": 0}
        self.processes = set()
        self.seen = set()
        self.routes = {}
        self.capped = False

    def sample(self):
        self.samples += 1
        if self.capped:
            return
        try:
            processes = list(self.proc.iterdir())
        except OSError:
            self.errors["scan_unavailable"] += 1
            return
        for process in processes:
            if not process.name.isdigit():
                continue
            try:
                if process.stat().st_uid != os.getuid():
                    continue
                metadata = process_metadata(process)
            except FileNotFoundError:
                continue
            except (OSError, ValueError, IndexError):
                self.errors["metadata_unavailable"] += 1
                continue
            if metadata is None:
                continue
            try:
                if process_prefix(process) != self.prefix_identity:
                    continue
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                self.errors["prefix_unavailable"] += 1
                continue
            name, start = metadata
            pid = int(process.name)
            if len(self.processes) < 4096:
                self.processes.add((pid, start))
            try:
                inodes = socket_inodes(process)
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                self.errors["fd_unavailable"] += 1
                continue
            if not inodes:
                continue
            for table in TABLES:
                try:
                    with (process / "net" / table).open() as stream:
                        for item in parse_table(stream, table, inodes):
                            self.record(pid, start, name, item)
                            if self.capped:
                                return
                except FileNotFoundError:
                    # A process racing exit or an unavailable IPv6 table.
                    continue
                except (OSError, ValueError):
                    self.errors["table_unavailable"] += 1

    def record(self, pid, start, name, item):
        key = (pid, start, item["inode"], item["protocol"], item["destination"], item["port"], item["state"])
        if key in self.seen:
            return
        if len(self.seen) >= self.limit:
            self.capped = True
            self.emit({"event": "limit", "max_events": self.limit})
            return
        self.seen.add(key)
        classified = route_class(item["destination"], item["port"])
        self.emit({"event": "socket", "at": utc_now(), "pid": pid, "process": name,
                   "route_class": classified, **item})
        endpoint_key = (item["protocol"], item["destination"], item["port"])
        if endpoint_key not in self.routes:
            self.routes[endpoint_key] = {"protocol": item["protocol"], "destination": item["destination"],
                                         "port": item["port"], "route_class": classified,
                                         "observations": 0, "processes": set(), "states": set()}
        route = self.routes[endpoint_key]
        route["observations"] += 1
        route["processes"].add(name)
        route["states"].add(item["state"])

    def summary(self):
        routes = []
        for key in sorted(self.routes):
            value = dict(self.routes[key])
            value["processes"] = sorted(value["processes"])
            value["states"] = sorted(value["states"])
            routes.append(value)
        return {"samples": self.samples, "matched_processes": len(self.processes), "events": len(self.seen),
                "limit_reached": self.capped, "inspection_errors": self.errors, "limitations": LIMITATIONS,
                "routes": routes}


def report(value):
    lines = ["Division-prefix route inventory (metadata only)", value["limitations"],
             f"Samples: {value['samples']}; matched processes: {value['matched_processes']}; "
             f"events: {value['events']}; limit reached: {value['limit_reached']}",
             "Inspection errors: " + json.dumps(value["inspection_errors"], sort_keys=True), ""]
    if not value["routes"]:
        lines.append("No attributable peer endpoints observed. This is not proof of no external traffic.")
    for item in value["routes"]:
        lines.append(f"{item['route_class']} {item['protocol']} [{item['destination']}]:{item['port']} "
                     f"processes={','.join(item['processes'])} states={','.join(item['states'])}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--max-events", type=int, default=4096)
    args = parser.parse_args()
    if not 0.05 <= args.interval <= 2 or not 1 <= args.max_events <= 16384:
        parser.error("invalid interval or event limit")
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        with (args.output_dir / "route-audit.jsonl").open("x") as stream:
            def emit(value):
                stream.write(json.dumps(value, sort_keys=True) + "\n")
                stream.flush()
            audit = RouteAudit(args.prefix, emit, proc=Path(os.environ.get("ISAC_HOST_PROC", "/proc")),
                               limit=args.max_events)
            emit({"event": "ready", "at": utc_now(), "interval_seconds": args.interval,
                  "max_events": args.max_events, "scope": "matching-wine-prefix", "limitations": LIMITATIONS})
            while not stop.is_set():
                audit.sample()
                stop.wait(args.interval)
            audit.sample()
            value = audit.summary()
            emit({"event": "finished", "at": utc_now(), "samples": value["samples"], "events": value["events"]})
        with (args.output_dir / "route-audit-summary.json").open("x") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
        with (args.output_dir / "route-audit-summary.txt").open("x") as stream:
            stream.write(report(value))
    except (OSError, ValueError) as error:
        # Avoid printing arbitrary process data or paths in exception strings.
        print("ROUTE_AUDIT_ERROR type=" + type(error).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
