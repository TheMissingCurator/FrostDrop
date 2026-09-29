#!/usr/bin/env python3
"""Summarize Division-dedicated Winsock activity from a Proton log."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


TARGET_PORTS = {51000, 55000, 55002}
LINE_RE = re.compile(
    r"^(?P<time>\d+(?:\.\d+)?):(?P<pid>[0-9a-fA-F]+):"
    r"(?P<tid>[0-9a-fA-F]+):(?P<level>[^:]+):(?P<channel>[^:]+):(?P<body>.*)$"
)
CONNECT_RE = re.compile(
    r"^connect socket (?P<handle>0x[0-9a-fA-F]+), addr \{ family AF_INET, "
    r"address (?P<address>[^,]+), port (?P<port>\d+) \}"
)
SOCKET_RE = re.compile(r"\b(?:socket|handle) (?P<handle>0x[0-9a-fA-F]+)\b")
FUNCTION_RE = re.compile(r"^(?P<function>[^ (]+)")
DNS_RE = re.compile(
    r'^getaddrinfo node "(?P<node>[^"]+)", service "(?P<service>[^"]+)"'
)
GAME_LOAD_RE = re.compile(r"Loaded L\"[^\"]*\\thedivision\.exe\"", re.IGNORECASE)


@dataclass
class TraceLine:
    timestamp: float
    pid: str
    tid: str
    channel: str
    body: str


@dataclass
class Session:
    timestamp: float
    tid: str
    handle: str
    address: str
    port: int
    calls: Counter[str] = field(default_factory=Counter)
    threads: Counter[str] = field(default_factory=Counter)
    last_timestamp: float | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Report socket handles, threads, endpoints, and call counts for "
            "Division ports 51000, 55000, and 55002. Payloads are not read."
        )
    )
    parser.add_argument("log", type=Path, help="Proton steam-365590.log")
    parser.add_argument(
        "--pid",
        help="Windows process ID in hexadecimal; auto-detected when omitted",
    )
    return parser.parse_args()


def read_trace(path: Path) -> tuple[list[TraceLine], set[str], Counter[str]]:
    lines: list[TraceLine] = []
    game_pids: set[str] = set()
    winsock_counts: Counter[str] = Counter()

    with path.open("r", encoding="utf-8", errors="replace") as source:
        for raw_line in source:
            match = LINE_RE.match(raw_line)
            if not match:
                continue
            pid = match.group("pid").lower()
            channel = match.group("channel")
            body = match.group("body").rstrip("\r\n")
            if channel == "loaddll" and GAME_LOAD_RE.search(body):
                game_pids.add(pid)
            if channel == "winsock":
                winsock_counts[pid] += 1
            lines.append(
                TraceLine(
                    timestamp=float(match.group("time")),
                    pid=pid,
                    tid=match.group("tid").lower(),
                    channel=channel,
                    body=body,
                )
            )

    return lines, game_pids, winsock_counts


def choose_pid(
    requested: str | None, game_pids: set[str], winsock_counts: Counter[str]
) -> str:
    if requested:
        return requested.lower().removeprefix("0x").zfill(4)
    candidates = [pid for pid in game_pids if winsock_counts[pid]]
    if not candidates:
        raise ValueError(
            "could not auto-detect a thedivision.exe process with Winsock traces; "
            "pass --pid"
        )
    return max(candidates, key=winsock_counts.__getitem__)


def analyze(lines: list[TraceLine], pid: str) -> tuple[list[tuple], list[Session]]:
    dns_queries: list[tuple[float, str, str, str]] = []
    sessions: list[Session] = []
    active: dict[str, Session] = {}

    for line in lines:
        if line.pid != pid or line.channel != "winsock":
            continue

        dns_match = DNS_RE.match(line.body)
        if dns_match and (
            dns_match.group("service") in {str(port) for port in TARGET_PORTS}
            or dns_match.group("node").lower().startswith("tctd-")
        ):
            dns_queries.append(
                (
                    line.timestamp,
                    line.tid,
                    dns_match.group("node"),
                    dns_match.group("service"),
                )
            )

        connect_match = CONNECT_RE.match(line.body)
        if connect_match:
            handle = connect_match.group("handle").lower()
            active.pop(handle, None)
            port = int(connect_match.group("port"))
            if port in TARGET_PORTS:
                session = Session(
                    timestamp=line.timestamp,
                    tid=line.tid,
                    handle=handle,
                    address=connect_match.group("address"),
                    port=port,
                )
                sessions.append(session)
                active[handle] = session

        socket_match = SOCKET_RE.search(line.body)
        function_match = FUNCTION_RE.match(line.body)
        if not socket_match or not function_match:
            continue
        handle = socket_match.group("handle").lower()
        session = active.get(handle)
        if session is None:
            continue
        function = function_match.group("function")
        if function in {"WS2_recv_base", "WS2_sendto", "shutdown", "closesocket"}:
            session.calls[function] += 1
            session.threads[line.tid] += 1
            session.last_timestamp = line.timestamp
        if function in {"shutdown", "closesocket"}:
            active.pop(handle, None)

    return dns_queries, sessions


def main() -> int:
    args = parse_args()
    lines, game_pids, winsock_counts = read_trace(args.log)
    try:
        pid = choose_pid(args.pid, game_pids, winsock_counts)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    dns_queries, sessions = analyze(lines, pid)
    print(f"Trace: {args.log}")
    print(f"Game PID: 0x{pid} ({int(pid, 16)})")
    print(f"Game Winsock trace lines: {winsock_counts[pid]}")

    print("\nDedicated-service DNS queries:")
    if not dns_queries:
        print("  <none observed>")
    for timestamp, tid, node, service in dns_queries:
        print(f"  +{timestamp:.3f} thread=0x{tid} {node}:{service}")

    print("\nDedicated socket sessions:")
    if not sessions:
        print("  <none observed>")
    for session in sessions:
        duration = "unknown"
        if session.last_timestamp is not None:
            duration = f"{session.last_timestamp - session.timestamp:.3f}s traced"
        print(
            f"  +{session.timestamp:.3f} thread=0x{session.tid} "
            f"socket={session.handle} -> {session.address}:{session.port} "
            f"({duration})"
        )
        if session.calls:
            calls = ", ".join(
                f"{name}={count}" for name, count in session.calls.most_common()
            )
            print(f"    calls: {calls}")
        if session.threads:
            threads = ", ".join(
                f"0x{tid}={count}" for tid, count in session.threads.most_common()
            )
            print(f"    servicing threads: {threads}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
