#!/usr/bin/env python3
"""Summarize the loopback-only TCTD acceptance and resulting TLS session."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


SUMMARY_PATTERN = re.compile(
    r"^TCTD_PC_CONNECTION_SUMMARY .* "
    r"stage=(?P<stage>\S+) outcome=(?P<outcome>\S+) .* "
    r"client_plaintext_bytes=(?P<bytes>\d+) "
    r"client_plaintext_sha256=(?P<digest>\S+)$"
)


def count_events(path: Path) -> tuple[Counter[str], list[str]]:
    events: Counter[str] = Counter()
    errors: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        event = line.split(maxsplit=1)[0]
        events[event] += 1
        if event == "TCTD_LOCAL_ACCEPT_ERROR":
            errors.append(line)
    return events, errors


def parse_listener(path: Path) -> tuple[Counter[str], list[tuple[str, str, int]]]:
    events: Counter[str] = Counter()
    summaries: list[tuple[str, str, int]] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line:
            continue
        event = line.split(maxsplit=1)[0]
        events[event] += 1
        if event != "TCTD_PC_CONNECTION_SUMMARY":
            continue
        match = SUMMARY_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"malformed connection summary on line {line_number}")
        summaries.append(
            (match["stage"], match["outcome"], int(match["bytes"]))
        )
    return events, summaries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stack_log", type=Path)
    parser.add_argument("listener_log", type=Path)
    args = parser.parse_args()
    try:
        stack_events, errors = count_events(args.stack_log)
        listener_events, summaries = parse_listener(args.listener_log)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Stack log: {args.stack_log}")
    print(f"Listener log: {args.listener_log}")
    print(f"Acceptance ready events: {stack_events['TCTD_LOCAL_ACCEPT_READY']}")
    print(f"Acceptance armed events: {stack_events['TCTD_LOCAL_ACCEPT_ARMED']}")
    print(f"Acceptance applied events: {stack_events['TCTD_LOCAL_ACCEPT_APPLIED']}")
    print(f"Acceptance skipped events: {stack_events['TCTD_LOCAL_ACCEPT_SKIPPED']}")
    print(f"Acceptance errors: {stack_events['TCTD_LOCAL_ACCEPT_ERROR']}")
    print(f"TLS-established events: {listener_events['TCTD_PC_TLS_ESTABLISHED']}")
    print(f"Certificate responses sent: {listener_events['TCTD_PC_CERTIFICATE_SENT']}")
    if listener_events['TCTD_PC_CERTIFICATE_SENT']:
        print("Certificate delivery is not proof of game-side certificate acceptance.")
    print(f"Connections summarized: {len(summaries)}")
    print(f"Client plaintext bytes: {sum(item[2] for item in summaries)}")
    for error in errors:
        print(f"ERROR: {error}")
    for stage, outcome, byte_count in summaries:
        print(
            f"CONNECTION stage={stage} outcome={outcome} "
            f"client_plaintext_bytes={byte_count}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
