#!/usr/bin/env python3
"""Summarize private allocation captures without printing payloads or endpoints."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from pathlib import Path
import struct

MAGIC = b"ISACAL01"
HEADER = struct.Struct("<IIIIQQQII")
KINDS = {1: "tls-inbound", 2: "message-status", 3: "parsed-allocation", 4: "handoff"}
SITES = {1: 0x224817B, 2: 0xF11D8, 3: 0xF1251, 4: 0xBB4DF}


def parse_capture(data: bytes) -> list[dict]:
    if len(data) > 1048576 + 128 * HEADER.size + len(MAGIC):
        raise ValueError("capture exceeds size limit")
    if not data.startswith(MAGIC):
        raise ValueError("missing allocation capture header (wrapper or hook not active)")
    offset = len(MAGIC)
    records = []
    previous_tick = 0
    while offset < len(data):
        if len(data) - offset < HEADER.size:
            raise ValueError("truncated record header")
        kind, seq, thread, size, tick, obj, site, result, reserved = HEADER.unpack_from(data, offset)
        offset += HEADER.size
        if kind not in KINDS or site != SITES[kind] or reserved:
            raise ValueError("invalid record kind/site/reserved field")
        if seq != len(records) + 1 or seq > 128 or tick < previous_tick:
            raise ValueError("invalid sequence or timestamp order")
        if size > 65536 or size > len(data) - offset:
            raise ValueError("invalid or truncated payload length")
        payload = data[offset:offset + size]
        records.append(dict(kind=kind, sequence=seq, thread=thread, tick=tick,
                            object=obj, site=site, result=result, payload=payload))
        offset += size
        previous_tick = tick
    return records


def summarize(path: Path) -> None:
    # Files remain private; the summary contains only sizes, hashes and scalars.
    if path.stat().st_size > 1048576 + 128 * HEADER.size + len(MAGIC):
        raise ValueError("capture exceeds size limit")
    data = path.read_bytes()
    records = parse_capture(data)
    print(f"Private capture: {path}")
    print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")
    counts = Counter(KINDS[r['kind']] for r in records)
    print(f"Records: {len(records)}; stages: {dict(counts)}")
    objects: dict[int, int] = {}
    for record in records:
        obj = objects.setdefault(record['object'], len(objects) + 1)
        payload = record['payload']
        print(f"  seq={record['sequence']} tick={record['tick']} "
              f"thread={record['thread']} object={obj} stage={KINDS[record['kind']]} "
              f"bytes={len(payload)} result={record['result']} "
              f"sha256={hashlib.sha256(payload).hexdigest()}")
    inbound = [r['payload'] for r in records if r['kind'] == 1]
    parsed = [r['payload'] for r in records if r['kind'] == 3 and r['result'] and r['payload']]
    handoffs = [r['payload'] for r in records if r['kind'] == 4]
    print(f"Decrypted inbound bytes: {sum(map(len, inbound))}")
    print(f"Successful parsed responses: {len(parsed)}")
    print(f"Parsed response matches handoff: {any(p in handoffs for p in parsed)}")
    print("Status: " + ("plaintext and parsed response available for schema analysis"
          if inbound and parsed else "incomplete; inspect stage events before requesting another run"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--since", type=Path, required=True)
    parser.add_argument("--stack-log", type=Path, required=True)
    args = parser.parse_args()
    log = args.stack_log.read_text(errors="replace") if args.stack_log.exists() else ""
    print(f"Capture initialized: {'TCTD_ALLOCATION_READY ' in log}")
    for line in log.splitlines():
        if line.startswith(("TCTD_ALLOCATION_ERROR ", "TCTD_ALLOCATION_DROP ", "DISPATCH_PROBE_ERROR ")):
            print(line)
    cutoff = args.since.stat().st_mtime_ns
    files = sorted(p for p in args.private_root.glob("tctd-allocation-*/records.bin")
                   if p.stat().st_mtime_ns >= cutoff)
    if not files:
        print("No fresh private capture. Check Steam wrapper selection.")
    for path in files:
        try:
            summarize(path)
        except (OSError, ValueError) as error:
            print(f"Capture incomplete: {path}: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
