#!/usr/bin/env python3
"""Inspect selected static strings and candidate RIP-relative LEA references.

Reads private snapshots locally; performs no network requests. References are
byte-pattern candidates and require disassembly verification, not a call graph.
"""
import argparse
import hashlib
from pathlib import Path
import re
import struct

RDATA_RVA = 0x2901000
RDATA_SIZE = 0x152CC8A
TEXT_SHA256 = "dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74"


def load_section(path):
    if path.stat().st_size != RDATA_SIZE + 16:
        raise ValueError("missing, partial or unexpected static snapshot size")
    with path.open("rb") as stream:
        header = stream.read(16)
        magic, rva, length = struct.unpack("<8sII", header)
        if (magic, rva, length) != (b"ISACRD01", RDATA_RVA, RDATA_SIZE):
            raise ValueError("unsupported static snapshot header")
        return stream.read(length)


def strings(data, base=RDATA_RVA):
    for match in re.finditer(rb"[\x20-\x7e\r\n\t]{4,}\x00", data):
        yield base + match.start(), "ascii", match[0][:-1].decode("ascii")
    for match in re.finditer(rb"(?:[\x20-\x7e\r\n\t]\x00){4,}\x00\x00", data):
        yield base + match.start(), "utf16le", match[0][:-2].decode("utf-16le")


def string_at(data, rva, base=RDATA_RVA):
    offset = rva - base
    if not 0 <= offset < len(data):
        raise ValueError("requested RVA outside static section")
    bounded = data[offset:offset + 4096]
    if len(bounded) >= 2 and bounded[1] == 0:
        end = next((i for i in range(0, len(bounded) - 1, 2)
                    if bounded[i:i + 2] == b"\x00\x00"), None)
        if end is not None:
            return "utf16le", bounded[:end].decode("utf-16le", errors="replace")
    end = bounded.find(b"\x00")
    if end < 0:
        raise ValueError("no bounded string terminator")
    return "ascii", bounded[:end].decode("ascii", errors="replace")


def lea_references(text, targets, base=0x1000):
    found = {rva: [] for rva in targets}
    for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text):
        offset = match.start()
        if offset + 7 > len(text):
            continue
        target = base + offset + 7 + struct.unpack_from("<i", text, offset + 3)[0]
        if target in found:
            found[target].append(base + offset)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--text", type=Path, help="the previously verified runtime text snapshot")
    parser.add_argument("--contains", action="append", help="case-insensitive static string filter")
    parser.add_argument("--rva", action="append", type=lambda value: int(value, 0), default=[])
    args = parser.parse_args()
    try:
        data = load_section(args.snapshot)
        needles = [value.lower() for value in (args.contains or
                   ["static2", "public-ubiservices", " HTTP/1."])]
        selected = {rva: (encoding, value) for rva, encoding, value in strings(data)
                    if any(needle in value.lower() for needle in needles)}
        for rva in args.rva:
            selected[rva] = string_at(data, rva)
        if len(selected) > 256:
            raise ValueError("too many matching strings; narrow --contains")
        refs = {}
        if args.text:
            if args.text.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("oversized text snapshot")
            code = args.text.read_bytes()
            if hashlib.sha256(code).hexdigest() != TEXT_SHA256:
                raise ValueError("text snapshot does not match the verified build")
            refs = lea_references(code, selected)
        print(f"Static section: RVA={RDATA_RVA:#x}, bytes={len(data)}, matches={len(selected)}")
        for rva, (encoding, value) in sorted(selected.items()):
            print(f"{rva:#x} {encoding}: {value[:512]!r}")
            if args.text:
                print("  candidate LEA sites: " + (", ".join(hex(site) for site in refs[rva][:32]) or "none"))
        print("Candidate references require instruction-boundary verification; no runtime dependency is proven.")
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"Static analysis failed: {error}\n")


if __name__ == "__main__":
    main()
