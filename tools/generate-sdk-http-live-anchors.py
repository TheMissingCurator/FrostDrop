#!/usr/bin/env python3
"""Generate build-only live instruction anchors from the verified private snapshot."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("abi", ROOT / "tools/verify-sdk-http-request-abi.py")
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)
text = (ROOT / "private" / f"tctd-runtime-text-{abi.TEXT_HASH}.bin").read_bytes()
rdata = (ROOT / "private/startup-leads-jcoCPbG7/static-rdata.bin").read_bytes()
abi.verify(text, rdata)
addresses = set(abi.FUNCTIONS.values())
for _, destroy, method, clone, _ in abi.CLASSES.values():
    addresses.update((destroy, method, clone))
addresses.update((0x20FA7FA, 0x20FA804, 0x2111E60, 0x2110E20, 0x21E3720))
print("/* Generated from a hash-verified snapshot; do not edit. */")
print("static const struct { uintptr_t rva; unsigned char bytes[32]; } live_anchors[] = {")
for rva in sorted(addresses):
    data = text[rva - 0x1000:rva - 0x1000 + 32]
    print("{0x%xu, {%s}}," % (rva, ",".join("0x%02x" % b for b in data)))
print("};")
