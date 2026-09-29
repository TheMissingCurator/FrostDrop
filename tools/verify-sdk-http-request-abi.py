#!/usr/bin/env python3
"""Read-only request/result ABI snapshot checks; never resolves live calls."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TEXT_HASH = "dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74"
CLASSES = {
    "GET": (0x346D738, 0x212FF80, 0x217A5E0, 0x2153E30, 0),
    "POST": (0x346D750, 0x212FFE0, 0x217A5F0, 0x2153E70, 1),
    "DELETE": (0x346D720, 0x212FE60, 0x217A5D0, 0x2153DF0, 4),
}
FUNCTIONS = {
    "string_from_utf8": 0x211ABE0,
    "string_destroy": 0x3C160,
    "url_parse": 0x211B490,
    "url_format": 0x217DB90,
    "url_assign": 0x2127390,
    "url_destroy": 0x21240F0,
    "future_construct": 0x2104BA0,
    "future_complete": 0x21E3640,
    "future_copy": 0x2104AF0,
    "future_destroy": 0x212D970,
    "http_dispatch": 0x21DBAD0,
    "http_destroy": 0x212FE30,
}
FUTURE_TABLES = {
    "future": (0x346D030, 0x212D970),
    "state": (0x346C388, 0x2130510),
    "response": (0x3475C50, 0x2130890),
}


def verify(text, rdata):
    if hashlib.sha256(text).hexdigest() != TEXT_HASH:
        raise ValueError("unsupported runtime text snapshot")
    if len(rdata) != 16 + 0x152CC8A or struct.unpack_from("<8sII", rdata) != (
            b"ISACRD01", 0x2901000, 0x152CC8A):
        raise ValueError("unsupported static data snapshot")

    def expect(rva, expected):
        if text[rva - 0x1000:rva - 0x1000 + len(expected)] != expected:
            raise ValueError(f"instruction anchor mismatch at {rva:#x}")

    def edge(site, target, opcode=0xE8):
        expect(site, bytes([opcode]) + struct.pack("<i", target - site - 5))

    for table, destroy, method, clone, method_id in CLASSES.values():
        actual = struct.unpack_from("<QQQ", rdata, 16 + table - 0x2901000)
        if actual != tuple(0x140000000 + rva for rva in (destroy, method, clone)):
            raise ValueError(f"request vtable mismatch at {table:#x}")
        expect(method, b"\x33\xc0\xc3" if method_id == 0 else
               b"\xb8" + struct.pack("<I", method_id) + b"\xc3")
    for site in (0x21273A0, 0x21273B0, 0x21273C6, 0x21273DC,
                 0x21273FE, 0x2127414, 0x212742A, 0x2127440):
        edge(site, 0x2124910)
    expect(0x21273F2, bytes.fromhex("8b 83 60 01 00 00 89 87 60 01 00 00"))
    edge(0x21E2C20, FUNCTIONS["url_assign"])
    edge(0x211B4D3, FUNCTIONS["string_from_utf8"])
    edge(0x21DBD0A, FUNCTIONS["url_format"])
    edge(0x2120835, FUNCTIONS["url_destroy"], 0xE9)
    edge(0x2124100, FUNCTIONS["string_destroy"])
    edge(0x2153E20, 0x210F970, 0xE9)
    edge(0x2153E60, 0x21100A0, 0xE9)
    edge(0x2153EA0, 0x2110250, 0xE9)
    edge(0x212FE6F, 0x21207C0)
    expect(0x21DBD8F, bytes.fromhex("49 8b 16 48 8b 42 10 48 63 48 04 48 8b 7c 11 20"))
    for name, (table, destroy) in FUTURE_TABLES.items():
        actual = struct.unpack_from("<Q", rdata, 16 + table - 0x2901000)[0]
        if actual != 0x140000000 + destroy:
            raise ValueError(f"{name} vtable mismatch at {table:#x}")
    # Same owned state/response types in reusable ctor and no-job early failure.
    for site in (0x2104BDC, 0x21D9C72, 0x21DBE46):
        edge(site, 0x2111E60)
    for site in (0x2104C34, 0x21D9CCB, 0x21DBE9F):
        edge(site, 0x2110E20)
    edge(0x21E3680, 0x21E3720)  # synchronized completion -> state transition
    edge(0x21E3744, 0x2124910)  # retain/copy error message
    edge(0x21E3788, 0x2152410)  # dependency cleanup
    edge(0x21D9D7B, FUNCTIONS["string_from_utf8"])
    edge(0x21D9EBE, FUNCTIONS["string_destroy"])
    for site in (0x21D9F44, 0x21DC34B):
        edge(site, FUNCTIONS["future_copy"])
    edge(0x212D9CD, 0x21FBF80)  # conditional wrapper deallocation; flags=0 skips
    if struct.unpack_from("<QQ", rdata, 16 + 0x346D628 - 0x2901000) != (
            0x140000000 + FUNCTIONS["http_destroy"], 0x140000000 + FUNCTIONS["http_dispatch"]):
        raise ValueError("HTTP service vtable mismatch")
    if struct.unpack_from("<Q", rdata, 16 + 0x346CF68 - 0x2901000)[0] != 0x14212FDE0:
        raise ValueError("HTTP wrapper vtable mismatch")
    edge(0x20FA7FA, 0x21E30A0)  # concrete state binding
    expect(0x20FA7FF, bytes.fromhex("eb 03"))  # required stopped event, NOT installed hook
    expect(0x20FA81B, bytes.fromhex("48 89 3b"))  # facade publication
    expect(0x212FDF9, bytes.fromhex("48 8b 49 10"))  # wrapper owns interface
    expect(0x212FE05, bytes.fromhex("ba 01 00 00 00 ff 10"))  # deleting destructor flag
    edge(0x212FE3F, 0x21204D0)
    edge(0x212FE4C, 0x21FBF80)
    return {
        "status": "snapshot-anchors-verified-not-live-validation",
        "text_sha256": TEXT_HASH,
        "functions_rva": {name: hex(rva) for name, rva in FUNCTIONS.items()},
        "requests": {name: {"vtable_rva": hex(values[0]), "native_method": values[4]}
                     for name, values in CLASSES.items()},
        "future_vtables_rva": {name: hex(values[0]) for name, values in FUTURE_TABLES.items()},
        "http_service": {"vtable_rva": "0x346d628", "wrapper_vtable_rva": "0x346cf68",
                         "required_publication_event_rva": "0x20fa7ff"},
        "live_installer": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", type=Path,
                        default=ROOT / "private" / f"tctd-runtime-text-{TEXT_HASH}.bin")
    parser.add_argument("--rdata", type=Path,
                        default=ROOT / "private/startup-leads-jcoCPbG7/static-rdata.bin")
    args = parser.parse_args()
    try:
        if args.text.stat().st_size > 64 * 1024 * 1024 or args.rdata.stat().st_size != 16 + 0x152CC8A:
            raise ValueError("unexpected snapshot size")
        print(json.dumps(verify(args.text.read_bytes(), args.rdata.read_bytes()), indent=2))
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"SDK request ABI verification failed: {error}\n")


if __name__ == "__main__":
    main()
