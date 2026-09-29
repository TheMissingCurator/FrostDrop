#!/usr/bin/env python3
"""Read three allowlisted Proton-prefix DLLs; emit bounded API code references."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

APIS = {"kernel32.VirtualProtect": ("kernel32.dll", "VirtualProtect", 24),
        "kernelbase.VirtualProtect": ("kernelbase.dll", "VirtualProtect", 176),
        "ntdll.NtProtectVirtualMemory": ("ntdll.dll", "NtProtectVirtualMemory", 32)}


class PE:
    def __init__(self, data):
        self.data = data
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("DOS header")
        offset = self.number(60, "I")
        if offset < 64 or offset > 0x100000 or self.slice(offset, 4) != b"PE\0\0":
            raise ValueError("PE header")
        self.machine, count, self.timestamp = self.unpack(offset + 4, "HHI")
        optional_size = self.number(offset + 20, "H")
        optional = offset + 24
        if self.machine != 0x8664 or not 1 <= count <= 96 or optional_size < 240 or self.number(optional, "H") != 0x20b:
            raise ValueError("x64 optional header")
        self.image_base = self.number(optional + 24, "Q")
        self.image_size = self.number(optional + 56, "I")
        self.header_size = self.number(optional + 60, "I")
        if self.number(optional + 108, "I") < 6:
            raise ValueError("missing directories")
        self.export = self.unpack(optional + 112, "II")
        self.relocation = self.unpack(optional + 112 + 5 * 8, "II")
        self.sections = []
        for index in range(count):
            section = optional + optional_size + index * 40
            virtual_size, rva, raw_size, raw_offset = self.unpack(section + 8, "IIII")
            flags = self.number(section + 36, "I")
            self.sections.append((rva, virtual_size, raw_size, raw_offset, flags))

    def slice(self, offset, length):
        if offset < 0 or length < 0 or offset + length > len(self.data):
            raise ValueError("file bounds")
        return self.data[offset:offset + length]

    def unpack(self, offset, format):
        return struct.unpack("<" + format, self.slice(offset, struct.calcsize("<" + format)))

    def number(self, offset, format):
        return self.unpack(offset, format)[0]

    def raw(self, rva, length):
        if rva < 0 or rva + length > self.image_size:
            raise ValueError("image bounds")
        if rva + length <= self.header_size:
            return self.slice(rva, length)
        for start, _, size, offset, _ in self.sections:
            if start <= rva and rva + length <= start + size:
                return self.slice(offset + rva - start, length)
        raise ValueError("unbacked RVA")

    def executable(self, rva, length):
        return any(start <= rva and rva + length <= start + size and flags & 0x20000000
                   for start, _, size, _, flags in self.sections)

    def export_rva(self, symbol):
        rva, size = self.export
        if size < 40:
            raise ValueError("export directory")
        header = self.raw(rva, 40)
        functions, names, function_table, name_table, ordinal_table = struct.unpack_from("<IIIII", header, 20)
        if not 1 <= functions <= 8192 or names > 8192:
            raise ValueError("export limit")
        for index in range(names):
            name_rva = struct.unpack("<I", self.raw(name_table + index * 4, 4))[0]
            wanted = symbol.encode("ascii") + b"\0"
            if self.raw(name_rva, len(wanted)) != wanted:
                continue
            ordinal = struct.unpack("<H", self.raw(ordinal_table + index * 2, 2))[0]
            if ordinal >= functions:
                raise ValueError("export ordinal")
            target = struct.unpack("<I", self.raw(function_table + ordinal * 4, 4))[0]
            if rva <= target < rva + size:
                raise ValueError("forwarded export")
            return target
        raise ValueError("export missing")

    def relocations(self, target, length):
        rva, size = self.relocation
        if not rva or not size:
            return []
        if size > 2 * 1024 * 1024:
            raise ValueError("relocation limit")
        data = self.raw(rva, size)
        offset, count, result = 0, 0, []
        while offset < len(data):
            if len(data) - offset < 8:
                raise ValueError("relocation header")
            page, block_size = struct.unpack_from("<II", data, offset)
            if block_size < 8 or block_size % 2 or offset + block_size > len(data):
                raise ValueError("relocation block")
            for entry_offset in range(offset + 8, offset + block_size, 2):
                count += 1
                if count > 262144:
                    raise ValueError("relocation count")
                entry = struct.unpack_from("<H", data, entry_offset)[0]
                kind, address = entry >> 12, page + (entry & 0xfff)
                width = {0: 0, 3: 4, 10: 8}.get(kind, 8)
                if width and address < target + length and address + width > target:
                    if kind not in (3, 10) or address < target or address + width > target + length:
                        raise ValueError("unsupported overlapping relocation")
                    result.append({"offset": address - target, "width": width})
            offset += block_size
        return result


def reference(prefix):
    values = {}
    for api, (module, symbol, length) in APIS.items():
        try:
            path = prefix / "drive_c/windows/system32" / module
            if path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("file limit")
            with path.open("rb") as source:
                data = source.read(64 * 1024 * 1024 + 1)
            if len(data) > 64 * 1024 * 1024:
                raise ValueError("file limit")
            pe = PE(data)
            rva = pe.export_rva(symbol)
            if not pe.executable(rva, length):
                raise ValueError("export not executable")
            values[api] = {"status": "ok", "file_sha256": hashlib.sha256(data).hexdigest(),
                           "timestamp": pe.timestamp, "image_size": pe.image_size, "image_base": pe.image_base,
                           "rva": rva, "length": length, "code_hex": pe.raw(rva, length).hex(),
                           "relocations": pe.relocations(rva, length)}
        except (OSError, ValueError, struct.error) as error:
            # Do not expose paths or arbitrary error strings.
            values[api] = {"status": "reference-unavailable", "error_type": type(error).__name__}
    return {"format": 1, "scope": "selected-prefix-system32-only", "apis": values}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefix", type=Path)
    args = parser.parse_args()
    print(json.dumps(reference(args.prefix), sort_keys=True))
