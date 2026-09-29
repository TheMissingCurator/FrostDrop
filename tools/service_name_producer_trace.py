"""Bounded read-only type-5 producer inputs, paired with NameLineageTrace.

Two rotating execution hardware slots; no packet buffers, auth objects, code
writes, inferior calls or register changes. Private artifacts retain exact
declared field bytes, not raw packets or a claimed wire encoding.
"""
import hashlib
import json
import os
import stat

from sdk_backend_trace import NameLineageTrace, NAME_AUXILIARY

SITES = {
    "consumer_read": (0x8B60B, bytes.fromhex("e8 20 ce 1c 02")),
    "parser_done": (0x8B610, bytes.fromhex("84 c0 75 07 32 db e9 3a 01 00 00")),
    "consumer_done": (0x8B755, bytes.fromhex("48 8d 4c 24 78 e8 51 a0 fa ff")),
    "name_length": (0x21830, bytes.fromhex("8b 54 24 48 3b d3 73 e6")),
    "attribute_count": (0x654C6, bytes.fromhex("8b 45 77 83 f8 18 77 e8")),
    "key_length": (0x6556E, bytes.fromhex("8b 55 67 83 fa 40")),
    "attribute_pair": (0x65623, bytes.fromhex("48 8d 55 b7 49 8b ce e8 11 db fe ff")),
}
AUXILIARY = {
    **NAME_AUXILIARY,
    0x12860: bytes.fromhex("48 8b 41 18 c3"),
    0x8B590: bytes.fromhex("48 8b c4 55 53 48 8d a8 18 fd ff ff 48 81 ec d8 03 00 00"),
    0x2258430: bytes.fromhex("48 89 5c 24 08 57 48 83 ec 20"),
    0x217F0: bytes.fromhex("48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20"),
    0x65480: bytes.fromhex("40 55 56 41 56 41 57 48 8d 6c 24 c1 48 81 ec a8 00 00 00"),
    0x654C6: bytes.fromhex("8b 45 77 83 f8 18 77 e8"),
    0x655D5: bytes.fromhex("8b 55 67 81 fa 00 02 00 00"),
}


def archive_fields(directory, fields):
    """Exclusive hash-named JSON; refuse unsafe dirs/files and oversize output."""
    data = (json.dumps(fields, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > 65536:
        raise ValueError("type-5 artifact exceeds bound")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("unsafe private producer directory")
        name = hashlib.sha256(data).hexdigest() + ".json"
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        except FileExistsError:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                        or stream.read(65537) != data):
                    raise ValueError("unsafe or inconsistent producer artifact")
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        return name
    finally:
        os.close(parent)


class ProducerTrace(NameLineageTrace):
    def __init__(self, *args, archive_fields=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = "service-name-producer"
        self.payload_policy = "type5-name-and-attributes-only"
        self.sites, self.auxiliary_signatures = SITES, AUXILIARY
        self.initial_sites = ("consumer_read", "name_length")
        self.control_slot, self.field_slot = self.initial_sites
        self.context = None
        self.calls = self.results = self.complete_results = self.ignored = 0
        self.archive_fields = archive_fields

    def completion_fields(self):
        return (f"calls={self.calls} results={self.results} complete={self.complete_results} "
                f"pending={int(self.context is not None)} ignored_hits={self.ignored}")

    def follow(self, slot, site):
        old = getattr(self, slot)
        if not self.closed and old != site:
            self.replace(old, site)
            setattr(self, slot, site)

    def exact(self, string, getter, offset, length, bound):
        if not 0 <= length < bound:
            return None
        pointer = self.name_data_pointer(string, getter, offset)
        if pointer <= 0:
            return None
        try:
            data = bytes(self.read(pointer, length))
            return data if len(data) == length else None
        except Exception:
            return None

    def frame(self, delta=0):
        return (self.context is not None and self.context["thread"] == self.thread()
                and self.register("rsp") == self.context["stack"] + delta)

    def attribute_frame(self):
        c = self.context
        return (self.frame(-0x100) and self.register("rbp") == c["stack"] - 0x97
                and self.register("rsi") == c["reader"]
                and self.register("r14") == c["stack"] + 0x78)

    def assignment(self, context, value):
        """Driver forwards only a successfully paired record assignment."""
        c = self.context
        if (c is not None and c["thread"] == context["thread"] and c["stack"] == context["stack"]
                and c["owner"] == context["owner"]):
            c["record_written"] = True
            c["record_name"] = value

    def handle(self, kind):
        if not self.begin(kind):
            return
        reg = self.register
        if kind == "consumer_read":
            stack, reader, owner = reg("rsp"), reg("rdx"), reg("r14")
            if (reg("rcx") != stack + 0x20 or reg("rbp") != stack + 0x100
                    or self.field(reader, 0x10, 2) != 5):
                self.ignored += 1
                return
            self.calls += 1
            if self.calls > 64:
                self.close("advertisement-limit")
                return
            self.context = {"thread": self.thread(), "stack": stack, "reader": reader, "owner": owner,
                            "before": self.registry_count(owner), "name_length": -1, "name": None,
                            "wire_count": -1, "parsed_count": -1, "pairs": [], "key": None,
                            "parse_success": False, "record_written": False, "record_name": None,
                            "incomplete": False}
            # Keep parser return covered even if any nested read fails early.
            self.follow("control_slot", "parser_done")
            return
        c = self.context
        if kind == "name_length":
            if (not self.frame(-0x60) or reg("rdi") != c["reader"]
                    or reg("rsi") != c["stack"] + 0x20 or (reg("rbx") & 0xffffffff) != 0x40):
                self.ignored += 1
                return
            c["name_length"] = self.field(reg("rsp"), 0x48)
            self.follow("field_slot", "attribute_count")
        elif kind == "attribute_count":
            if not self.attribute_frame():
                self.ignored += 1
                return
            count = self.field(reg("rbp"), 0x77)
            if not 0 <= count <= 24:
                c["incomplete"] = True
            c["wire_count"] = count
            self.follow("field_slot", "key_length")
        elif kind == "key_length":
            if not self.attribute_frame():
                self.ignored += 1
                return
            count, index = self.field(reg("rbp"), 0x77), reg("rdi") & 0xffffffff
            if not 0 <= index < count <= 24:
                c["incomplete"] = True
                return
            if c["wire_count"] not in (-1, count) or index != len(c["pairs"]):
                c["incomplete"] = True
            c["wire_count"] = count
            c["key"] = (index, self.field(reg("rbp"), 0x67))
            self.follow("field_slot", "attribute_pair")
        elif kind == "attribute_pair":
            if (not self.attribute_frame() or c["key"] is None
                    or (reg("rdi") & 0xffffffff) != c["key"][0]):
                self.ignored += 1
                return
            index, length = c["key"]
            key = self.exact(reg("rbp") - 0x49, 0x12860, 0x18, length, 64)
            value = self.exact(reg("rbp") - 0x21, 0x69160, 0x30,
                               self.field(reg("rbp"), 0x67), 512)
            if key is None or value is None:
                c["incomplete"] = True
            c["pairs"].append({"index": index, "key_hex": None if key is None else key.hex(),
                                "value_hex": None if value is None else value.hex()})
            c["key"] = None
            self.follow("field_slot", "key_length")
        elif kind == "parser_done":
            if not self.frame() or reg("r14") != c["owner"]:
                self.ignored += 1
                return
            c["parse_success"] = bool(reg("rax") & 255)
            if c["parse_success"]:
                c["name"] = self.exact(c["stack"] + 0x20, 0x12920, 0x48, c["name_length"], 64)
                table = self.pointer(c["stack"] + 0x78, 0)
                if self.pointer(table, 0x70) == self.base + 0x5B9D0:
                    c["parsed_count"] = self.field(c["stack"] + 0x78, 8)
            self.follow("field_slot", "name_length")
            self.follow("control_slot", "consumer_done")
        elif kind == "consumer_done":
            if not self.frame() or reg("r14") != c["owner"]:
                self.ignored += 1
                return
            accepted = bool(reg("rbx") & 255)
            complete = (c["parse_success"] and c["name"] is not None and not c["incomplete"]
                        and c["key"] is None and c["wire_count"] == len(c["pairs"]))
            self.results += 1
            self.complete_results += int(complete)
            name = c["name"]
            copy_equal = (-1 if name is None or c["record_name"] is None
                          else int(name.split(b"\0", 1)[0] == c["record_name"]))
            fields = {"version": 1, "root_type": 5, "call": self.calls,
                      "owner": self.identifier(c["owner"]), "complete_fields": complete,
                      "parse_success": c["parse_success"], "consumer_accepted": accepted,
                      "name_declared_length": c["name_length"],
                      "name_hex": None if name is None else name.hex(),
                      "wire_attribute_count": c["wire_count"], "parsed_attribute_count": c["parsed_count"],
                      "attributes": c["pairs"], "registry_before": c["before"],
                      "registry_after": self.registry_count(c["owner"]), "record_written": c["record_written"],
                      "record_name_hex": None if c["record_name"] is None else c["record_name"].hex(),
                      "copy_equal": copy_equal}
            artifact = "none"
            if self.archive_fields:
                try:
                    artifact = self.archive_fields(fields)
                except OSError:
                    raise ValueError("producer archival unavailable") from None
            auth = any(p["key_hex"] == b"type".hex() and p["value_hex"] == b"auth".hex() for p in c["pairs"])
            self.log("TYPE5", f"call={self.calls} owner={fields['owner']} complete={int(complete)} "
                     f"parsed={int(c['parse_success'])} accepted={int(accepted)} "
                     f"name_length={-1 if name is None else len(name)} "
                     f"name_sha256={'unknown' if name is None else hashlib.sha256(name).hexdigest()} "
                     f"wire_attributes={c['wire_count']} parsed_attributes={c['parsed_count']} wire_has_type_auth={int(auth)} "
                     f"record_written={int(c['record_written'])} copy_equal={copy_equal} "
                     f"registry_before={c['before']} registry_after={fields['registry_after']} artifact={artifact}")
            self.context = None
            self.follow("control_slot", "consumer_read")
