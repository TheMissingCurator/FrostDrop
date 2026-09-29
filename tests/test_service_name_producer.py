import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import service_name_producer_trace as module
import sdk_backend_trace as lineage
import test_sdk_backend_trace as startup


class ProducerTests(unittest.TestCase):
    put = startup.TraceTests.put
    integer = startup.TraceTests.integer
    read = startup.TraceTests.read
    make = startup.TraceTests.make

    def setUp(self):
        startup.TraceTests.setUp(self)
        for rva, signature in (*module.SITES.values(), *module.AUXILIARY.items()):
            self.put(self.base + rva, signature)
        self.reader, self.thread_id = 0x80000, 12
        self.integer(self.reader + 0x10, 5, 2)
        self.registry_table = 0x90000
        self.integer(self.owner + 0xB8, self.registry_table, 8)
        self.integer(self.registry_table + 0x70, self.base + 0x5B9D0, 8)
        self.integer(self.owner + 0xC0, 0, 4)
        self.artifacts = []
        def archive(fields):
            self.artifacts.append(fields)
            return "fixture.json"
        self.trace = module.ProducerTrace(self.base, self.read, self.registers.__getitem__, self.make,
            self.logs.append, now=lambda: self.clock, thread=lambda: self.thread_id, archive_fields=archive)
        self.trace.arm()

    def hit(self, kind, **registers):
        delta = -0x60 if kind == "name_length" else -0x100 if kind in ("attribute_count", "key_length", "attribute_pair") else 0
        self.registers.update(rip=self.base + module.SITES[kind][0], rsp=self.stack + delta,
            rbp=self.stack - 0x97 if delta == -0x100 else self.stack + 0x100,
            rdi=self.reader if kind == "name_length" else 0,
            rsi=self.stack + 0x20 if kind == "name_length" else self.reader,
            r14=self.stack + 0x78 if delta == -0x100 else self.owner,
            rbx=64 if kind == "name_length" else 1, rax=1, rcx=self.stack + 0x20, rdx=self.reader)
        self.registers.update(registers)
        before = self.memory.copy(), self.registers.copy()
        self.trace.handle(kind)
        self.assertEqual(before, (self.memory, self.registers))

    def string(self, obj, getter, offset, value, table, data):
        self.integer(obj, table, 8)
        self.integer(table + 0x10, self.base + getter, 8)
        self.integer(obj + offset, data, 8)
        self.put(data, value)

    def start(self, name=b"retail-service", count=0):
        self.hit("consumer_read")
        self.integer(self.stack - 0x60 + 0x48, len(name), 4)
        self.hit("name_length")
        self.string(self.stack + 0x20, 0x12920, 0x48, name, 0xA0000, 0xA1000)
        self.integer(self.stack + 0x78, self.registry_table, 8)
        self.integer(self.stack + 0x80, 0, 4)
        self.integer(self.stack - 0x97 + 0x77, count, 4)
        self.hit("attribute_count")

    def pair(self, key, value, index, count):
        rbp = self.stack - 0x97
        self.integer(rbp + 0x77, count, 4)
        self.integer(rbp + 0x67, len(key), 4)
        self.hit("key_length", rdi=index)
        self.string(rbp - 0x49, 0x12860, 0x18, key, 0xB0000, 0xB1000)
        self.string(rbp - 0x21, 0x69160, 0x30, value, 0xC0000, 0xC1000)
        self.integer(rbp + 0x67, len(value), 4)
        self.hit("attribute_pair", rdi=index)

    def test_exact_producer_fields_assignment_registry_and_no_public_values(self):
        self.start(count=2)
        self.pair(b"type", b"auth", 0, 2)
        self.pair(b"id", b"retail-private-value", 1, 2)
        self.integer(self.stack + 0x80, 2, 4)
        self.hit("parser_done")
        self.trace.assignment({"thread": 12, "stack": self.stack, "owner": self.owner}, b"retail-service")
        self.integer(self.owner + 0xC0, 1, 4)
        self.hit("consumer_done")
        fields = self.artifacts[-1]
        self.assertTrue(fields["complete_fields"])
        self.assertTrue(fields["record_written"])
        self.assertEqual(fields["copy_equal"], 1)
        self.assertEqual(fields["registry_after"], 1)
        self.assertEqual(bytes.fromhex(fields["name_hex"]), b"retail-service")
        self.assertEqual(fields["attributes"][1]["value_hex"], b"retail-private-value".hex())
        self.assertIn("wire_has_type_auth=1", self.logs[-1])
        for value in ("retail-service", "retail-private-value", hex(self.owner)):
            self.assertNotIn(value, "\n".join(self.logs))
        self.assertEqual(set(self.trace.breakpoints), {"consumer_read", "name_length"})

    def test_early_parse_failure_remains_covered_and_resets_slots(self):
        self.hit("consumer_read")
        self.assertIn("parser_done", self.trace.breakpoints)
        self.hit("parser_done", rax=0)
        self.hit("consumer_done", rbx=0)
        self.assertFalse(self.artifacts[-1]["complete_fields"])
        self.assertFalse(self.artifacts[-1]["consumer_accepted"])
        self.assertIsNone(self.artifacts[-1]["name_hex"])
        self.start()
        self.hit("parser_done")
        self.hit("consumer_done")
        self.assertTrue(self.artifacts[-1]["complete_fields"])
        self.assertEqual(self.artifacts[-1]["wire_attribute_count"], 0)

    def test_duplicate_keys_wire_order_embedded_nul_and_semantic_name(self):
        self.start(b"wire\0tail", count=2)
        self.pair(b"type", b"auth", 0, 2)
        self.pair(b"type", b"other\0bytes", 1, 2)
        self.integer(self.stack + 0x80, 1, 4)  # Parsed vector deduplicates keys.
        self.hit("parser_done")
        self.trace.assignment({"thread": 12, "stack": self.stack, "owner": self.owner}, b"wire")
        self.hit("consumer_done")
        fields = self.artifacts[-1]
        self.assertTrue(fields["complete_fields"])
        self.assertEqual(fields["wire_attribute_count"], 2)
        self.assertEqual(fields["parsed_attribute_count"], 1)
        self.assertEqual(fields["copy_equal"], 1)
        self.assertEqual(bytes.fromhex(fields["name_hex"]), b"wire\0tail")
        self.assertEqual(bytes.fromhex(fields["attributes"][1]["value_hex"]), b"other\0bytes")

    def test_cross_thread_frame_reader_and_assignment_cannot_advance(self):
        self.hit("consumer_read")
        self.thread_id = 13
        self.hit("name_length")
        self.thread_id = 12
        self.hit("name_length", rdi=self.reader + 8)
        self.hit("name_length", rsp=self.stack - 0x68)
        self.assertEqual(self.trace.field_slot, "name_length")
        self.assertEqual(self.trace.context["name_length"], -1)
        self.trace.assignment({"thread": 13, "stack": self.stack, "owner": self.owner}, b"wrong")
        self.assertFalse(self.trace.context["record_written"])

    def test_unknown_getter_or_missing_pair_is_not_complete(self):
        self.start(count=2)
        self.pair(b"type", b"auth", 0, 2)
        self.integer(self.stack + 0x80, 2, 4)
        self.integer(0xA0000 + 0x10, self.base + 0x12940, 8)
        self.hit("parser_done")
        self.hit("consumer_done")
        self.assertFalse(self.artifacts[-1]["complete_fields"])
        self.assertIsNone(self.artifacts[-1]["name_hex"])
        self.assertEqual(len(self.artifacts[-1]["attributes"]), 1)

    def test_bounds_and_unreadable_never_read_arbitrary_payload(self):
        self.assertIsNone(self.trace.exact(self.stack, 0x12920, 0x48, 64, 64))
        self.assertIsNone(self.trace.exact(self.stack, 0x12920, 0x48, -1, 64))
        self.assertIsNone(self.trace.exact(self.stack, 0x69160, 0x30, 512, 512))
        self.start(count=1)
        self.pair(b"k" * 63, b"v" * 511, 0, 1)
        self.integer(self.stack + 0x80, 1, 4)
        self.hit("parser_done")
        self.hit("consumer_done")
        self.assertTrue(self.artifacts[-1]["complete_fields"])

    def test_every_signature_refuses_before_arming_and_time_limit_truthful(self):
        self.trace.close("test")
        for rva, signature in (*module.SITES.values(), *module.AUXILIARY.items()):
            self.put(self.base + rva, b"x")
            trace = module.ProducerTrace(self.base, self.read, self.registers.__getitem__, self.make,
                self.logs.append, now=lambda: self.clock)
            with self.assertRaisesRegex(ValueError, "signature mismatch"):
                trace.arm()
            self.assertEqual(self.live, [])
            self.put(self.base + rva, signature)
        self.trace = trace = module.ProducerTrace(self.base, self.read, self.registers.__getitem__, self.make,
            self.logs.append, now=lambda: self.clock)
        trace.arm()
        self.hit("consumer_read")
        self.clock = 90
        self.hit("parser_done")
        self.assertTrue(trace.closed)
        self.assertIn("pending=1", self.logs[-1])

    def test_four_slots_with_existing_assignment_and_gate_observer(self):
        self.trace.close("test")
        for rva, signature in (*lineage.NAME_SITES.values(), *lineage.NAME_AUXILIARY.items()):
            self.put(self.base + rva, signature)
        def make(address):
            test = self
            class BP:
                def delete(self):
                    test.live.remove(self)
            bp = BP()
            self.live.append(bp)
            self.assertLessEqual(len(self.live), 4)
            return bp
        name = lineage.NameLineageTrace(self.base, self.read, self.registers.__getitem__, make, self.logs.append)
        name.arm()
        self.trace = module.ProducerTrace(self.base, self.read, self.registers.__getitem__, make,
            self.logs.append, thread=lambda: self.thread_id)
        self.trace.arm()
        self.assertEqual(len(self.live), 4)
        self.start()
        self.hit("parser_done")
        self.hit("consumer_done")
        name.close("test")
        self.trace.close("test")
        self.assertEqual(self.live, [])


class ArchiveTests(unittest.TestCase):
    def test_exact_private_json_dedup_permissions_symlinks_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            fields = {"name_hex": b"private-service".hex(), "attributes": []}
            name = module.archive_fields(directory, fields)
            self.assertEqual(module.archive_fields(directory, fields), name)
            file = Path(directory) / name
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)
            file.chmod(0o644)
            with self.assertRaises(ValueError):
                module.archive_fields(directory, fields)
            with self.assertRaises(ValueError):
                module.archive_fields(directory, {"too_big": "x" * 65536})
            link = Path(directory) / "link"
            link.symlink_to(directory)
            with self.assertRaises(OSError):
                module.archive_fields(link, {})


if __name__ == "__main__":
    unittest.main()
