import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import test_sdk_backend_trace as startup
module = startup.module


class NameTests(unittest.TestCase):
    put = startup.TraceTests.put
    integer = startup.TraceTests.integer
    read = startup.TraceTests.read
    make = startup.TraceTests.make

    def setUp(self):
        startup.TraceTests.setUp(self)
        for rva, signature in (*module.NAME_SITES.values(), *module.NAME_AUXILIARY.items()):
            self.put(self.base + rva, signature)
        self.thread_id, self.record, self.table, self.data = 12, 0x80000, 0x90000, 0xA0000
        self.put(self.data, b"service-alpha\0")
        self.integer(self.table + 0x10, self.base + 0x69160, 8)
        self.integer(self.record + 0x358, self.table, 8)
        self.integer(self.record + 0x388, self.data, 8)
        self.registry_table = 0xB0000
        self.integer(self.owner + 0xB8, self.registry_table, 8)
        self.integer(self.registry_table + 0x70, self.base + 0x5B9D0, 8)
        self.integer(self.owner + 0xC0, 0, 4)
        self.temp_table = 0xC0000
        self.integer(self.temp_table + 0x10, self.base + 0x12920, 8)
        self.integer(self.stack + 0x50, self.temp_table, 8)
        self.integer(self.stack + 0x98, self.stack + 0x58, 8)
        self.put(self.stack + 0x58, b"\0")
        self.archived = []
        self.trace = module.NameLineageTrace(self.base, self.read, self.registers.__getitem__, self.make,
            self.logs.append, now=lambda: self.clock, thread=lambda: self.thread_id,
            archive_name=self.archived.append)
        self.trace.arm()
        self.hit("owner_constructed")

    def hit(self, kind, **registers):
        self.registers.update(rip=self.base + module.NAME_SITES[kind][0], rsp=self.stack,
                              rbx=self.owner, r13=self.owner, r14=self.owner, rbp=self.stack + 0x100,
                              rsi=0, rax=0, rcx=self.stack + 0x50, rdx=self.data)
        self.registers.update(registers)
        before = self.memory.copy(), self.registers.copy()
        self.trace.handle(kind)
        self.assertEqual(before, (self.memory, self.registers))

    def automatic_source(self):
        self.hit("name_init")
        self.hit("registry_count", rax=1)
        self.integer(self.stack + 0xB8, 1, 4)  # RBP - 0x48.
        self.hit("matched_count")
        self.integer(0xD0000, self.record, 8)
        self.hit("selected_source", rax=0xD0000)
        self.hit("automatic_copy")

    def test_empty_registry_skips_assignment_and_reaches_gate(self):
        for _ in range(100):
            self.hit("name_init")
            self.hit("registry_count", rax=0)
            self.hit("name_gate", rax=1)
        line = self.logs[-1]
        self.assertIn("initial_empty=1", line)
        self.assertIn("registry_count=0 preferred_present=0", line)
        self.assertIn("source_copy_seen=0", line)
        self.assertIn("gate_empty=1 copy_equal=-1 final_length=0", line)
        self.assertEqual(self.trace.name_results, 100)
        self.assertEqual(sum("TRACE_NAME_LINEAGE" in item for item in self.logs), 1)
        self.assertEqual(self.archived, [])

    def test_matching_source_copy_preserves_name_without_public_value(self):
        self.automatic_source()
        self.put(self.stack + 0x58, b"service-alpha\0")  # Simulate real assignment.
        self.hit("name_gate", rax=0)
        line = self.logs[-1]
        self.assertIn("source_pointer_equal=1 source_length=13", line)
        self.assertIn("gate_empty=0 copy_equal=1 final_length=13", line)
        self.assertNotIn("service-alpha", "\n".join(self.logs))
        self.assertNotIn(hex(self.record), "\n".join(self.logs))
        self.assertEqual(self.archived, [b"service-alpha"])

    def test_no_matching_record_is_not_the_same_as_empty_registry(self):
        self.hit("name_init")
        self.hit("registry_count", rax=3)
        self.integer(self.stack + 0xB8, 0, 4)
        self.hit("matched_count")
        self.hit("name_gate", rax=1)
        self.assertIn("registry_count=3 preferred_present=0 matched_count=0", self.logs[-1])

    def test_preferred_failures_and_success(self):
        self.hit("name_init", rsi=1)
        self.hit("preferred_lookup", rax=0)
        self.hit("name_gate", rax=1)
        self.assertIn("preferred_lookup=0 preferred_parse=-1", self.logs[-1])
        self.hit("name_init", rsi=1)
        self.hit("preferred_lookup", rax=1)
        self.hit("preferred_parse", rax=0)
        self.hit("name_gate", rax=1)
        self.assertIn("preferred_lookup=1 preferred_parse=0", self.logs[-1])
        self.hit("name_init", rsi=1)
        self.hit("preferred_lookup", rax=1)
        self.hit("preferred_parse", rax=1)
        self.integer(self.stack + 0x328, self.record, 8)
        self.hit("preferred_resolve")
        self.hit("preferred_copy")
        self.put(self.stack + 0x58, b"service-alpha\0")
        self.hit("name_gate", rax=0)
        self.assertIn("copy_equal=1", self.logs[-1])

    def test_producer_before_after_pairs_exact_destination_and_does_not_advance_other_slot(self):
        self.hit("name_init")
        self.integer(self.stack + 0x400, self.record, 8)
        old = 0xE0000
        self.put(old, b"\0")
        self.integer(self.record + 0x388, old, 8)
        self.hit("producer_copy", rcx=self.record + 0x358)
        self.assertIn("registry_count", self.trace.breakpoints)
        self.thread_id = 13
        self.hit("producer_written")
        self.thread_id = 12
        self.hit("producer_written", rsp=self.stack + 8)
        self.assertEqual(self.trace.producer_results, 0)
        self.integer(self.record + 0x388, self.data, 8)  # Simulate allocation/copy.
        self.hit("producer_written")
        self.assertIn("root_type=5 field_offset=856 before_empty=1 copy_equal=1 length=13", self.logs[-1])
        self.assertEqual(self.archived, [b"service-alpha"])
        self.hit("registry_count", rax=0)
        self.hit("name_gate", rax=1)
        self.assertEqual(self.trace.producer_results, 1)

    def test_unknown_layout_truncated_or_null_not_fabricated_as_empty(self):
        self.assertIsNone(self.trace.bounded_name(0))
        self.put(self.data, b"x" * 64)
        self.assertIsNone(self.trace.bounded_name(self.data))
        self.integer(self.temp_table + 0x10, self.base + 0x12940, 8)
        self.hit("name_init")
        self.hit("registry_count", rax=0)
        self.hit("name_gate", rax=1)
        self.assertIn("initial_empty=-1", self.logs[-1])
        self.assertIn("final_length=-1 final_sha256=unknown", self.logs[-1])

    def test_archival_io_failure_is_diagnostic_not_a_fatal_driver_exception(self):
        def unavailable(_):
            raise PermissionError("private contents must not appear")
        self.trace.archive_name = unavailable
        with self.assertRaisesRegex(ValueError, "^service-name archival unavailable$"):
            self.trace.archive(b"service-alpha")

    def test_mismatched_assignment_source_is_not_read_or_archived(self):
        self.automatic_source()
        self.assertEqual(self.archived, [b"service-alpha"])
        self.hit("name_gate", rax=1)
        self.archived.clear()
        self.hit("name_init")
        self.hit("registry_count", rax=1)
        self.hit("matched_count")
        self.hit("selected_source", rax=0xD0000)
        self.hit("automatic_copy", rdx=0xDEAD000)
        self.assertEqual(self.archived, [])
        self.hit("name_gate", rax=1)
        self.assertIn("source_pointer_equal=0 source_length=-1", self.logs[-1])

    def test_signature_refusal_and_limit_summary(self):
        self.trace.close("test")
        for mapping in (module.NAME_SITES, module.NAME_AUXILIARY):
            for item in mapping.items():
                rva, signature = item[1] if mapping is module.NAME_SITES else item
                self.put(self.base + rva, b"x")
                trace = module.NameLineageTrace(self.base, self.read, self.registers.__getitem__, self.make,
                    self.logs.append, now=lambda: self.clock, thread=lambda: self.thread_id)
                with self.assertRaisesRegex(ValueError, "signature mismatch"):
                    trace.arm()
                self.assertEqual(self.live, [])
                self.put(self.base + rva, signature)

    def test_unpaired_name_hit_does_not_advance_and_limit_leaves_pending_truthful(self):
        self.hit("name_init")
        self.thread_id = 13
        self.hit("registry_count", rax=0)
        self.assertEqual(self.trace.name_slot, "registry_count")
        self.thread_id = 12
        self.clock = 90
        self.hit("registry_count", rax=0)
        self.assertTrue(self.trace.closed)
        self.assertIn("pending_name=1", self.logs[-1])
        self.assertEqual(self.live, [])


class ArchiveTests(unittest.TestCase):
    def test_private_exact_name_hash_file_dedup_bounds_and_no_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = b"service-alpha"
            module.archive_service_name(root, value)
            module.archive_service_name(root, value)
            file = root / "service-names" / (hashlib.sha256(value).hexdigest() + ".bin")
            self.assertEqual(file.read_bytes(), value)
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(file.parent.stat().st_mode & 0o777, 0o700)
            for invalid in (b"", b"x" * 64, b"x\0y"):
                with self.assertRaises(ValueError):
                    module.archive_service_name(root, invalid)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                module.archive_service_name(link, value)
            self.assertEqual(list(target.iterdir()), [])
            file.chmod(0o644)
            with self.assertRaises(ValueError):
                module.archive_service_name(root, value)


if __name__ == "__main__":
    unittest.main()
