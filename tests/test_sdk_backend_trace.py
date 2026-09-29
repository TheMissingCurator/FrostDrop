import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("startup_trace_test", ROOT / "tools/sdk_backend_trace.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.memory, self.registers, self.logs, self.live = {}, {}, [], []
        self.base, self.owner, self.transport, self.stack = 0x140000000, 0x10000, 0x20000, 0x30000
        self.clock = 0
        for rva, signature in module.SITES.values():
            self.put(self.base + rva, signature)
        self.integer(self.owner + 0x50, self.transport, 8)
        self.integer(self.owner + 0x53A, 1, 1)
        self.integer(self.owner + 0x53B, 0, 1)
        for offset, value, size in ((0xB8, 1, 4), (0xBC, 2056, 4), (0xD0, 0, 4),
                                    (0x15C, 1, 1), (0x15D, 0, 1)):
            self.integer(self.transport + offset, value, size)
        self.trace = module.StartupTrace(self.base, self.read, self.registers.__getitem__, self.make,
                                         self.logs.append, now=lambda: self.clock)

    def put(self, address, data):
        self.memory.update((address + i, byte) for i, byte in enumerate(data))

    def integer(self, address, value, size):
        self.put(address, value.to_bytes(size, "little"))

    def read(self, address, size):
        return bytes(self.memory[address + i] for i in range(size))

    def make(self, address):
        test = self
        class Breakpoint:
            def delete(self):
                test.live.remove(self)
        bp = Breakpoint()
        bp.address = address
        self.live.append(bp)
        self.assertLessEqual(len(self.live), 2)
        return bp

    def hit(self, kind, **registers):
        self.registers.update(rip=self.base + module.SITES[kind][0], rsp=self.stack,
                              rbx=self.transport, rdi=self.owner, rcx=self.transport,
                              rdx=0, rax=1)
        self.registers.update(registers)
        self.trace.handle(kind)

    def main_version(self):
        self.integer(self.stack + 0x30, 2056, 4)
        self.hit("version")

    def test_combined_path_rotates_two_slots_and_only_reads(self):
        self.trace.arm()
        self.integer(self.stack + 0x30, 2056, 4)
        original = self.memory.copy()
        self.hit("version")
        self.assertEqual(set(self.trace.breakpoints), {"error", "poll"})
        self.integer(self.stack + 0x30, 7, 2)
        self.hit("poll")
        self.assertEqual(set(self.trace.breakpoints), {"error", "settings"})
        self.integer(self.owner + 0x53A, 0, 1)  # Simulated client consumption.
        self.hit("settings")
        self.assertEqual(set(self.trace.breakpoints), {"error", "registration"})
        self.hit("registration", rcx=self.owner)
        self.hit("error", rdx=15)
        self.assertTrue(any("accepted=1" in line for line in self.logs))
        self.assertTrue(any("consumer_result=1 waiting_before=1" in line and
                            "waiting_settings=0" in line for line in self.logs))
        self.assertTrue(any("code=15 name=version-mismatch" in line for line in self.logs))
        # Only test's stack/type and simulated flag updates changed memory.
        original[self.stack + 0x30] = 7
        original[self.stack + 0x31] = 0
        original[self.owner + 0x53A] = 0
        self.assertEqual(self.memory, original)
        self.trace.close("test-complete")
        self.assertEqual(self.live, [])
        self.assertTrue(any("registration_calls=1" in line for line in self.logs))
        self.assertNotIn(hex(self.owner), "\n".join(self.logs))

    def test_failed_settings_returns_to_poll_without_claiming_acceptance(self):
        self.trace.arm()
        self.main_version()
        self.integer(self.stack + 0x30, 7, 2)
        self.hit("poll")
        self.hit("settings", rax=0)
        self.assertIn("poll", self.trace.breakpoints)
        self.assertNotIn("registration", self.trace.breakpoints)
        self.assertTrue(any("consumer_result=0 waiting_before=1" in line for line in self.logs))

    def test_valid_dispatch_uses_type_not_al_and_deduplicates(self):
        self.trace.arm()
        self.main_version()
        # This checkpoint is reached only with a valid parser. AL is no longer
        # a reliable availability test on every drain-loop iteration.
        self.integer(self.stack + 0x30, 10, 2)
        self.hit("poll", rax=0)
        for _ in range(10):
            self.hit("poll", rax=0)
        self.assertEqual(sum("TRACE_POLL" in line for line in self.logs), 1)
        self.assertTrue(any("message_available=1 type=10" in line for line in self.logs))

    def test_non_main_version_does_not_consume_main_checkpoint(self):
        self.trace.arm()
        self.integer(self.transport + 0xBC, 556, 4)
        self.integer(self.stack + 0x30, 556, 4)
        self.hit("version")
        self.assertIn("version", self.trace.breakpoints)
        self.assertFalse(self.trace.version_seen)

    def test_signature_failure_arms_nothing(self):
        self.put(self.base + module.SITES["registration"][0], b"x")
        with self.assertRaisesRegex(ValueError, "signature mismatch"):
            self.trace.arm()
        self.assertEqual(self.live, [])

    def test_stop_time_and_event_limits_retire_only_diagnostic_breakpoints(self):
        for limit in ("stop", "time", "events"):
            with self.subTest(limit=limit):
                self.setUp()
                self.trace.arm()
                if limit == "stop":
                    self.trace.maximum_stops = 1
                    self.main_version()
                elif limit == "time":
                    self.clock = 100
                else:
                    self.trace.maximum_events = 1  # READY exhausted the budget.
                    self.integer(self.stack + 0x30, 2056, 4)
                self.integer(self.stack + 0x30, 2056, 4)
                self.hit("version")
                self.assertTrue(self.trace.closed)
                self.assertEqual(self.live, [])

    def test_unknown_error_logged_as_numeric_not_exception_text(self):
        self.trace.arm()
        self.integer(self.stack + 0x30, 2056, 4)
        self.hit("version")
        self.hit("error", rdx=0x12345678)
        self.assertTrue(any("code=305419896 name=unmapped" in line for line in self.logs))

    def test_decompression_error_before_version_is_already_covered(self):
        self.trace.arm()
        self.assertEqual(set(self.trace.breakpoints), {"error", "version"})
        self.hit("error", rdx=8)
        self.assertTrue(any("code=8 name=decompression" in line for line in self.logs))
        self.assertFalse(self.trace.version_seen)


if __name__ == "__main__":
    unittest.main()
