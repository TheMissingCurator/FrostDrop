import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tutorial_trace_test", ROOT / "tools/sdk_tutorial_trace.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TutorialTraceTests(unittest.TestCase):
    def setUp(self):
        self.base = 0x140000000
        self.destination = 0x100000
        self.stack = 0x200000
        self.return_address = self.base + 0x123456
        self.producer_return = self.base + 0x156789
        self.object = self.destination - 0x20
        self.queue = 0x300000
        self.vector = 0x400000
        self.batch = 0x500000
        self.memory = {}
        self.registers = {}
        self.logs = []
        self.breakpoints = []
        for rva, signature in (*module.SITES.values(), module.WRAPPER):
            self.put(self.base + rva, signature)
        self.put(self.base + module.VTABLE_RVA + module.READER_SLOT,
                 (self.base + module.WRAPPER[0]).to_bytes(8, "little"))
        self.put(self.destination - 0x20, (self.base + module.VTABLE_RVA).to_bytes(8, "little"))
        self.put(self.destination + 0x28, (5).to_bytes(4, "little"))
        self.put(self.stack, self.return_address.to_bytes(8, "little"))
        self.put(self.stack + 0x88, self.producer_return.to_bytes(8, "little"))
        self.put(self.queue + 0x20, self.vector.to_bytes(8, "little"))
        self.put(self.queue + 0x28, (1).to_bytes(4, "little"))
        self.put(self.vector, self.object.to_bytes(8, "little"))
        self.put(self.batch, self.vector.to_bytes(8, "little"))
        self.put(self.batch + 8, (1).to_bytes(4, "little"))
        self.registers["rsp"] = self.stack
        self.trace = module.ActivityTrace(self.base, self.read, self.registers.__getitem__,
                                          self.make_breakpoint, self.logs.append,
                                          make_return_breakpoint=self.make_breakpoint,
                                          thread=lambda: 7)

    def put(self, address, data):
        self.memory.update((address + index, byte) for index, byte in enumerate(data))

    def read(self, address, size):
        return bytes(self.memory[address + index] for index in range(size))

    def make_breakpoint(self, address):
        test = self
        class Breakpoint:
            def delete(self):
                test.breakpoints.remove(self)
        breakpoint = Breakpoint()
        breakpoint.address = address
        self.breakpoints.append(breakpoint)
        self.assertLessEqual(len(self.breakpoints), 2)
        return breakpoint

    def test_reader_completion_and_queue_append_trace(self):
        original = self.memory.copy()
        self.trace.arm()
        self.assertEqual(len(self.breakpoints), 2)
        self.registers["rcx"] = self.destination
        self.trace.handle("reader")
        self.registers.update(rsi=self.destination, eax=1)
        self.trace.handle("completion")
        self.assertEqual(set(self.trace.breakpoints), {"return"})
        self.registers["rip"] = self.return_address
        self.trace.handle("return")
        self.assertEqual(set(self.trace.breakpoints), {"enqueue"})
        self.registers.update(rip=self.base + module.SITES["enqueue"][0],
                              rdi=self.object, rbx=self.queue, rdx=self.vector,
                              r8=0)
        self.trace.handle("enqueue")
        self.assertEqual(set(self.trace.breakpoints), {"producer_return", "flush"})
        self.registers["rip"] = self.producer_return
        self.trace.handle("producer_return")
        self.assertEqual(set(self.trace.breakpoints), {"flush"})
        self.registers.update(rip=self.base + module.SITES["flush"][0],
                              rbx=self.queue, rdi=self.batch)
        self.trace.handle("flush")
        self.assertEqual(self.breakpoints, [])
        self.assertTrue(self.trace.closed)
        self.assertEqual(self.memory, original)
        self.assertTrue(any("parser_success=1 rows=5 retention=unobserved" in line
                            for line in self.logs))
        self.assertTrue(any("object=decoded-five-row stored=1" in line
                            for line in self.logs))
        self.assertTrue(any("return_rva=0x123456 parser_result=1" in line
                            for line in self.logs))
        self.assertTrue(any("return_rva=0x156789 queue=confirmed" in line
                            for line in self.logs))
        self.assertTrue(any("same_queue=1 transferred=1 batch_count=1" in line
                            for line in self.logs))
        self.assertTrue(any("enqueues=1 producer_returns=1 flushes=1" in line
                            for line in self.logs))
        self.assertNotIn(hex(self.destination), "\n".join(self.logs))

    def test_missing_completion_remains_unresolved(self):
        self.trace.arm()
        self.registers["rcx"] = self.destination
        self.trace.handle("reader")
        self.trace.close("test-complete")
        self.assertIn("pending=1", self.logs[-1])
        self.assertIn("parser_success=0", self.logs[-1])

    def test_signature_mismatch_fails_closed_before_breakpoint_installation(self):
        self.put(self.base + module.WRAPPER[0], b"\x00")
        with self.assertRaisesRegex(ValueError, "signature mismatch"):
            self.trace.arm()
        self.assertEqual(self.breakpoints, [])

    def test_enqueue_mismatch_does_not_claim_application(self):
        self.trace.arm()
        self.registers["rcx"] = self.destination
        self.trace.handle("reader")
        self.registers.update(rsi=self.destination, eax=1)
        self.trace.handle("completion")
        self.registers["rip"] = self.return_address
        self.trace.handle("return")
        self.put(self.queue + 0x28, (0).to_bytes(4, "little"))
        self.registers.update(rip=self.base + module.SITES["enqueue"][0],
                              rdi=self.object, rbx=self.queue, rdx=self.vector,
                              r8=0)
        self.trace.handle("enqueue")
        self.assertTrue(self.trace.closed)
        self.assertIn("reason=enqueue-not-confirmed", self.logs[-1])
        self.assertIn("application=unproven", self.logs[-1])

    def test_unrelated_flush_does_not_claim_target_transfer(self):
        self.trace.arm()
        self.registers["rcx"] = self.destination
        self.trace.handle("reader")
        self.registers.update(rsi=self.destination, eax=1, rip=self.return_address)
        self.trace.handle("completion")
        self.trace.handle("return")
        self.registers.update(rip=self.base + module.SITES["enqueue"][0],
                              rdi=self.object, rbx=self.queue, rdx=self.vector,
                              r8=0)
        self.trace.handle("enqueue")
        self.registers.update(rip=self.base + module.SITES["flush"][0],
                              rbx=self.queue + 0x100, rdi=self.batch)
        self.trace.handle("flush")
        self.assertFalse(self.trace.closed)
        self.assertEqual(self.trace.flushes, 0)
        self.trace.close("test-complete")


if __name__ == "__main__":
    unittest.main()
