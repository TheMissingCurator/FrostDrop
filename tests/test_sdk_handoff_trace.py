import unittest
import test_sdk_backend_trace as startup
module = startup.module


class HandoffTests(unittest.TestCase):
    put = startup.TraceTests.put
    integer = startup.TraceTests.integer
    read = startup.TraceTests.read
    make = startup.TraceTests.make

    def setUp(self):
        startup.TraceTests.setUp(self)
        for rva, signature in module.HANDOFF_SITES.values():
            self.put(self.base + rva, signature)
        for rva, (_, signature) in module.GETTERS.items():
            self.put(self.base + rva, signature)
        self.thread_id = 12
        self.trace = module.HandoffTrace(self.base, self.read, self.registers.__getitem__, self.make,
            self.logs.append, now=lambda: self.clock, thread=lambda: self.thread_id)

    def hit(self, kind, **registers):
        self.registers.update(rip=self.base + module.HANDOFF_SITES[kind][0], rsp=self.stack,
                              rbp=self.owner, r14=0x40000, r15=0, r12=0x1001, rsi=self.owner, rbx=1)
        self.registers.update(registers)
        self.trace.handle(kind)

    def install_frontend(self):
        self.services, self.auth, self.client, self.manager = 0x50000, 0x60000, 0x70000, 0x80000
        self.integer(self.owner + 0x60, self.services, 8)
        self.integer(self.owner + 0x68, self.auth, 8)
        self.integer(self.auth + 0x1128, self.client, 8)
        self.integer(self.client, self.manager, 8)
        self.integer(self.client + 0x28, 0x90000, 8)
        self.integer(self.client + 8, 0, 8)
        self.integer(self.manager + 0x38, 2, 4)
        self.integer(self.services + 0x220, 7, 4)
        self.integer(self.auth + 0x1124, 1, 4)
        for owner, offset in ((self.auth, 0x10), (self.auth, 0xFA8), (self.auth, 0x1120),
                              (self.owner, 0x29A8), (self.owner, 0x29AA)):
            self.integer(owner + offset, 0, 1)
        for i, (owner, offset, nonempty) in enumerate(((self.services, 0x330, 1), (self.services, 0x228, 1),
                                                     (self.auth, 0xF50, 1), (self.auth, 0xEA0, 0))):
            table, data = 0xA0000 + i * 0x100, 0xB0000 + i * 0x100
            self.integer(owner + offset, table, 8)
            self.integer(table + 0x10, self.base + 0x12920, 8)
            self.integer(owner + offset + 0x48, data, 8)
            self.put(data, b"PRIVATE-TICKET" if nonempty else b"\0")

    def test_frontend_numeric_predicates_only_and_deduplicated(self):
        self.install_frontend()
        self.trace.arm()
        original = self.memory.copy()
        for _ in range(4):
            self.hit("frontend")
        log = "\n".join(self.logs)
        self.assertEqual(sum("TRACE_FRONTEND" in line for line in self.logs), 1)
        self.assertIn("auth_state=1", log)
        self.assertIn("services_ticket_present=1 auth_ticket_present=1", log)
        self.assertIn("pending_ticket_login=1 channel_present=0 manager_state=2", log)
        self.assertNotIn("PRIVATE", log)
        self.assertNotIn(hex(self.auth), log)
        self.assertEqual(self.memory, original)
        self.integer(self.owner + 0x29AA, 1, 1)
        self.hit("frontend")
        self.assertIn("suppress_copy=1", self.logs[-1])

    def test_channel_pair_preserves_original_selector_and_reads_result(self):
        self.integer(self.owner + 0x38, 2, 4)
        self.integer(0x40000, 0, 8)
        self.trace.arm()
        self.hit("channel", r15=0, r12=0x1001)
        self.assertEqual(set(self.trace.breakpoints), {"frontend", "channel_result"})
        channel = 0xC0000
        self.integer(0x40000, channel, 8)
        self.integer(channel + 0x58, 0xD0000, 8)
        self.integer(channel + 0x90, 2, 4)
        self.integer(channel + 0x94, 1, 4)
        self.hit("channel_result", r15=123, r12=456, rbx=1)
        self.assertEqual(set(self.trace.breakpoints), {"frontend", "channel"})
        self.assertIn("kind=0 channel_param=4097 paired=1 result=1 output_present=1", self.logs[-1])
        self.assertIn("channel_state=2 channel_error=1 channel_owner_present=1", self.logs[-1])
        self.trace.close("test")
        self.assertIn("channel_calls=1 channel_results=1 pending_results=0", self.logs[-1])

    def test_unpaired_thread_does_not_steal_pending_result(self):
        self.integer(self.owner + 0x38, 1, 4)
        self.integer(0x40000, 0, 8)
        self.trace.arm()
        self.hit("channel")
        self.thread_id = 13
        self.hit("channel_result", rbx=0)
        self.assertIn("paired=0 result=0 output_present=-1", self.logs[-1])
        self.assertIn("channel_result", self.trace.breakpoints)
        self.thread_id = 12
        self.hit("channel_result", rbx=0)
        self.assertIn("paired=1 result=0 output_present=0", self.logs[-1])
        self.assertIn("channel", self.trace.breakpoints)

    def test_unreadable_and_unknown_layouts_are_not_false(self):
        self.trace.arm()
        self.hit("frontend")
        self.assertIn("services_state=-1", self.logs[-1])
        self.assertIn("auth_ticket_present=-1", self.logs[-1])
        self.assertEqual(self.trace.scalar(1 << 64, 8), -1)
        self.assertEqual(self.trace.scalar(0, 8), -1)
        self.assertEqual(self.trace.nonempty(0, 0), -1)
        self.integer(0x50000, 0x60000, 8)
        self.integer(0x60000 + 0x10, self.base + 0x12345, 8)
        self.assertEqual(self.trace.nonempty(0x50000, 0), -1)

    def test_all_getter_layouts_and_signature_refusal(self):
        for index, (rva, (offset, _)) in enumerate(module.GETTERS.items()):
            owner, table, data = 0x100000 + index * 0x2000, 0x200000 + index * 0x100, 0x300000 + index * 0x100
            self.integer(owner, table, 8)
            self.integer(table + 0x10, self.base + rva, 8)
            self.integer(owner + offset, data, 8)
            self.put(data, b"x")
            self.assertEqual(self.trace.nonempty(owner, 0), 1)
            self.put(data, b"\0")
            self.assertEqual(self.trace.nonempty(owner, 0), 0)
        rva = next(iter(module.GETTERS))
        self.put(self.base + rva, b"x")
        with self.assertRaisesRegex(ValueError, "signature mismatch"):
            self.trace.arm()
        self.assertEqual(self.live, [])

    def test_handoff_stop_limit_retirement(self):
        self.trace.maximum_stops = 1
        self.trace.arm()
        self.hit("frontend")
        self.hit("frontend")
        self.assertTrue(self.trace.closed)
        self.assertEqual(self.live, [])


if __name__ == "__main__":
    unittest.main()
