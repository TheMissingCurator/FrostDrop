import unittest
import test_sdk_backend_trace as startup
module = startup.module


class ChannelTests(unittest.TestCase):
    put = startup.TraceTests.put
    integer = startup.TraceTests.integer
    read = startup.TraceTests.read
    make = startup.TraceTests.make

    def setUp(self):
        startup.TraceTests.setUp(self)
        for rva, signature in (*module.CHANNEL_SITES.values(), *module.CHANNEL_AUXILIARY.items()):
            self.put(self.base + rva, signature)
        self.thread_id = 12
        self.manager, self.entry, self.channel, self.output = 0x80000, 0x90000, 0xA0000, 0xB0000
        self.integer(self.manager + 0x38, 2, 4)
        self.integer(self.entry + 0x58, 55001, 2)
        self.integer(self.entry + 0x5C, 0, 4)
        self.integer(self.entry + 0x60, self.owner, 8)
        self.integer(self.channel + 0x90, 2, 4)
        self.integer(self.channel + 0x94, 1, 4)
        self.integer(self.output, 0, 8)
        self.trace = module.ChannelTrace(self.base, self.read, self.registers.__getitem__, self.make,
            self.logs.append, now=lambda: self.clock, thread=lambda: self.thread_id)
        self.trace.arm()

    def hit(self, kind, **registers):
        offset = (0xC0 if kind in ("selector_count", "candidate", "candidate_filter", "selector_iteration")
                  else 0x3D0 if kind == "registration"
                  else 0x370 if kind in ("setup", "transport_check", "prepared_name", "registration_result")
                  else 0)
        self.registers.update(rip=self.base + module.CHANNEL_SITES[kind][0], rsp=self.stack - offset,
                              rbp=self.manager, r14=self.output, r15=0, r12=0x1001,
                              r13=self.manager if kind == "selector_count" else self.owner,
                              rbx=self.entry, rax=0, rcx=self.owner)
        self.registers.update(registers)
        original = self.memory.copy(), self.registers.copy()
        self.trace.handle(kind)
        self.assertEqual(original, (self.memory, self.registers))

    def selection(self, reusable=True):
        self.hit("channel")
        self.hit("selector_count", rax=1)
        self.hit("candidate")
        if not reusable:
            self.integer(self.entry + 0x60, 0, 8)
        self.hit("candidate_filter", rax=0)
        if not reusable:
            self.hit("selector_iteration", rbp=1, rax=1)
            self.integer(self.entry + 0x60, self.owner, 8)  # Constructor's simulated effect.
        self.hit("selector_result", rax=self.entry)

    def check_and_finish(self, rejected=True):
        self.integer(self.output, self.channel, 8)
        self.hit("channel_check", rax=int(rejected))
        if rejected:
            self.integer(self.output, 0, 8)  # Game releases its rejected object.
        self.hit("channel_result", rbx=int(not rejected))
        self.assertEqual(set(self.trace.breakpoints), {"channel_result", "channel"})

    def test_no_candidates_distinguishes_selector_failure(self):
        self.hit("channel")
        self.hit("selector_count", rax=0)
        self.hit("selector_result", rax=0)
        self.hit("channel_result", rbx=0)
        line = self.logs[-1]
        self.assertIn("candidate_count=0", line)
        self.assertIn("selector_present=0", line)
        self.assertIn("setup_seen=0", line)
        self.assertIn("channel_rejected=-1", line)
        self.assertIn("result=0 output_present=0", line)

    def test_kind_mismatch_and_filter_rejection_are_separate(self):
        self.hit("channel")
        self.hit("selector_count", rax=2)
        self.integer(self.entry + 0x5C, 1, 4)
        self.hit("candidate")
        self.assertEqual(self.trace.slot, "selector_iteration")
        self.hit("selector_iteration", rbp=1, rax=2)
        self.integer(self.entry + 0x5C, 0, 4)
        self.hit("candidate")
        self.hit("candidate_filter", rax=1)
        self.hit("selector_iteration", rbp=2, rax=2)
        self.hit("selector_result", rax=0)
        self.hit("channel_result", rbx=0)
        self.assertIn("kind_matches=1 kind_mismatches=1 filter_rejections=1", self.logs[-1])

    def test_empty_service_name_proves_constructor_rejection_not_selector_failure(self):
        self.selection()
        self.hit("setup")
        self.hit("transport_check", rax=0)
        self.hit("prepared_name", rax=1)
        self.check_and_finish()
        line = self.logs[-1]
        self.assertIn("selector_present=1 selected_port=55001 selected_kind=0", line)
        self.assertIn("transport_rejected=0 prepared_name_empty=1 registration_seen=0", line)
        self.assertIn("channel_rejected=1 channel_state=2 channel_error=1", line)

    def test_registration_gate_and_result_including_success(self):
        self.selection(reusable=False)
        self.hit("setup")
        self.hit("transport_check", rax=0)
        self.hit("prepared_name", rax=0)
        self.integer(self.owner + 0x53A, 0, 1)
        self.hit("registration")
        self.hit("registration_result", rax=1)
        self.integer(self.channel + 0x90, 0, 4)
        self.integer(self.channel + 0x94, 0, 4)
        self.check_and_finish(rejected=False)
        self.assertIn("eligible_new=1", self.logs[-1])
        self.assertIn("waiting_settings=0 policy_enabled=0", self.logs[-1])
        self.assertIn("registration_seen=1 registration_result=1 channel_rejected=0", self.logs[-1])
        self.assertIn("result=1 output_present=1", self.logs[-1])

    def test_transport_missing_or_rejected(self):
        for missing in (True, False):
            self.selection()
            self.integer(self.owner + 0x50, 0 if missing else self.transport, 8)
            self.hit("setup")
            if not missing:
                self.hit("transport_check", rax=1)
            self.check_and_finish()
            self.assertIn("prepared_name_empty=-1 registration_seen=0", self.logs[-1])
            self.assertIn("transport_present=0" if missing else "transport_rejected=1", self.logs[-1])

    def test_other_thread_frame_or_owner_cannot_advance_observer(self):
        self.hit("channel")
        self.thread_id = 13
        self.hit("selector_count", rax=1)
        self.hit("channel_result", rbx=0)
        self.thread_id = 12
        self.hit("selector_count", rsp=self.stack - 0xC8, rax=1)
        self.hit("selector_count", r13=self.owner, rax=1)
        self.assertEqual(self.trace.slot, "selector_count")
        self.hit("selector_count", rax=0)
        self.hit("selector_result", rax=0)
        self.hit("channel_result", rbx=0)
        self.assertEqual(self.trace.ignored, 4)
        self.assertEqual(self.trace.unpaired_results, 1)

    def test_tail_recovers_missing_checkpoint_and_same_decision_does_not_fill_log(self):
        for _ in range(80):
            self.hit("channel")
            self.hit("channel_result", rbx=0)
        self.assertEqual(self.trace.routes, 1)
        self.assertFalse(self.trace.closed)
        self.assertEqual(self.trace.channel_results, 80)
        self.trace.close("test")
        self.assertIn("pending_results=0", self.logs[-1])

    def test_unknown_memory_is_not_reported_as_false(self):
        self.selection()
        self.integer(self.owner + 0x50, 0xBAD000, 8)
        self.hit("setup")
        self.hit("transport_check", rax=1)
        self.check_and_finish()
        self.assertIn("transport_state=-1 expected_version=-1 transport_error=-1", self.logs[-1])

    def test_all_signatures_attested_before_arming(self):
        self.trace.close("test")
        for mapping in (module.CHANNEL_SITES, module.CHANNEL_AUXILIARY):
            for item in mapping.items():
                rva, signature = item[1] if mapping is module.CHANNEL_SITES else item
                self.put(self.base + rva, b"x")
                trace = module.ChannelTrace(self.base, self.read, self.registers.__getitem__, self.make,
                    self.logs.append, now=lambda: self.clock, thread=lambda: self.thread_id)
                with self.assertRaisesRegex(ValueError, "signature mismatch"):
                    trace.arm()
                self.assertEqual(self.live, [])
                self.put(self.base + rva, signature)

    def test_limits_retire_only_observer_and_report_pending_pair(self):
        self.trace.maximum_stops = 1
        self.hit("channel")
        self.hit("selector_count", rax=1)
        self.assertTrue(self.trace.closed)
        self.assertEqual(self.live, [])
        self.assertIn("pending_results=1", self.logs[-1])

    def test_event_limit_after_complete_pair_does_not_claim_pending_result(self):
        self.trace.maximum_events = 1  # READY already used the budget.
        self.hit("channel")
        self.hit("channel_result", rbx=0)
        self.assertTrue(self.trace.closed)
        self.assertIn("channel_results=1", self.logs[-1])
        self.assertIn("pending_results=0", self.logs[-1])


if __name__ == "__main__":
    unittest.main()
