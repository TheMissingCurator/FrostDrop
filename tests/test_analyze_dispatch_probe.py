#!/usr/bin/env python3
"""Focused tests for dispatch type-ID decoding and log parsing."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT_DIR / "tools/analyze-dispatch-probe.py"))


class DispatchAnalyzerTests(unittest.TestCase):
    def test_infers_rip_relative_u16_source(self) -> None:
        data = bytes.fromhex("0fb705f90f0000c3")
        self.assertEqual(ANALYZER["infer_u16_source_rva"](0x1000, data), 0x2000)

    def test_rejects_other_method_shapes(self) -> None:
        self.assertIsNone(
            ANALYZER["infer_u16_source_rva"](
                0x1000, bytes.fromhex("b834120000c3")
            )
        )

    def test_parses_captured_type_id(self) -> None:
        log = "\n".join(
            (
                "DISPATCH_TARGET tick_ms=1 process=2 thread=3 "
                "kind=message-type-method target_rva=0x1000",
                "DISPATCH_CODE tick_ms=1 process=2 thread=3 "
                "kind=message-type-method target_rva=0x1000 length=8 "
                "bytes=0fb705f90f0000c3",
                "DISPATCH_TYPE_ID tick_ms=1 process=2 thread=3 "
                "target_rva=0x1000 source_rva=0x2000 type_id=0x1234",
                "DISPATCH_EVENT sequence=1 tick_ms=2 process=2 thread=3 "
                "direction=outbound target_rva=0x1000 type_id=0x1234",
                "DISPATCH_CALLER tick_ms=2 process=2 thread=3 "
                "type_id=0x1234 return_rva=0x3456",
                "DISPATCH_CALLER_CODE tick_ms=2 process=2 thread=3 "
                "return_rva=0x3456 start_rva=0x3400 length=4 "
                "bytes=9090c390",
                "INBOUND_BATCH_CALLER tick_ms=3 process=2 thread=4 "
                "return_rva=0x4567",
                "INBOUND_SCHEDULER_CALLER tick_ms=4 process=2 thread=5 "
                "return_rva=0x5678",
                "INBOUND_QUEUE_WRITE sequence=1 tick_ms=5 process=2 thread=6 "
                "instruction_rva=0x6000 frame_count=2 rvas=0x6100,0x6200",
                "INBOUND_QUEUE_CODE tick_ms=5 process=2 thread=6 kind=writer "
                "anchor_rva=0x6000 start_rva=0x5f80 length=4 bytes=9090c390",
                "INBOUND_QUEUE_CODE tick_ms=5 process=2 thread=6 "
                "kind=reader-vtable-xref anchor_rva=0x6300 "
                "start_rva=0x6280 length=4 bytes=488dc3cc",
                "INBOUND_QUEUE_PRODUCER sequence=1 tick_ms=6 process=2 thread=7 "
                "instruction_rva=0xf843b6 type_id=0x01ab queue_count=2 "
                "queue_capacity=4 function_rva=0xf84000 "
                "function_end_rva=0xf84600 frame_count=2 "
                "rvas=0x7000,0x8000",
                "INBOUND_QUEUE_PRODUCER_CODE tick_ms=6 process=2 thread=7 "
                "function_rva=0xf84000 function_end_rva=0xf84600 length=4 "
                "bytes=9090c390",
                "INBOUND_READER_CODE tick_ms=6 process=2 thread=7 "
                "kind=read-next target_rva=0x111d640 function_rva=0x111d600 "
                "function_end_rva=0x111d700 length=4 bytes=9090c390",
                "INBOUND_READER_FORWARD_CODE tick_ms=6 process=2 thread=7 "
                "kind=context-init target_rva=0x22378c0 start_rva=0x22378c0 "
                "length=4 bytes=9090c390",
                "INBOUND_READER_FORWARD_CODE tick_ms=6 process=2 thread=7 "
                "kind=source-advance target_rva=0x78db0 start_rva=0x78db0 "
                "length=4 bytes=9090c390",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            (
                targets,
                code,
                type_ids,
                dispatch_events,
                callers,
                caller_code,
                inbound_batch_callers,
                inbound_scheduler_callers,
                queue_writes,
                queue_code,
                queue_producers,
                queue_producer_code,
                inbound_reader_code,
                inbound_reader_forward_code,
                events,
                errors,
            ) = ANALYZER["parse_log"](path)

        self.assertEqual(len(targets), 1)
        self.assertEqual(len(code), 1)
        self.assertEqual(type_ids[0x1000].source_rva, 0x2000)
        self.assertEqual(type_ids[0x1000].type_id, 0x1234)
        self.assertEqual(events["DISPATCH_TYPE_ID"], 1)
        self.assertEqual(len(dispatch_events), 1)
        self.assertEqual(dispatch_events[0].sequence, 1)
        self.assertEqual(dispatch_events[0].direction, "outbound")
        self.assertEqual(dispatch_events[0].type_id, 0x1234)
        self.assertEqual(len(callers), 1)
        self.assertEqual(callers[0].type_id, 0x1234)
        self.assertEqual(callers[0].return_rva, 0x3456)
        self.assertEqual(events["DISPATCH_CALLER"], 1)
        self.assertEqual(caller_code[0x3456].start_rva, 0x3400)
        self.assertEqual(caller_code[0x3456].data, bytes.fromhex("9090c390"))
        self.assertEqual(events["DISPATCH_CALLER_CODE"], 1)
        self.assertEqual(len(inbound_batch_callers), 1)
        self.assertEqual(inbound_batch_callers[0].return_rva, 0x4567)
        self.assertEqual(events["INBOUND_BATCH_CALLER"], 1)
        self.assertEqual(len(inbound_scheduler_callers), 1)
        self.assertEqual(inbound_scheduler_callers[0].return_rva, 0x5678)
        self.assertEqual(events["INBOUND_SCHEDULER_CALLER"], 1)
        self.assertEqual(queue_writes[0].instruction_rva, 0x6000)
        self.assertEqual(queue_writes[0].rvas, (0x6100, 0x6200))
        self.assertEqual(queue_code[0x6000].start_rva, 0x5F80)
        self.assertEqual(queue_code[0x6000].kind, "writer")
        self.assertEqual(queue_code[0x6300].kind, "reader-vtable-xref")
        self.assertEqual(events["INBOUND_QUEUE_WRITE"], 1)
        self.assertEqual(events["INBOUND_QUEUE_CODE"], 2)
        self.assertEqual(queue_producers[0].type_id, 0x01AB)
        self.assertEqual(queue_producers[0].queue_count, 2)
        self.assertEqual(queue_producers[0].queue_capacity, 4)
        self.assertEqual(queue_producers[0].rvas, (0x7000, 0x8000))
        self.assertIsNotNone(queue_producer_code)
        self.assertEqual(queue_producer_code.function_rva, 0xF84000)
        self.assertEqual(queue_producer_code.data, bytes.fromhex("9090c390"))
        self.assertEqual(events["INBOUND_QUEUE_PRODUCER"], 1)
        self.assertEqual(events["INBOUND_QUEUE_PRODUCER_CODE"], 1)
        self.assertEqual(inbound_reader_code["read-next"].target_rva, 0x111D640)
        self.assertEqual(
            inbound_reader_code["read-next"].function_rva,
            0x111D600,
        )
        self.assertEqual(events["INBOUND_READER_CODE"], 1)
        self.assertEqual(
            inbound_reader_forward_code["context-init"].start_rva,
            0x22378C0,
        )
        self.assertEqual(
            inbound_reader_forward_code["source-advance"].target_rva,
            0x78DB0,
        )
        self.assertEqual(events["INBOUND_READER_FORWARD_CODE"], 2)
        self.assertEqual(errors, [])

    def test_old_event_defaults_to_inbound(self) -> None:
        log = (
            "DISPATCH_EVENT sequence=1 tick_ms=2 process=2 thread=3 "
            "target_rva=0x1000 type_id=0x0012\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch.log"
            path.write_text(log, encoding="utf-8")
            parsed = ANALYZER["parse_log"](path)

        self.assertEqual(parsed[3][0].direction, "inbound")


if __name__ == "__main__":
    unittest.main()
