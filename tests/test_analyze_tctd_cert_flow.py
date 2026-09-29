#!/usr/bin/env python3
"""Tests for the copy-following certificate-flow analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-cert-flow.py"))


class AnalyzeTctdCertFlowTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_parses_copy_and_consumer_events(self) -> None:
        path = self.write_log(
            "TCTD_CERT_FLOW_READY tick_ms=1 process=2 thread=3 detail=ready\n"
            "TCTD_CERT_FLOW tick_ms=2 process=2 thread=3 "
            "detail=sequence=1,generation=1,instruction-rva=set,"
            "instruction=0x21fea19,access=copy-source,action=followed,"
            "copy-relative-offset=24,copy-length=91,consumer-rva=none,"
            "caller-count=1,caller-rvas=0x2016925,payloads=disabled\n"
            "TCTD_CERT_FLOW tick_ms=3 process=2 thread=3 "
            "detail=sequence=2,generation=1,instruction-rva=set,"
            "instruction=0x1234,access=consumer,action=retained,"
            "copy-relative-offset=none,copy-length=none,consumer-rva=0x1200,"
            "caller-count=2,caller-rvas=0x2000,0x3000,payloads=disabled\n"
        )
        flows, events, errors = ANALYZER["parse_log"](path)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0].action, "followed")
        self.assertEqual(flows[0].relative_offset, 24)
        self.assertEqual(flows[1].consumer, 0x1200)
        self.assertEqual(flows[1].callers, (0x2000, 0x3000))
        self.assertEqual(events["TCTD_CERT_FLOW_READY"], 1)
        self.assertEqual(errors, [])

    def test_rejects_copy_without_metadata(self) -> None:
        path = self.write_log(
            "TCTD_CERT_FLOW tick_ms=2 process=2 thread=3 "
            "detail=sequence=1,generation=0,instruction-rva=outside-game,"
            "access=copy-source,action=retained,copy-relative-offset=none,"
            "copy-length=none,consumer-rva=none,caller-count=0,"
            "caller-rvas=none,payloads=disabled\n"
        )
        with self.assertRaisesRegex(ValueError, "lacks copy metadata"):
            ANALYZER["parse_log"](path)

    def test_parses_decision_code_window(self) -> None:
        path = self.write_log(
            "CODE tick_ms=1 process=2 thread=3 "
            "label=tctd-flow-shared-verify target_rva=0x205291d "
            "start_rva=0x205287d length=4 bytes=01020304\n"
        )
        windows = ANALYZER["parse_decision_code_log"](path)
        self.assertEqual(
            windows,
            [("tctd-flow-shared-verify", 0x205291D, 0x205287D, 4)],
        )


if __name__ == "__main__":
    unittest.main()
