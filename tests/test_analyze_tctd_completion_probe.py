#!/usr/bin/env python3
"""Tests for the TCTD asynchronous completion-path analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(
    str(PROJECT / "tools/analyze-tctd-completion-probe.py")
)


class AnalyzeTctdCompletionProbeTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_parses_checkpoint_state_and_callers(self) -> None:
        path = self.write_log(
            "TCTD_COMPLETION_PROBE_READY tick_ms=1 process=2 thread=3 detail=ready\n"
            "TCTD_COMPLETION_CHECKPOINT tick_ms=2 process=2 thread=3 "
            "detail=sequence=1,checkpoint=completion-setter,state=readable,"
            "state-byte=zero,rax-class=wide,rax-low32=0x12345678,"
            "zf=0,cf=0,sf=0,caller-count=2,caller-rvas=0xbb537,0xbbba7,"
            "mutation=disabled,payloads=disabled\n"
        )
        checkpoints, events, errors = ANALYZER["parse_stack_log"](path)
        self.assertEqual(events["TCTD_COMPLETION_PROBE_READY"], 1)
        self.assertEqual(errors, [])
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0].name, "completion-setter")
        self.assertEqual(checkpoints[0].state_byte, "zero")
        self.assertEqual(checkpoints[0].callers, (0xBB537, 0xBBBA7))

    def test_reconstructs_contiguous_code_region(self) -> None:
        path = self.write_log(
            "CODE tick_ms=1 process=2 thread=3 "
            "label=tctd-completion-region-00 target_rva=0x1000 "
            "start_rva=0x1000 length=4 bytes=01020304\n"
            "CODE tick_ms=1 process=2 thread=3 "
            "label=tctd-completion-region-01 target_rva=0x1004 "
            "start_rva=0x1004 length=2 bytes=0506\n"
        )
        windows = ANALYZER["parse_code_log"](path)
        origin, body = ANALYZER["reconstruct"](windows)
        self.assertEqual(origin, 0x1000)
        self.assertEqual(body, b"\x01\x02\x03\x04\x05\x06")

    def test_rejects_noncontiguous_code_region(self) -> None:
        path = self.write_log(
            "CODE tick_ms=1 process=2 thread=3 "
            "label=tctd-completion-region-00 target_rva=0x1000 "
            "start_rva=0x1000 length=2 bytes=0102\n"
            "CODE tick_ms=1 process=2 thread=3 "
            "label=tctd-completion-region-01 target_rva=0x1003 "
            "start_rva=0x1003 length=1 bytes=04\n"
        )
        with self.assertRaisesRegex(ValueError, "not contiguous"):
            ANALYZER["reconstruct"](ANALYZER["parse_code_log"](path))


if __name__ == "__main__":
    unittest.main()
