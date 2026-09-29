#!/usr/bin/env python3
"""Tests for the TCTD certificate-processing chain analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-chain-probe.py"))


class AnalyzeTctdChainProbeTests(unittest.TestCase):
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
            "TCTD_CHAIN_PROBE_READY tick_ms=1 process=2 thread=3 detail=ready\n"
            "TCTD_CHAIN_CHECKPOINT tick_ms=2 process=2 thread=3 "
            "detail=sequence=1,checkpoint=key-parser-return,rax-class=u8,"
            "rax-low32=0x00000001,zf=0,cf=0,sf=0,caller-count=2,"
            "caller-rvas=0x20167db,0x223b8d5,mutation=disabled,"
            "payloads=disabled\n"
        )
        checkpoints, events, errors = ANALYZER["parse_stack_log"](path)
        self.assertEqual(events["TCTD_CHAIN_PROBE_READY"], 1)
        self.assertEqual(errors, [])
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0].name, "key-parser-return")
        self.assertEqual(checkpoints[0].rax_low32, 1)
        self.assertEqual(checkpoints[0].callers, (0x20167DB, 0x223B8D5))

    def test_parses_code_window_and_checks_length(self) -> None:
        path = self.write_log(
            "CODE tick_ms=1 process=2 thread=3 label=tctd-chain-key-parser "
            "target_rva=0x2016925 start_rva=0x2016885 length=4 "
            "bytes=01020304\n"
        )
        windows = ANALYZER["parse_code_log"](path)
        self.assertEqual(
            windows["tctd-chain-key-parser"],
            (0x2016925, 0x2016885, 4),
        )

    def test_rejects_caller_count_mismatch(self) -> None:
        path = self.write_log(
            "TCTD_CHAIN_CHECKPOINT tick_ms=2 process=2 thread=3 "
            "detail=sequence=1,checkpoint=tls-parser-return,rax-class=zero,"
            "rax-low32=0x00000000,zf=1,cf=0,sf=0,caller-count=2,"
            "caller-rvas=0x2248085,mutation=disabled,payloads=disabled\n"
        )
        with self.assertRaisesRegex(ValueError, "caller-count mismatch"):
            ANALYZER["parse_stack_log"](path)


if __name__ == "__main__":
    unittest.main()
