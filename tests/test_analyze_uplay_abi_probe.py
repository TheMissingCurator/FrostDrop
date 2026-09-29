#!/usr/bin/env python3
"""Tests for the metadata-only Uplay ABI analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(
    str(PROJECT_DIR / "tools/analyze-uplay-abi-probe.py")
)


class UplayAbiAnalyzerTests(unittest.TestCase):
    def test_pairs_shape_only_call_and_return(self) -> None:
        log = "\n".join(
            (
                "UPLAY_ABI_READY max-samples-per-function=16",
                "UPLAY_ABI_CALL tick_ms=1 process=2 thread=3 "
                "function=UPLAY_USER_IsOwned sample=1 "
                "caller=main-image:0x1234 arg0=writable-pointer",
                "UPLAY_ABI_RETURN tick_ms=2 process=2 thread=3 "
                "function=UPLAY_USER_IsOwned sample=1 "
                "rax=scalar32:0x00000001 rdx=opaque-nonpointer "
                "xmm0_nonzero=no arg0_word_changed=yes,nested_utf8_length=8",
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "abi.log"
            path.write_text(log, encoding="utf-8")
            summaries, events, errors = ANALYZER["parse_log"](path)

        summary = summaries["UPLAY_USER_IsOwned"]
        self.assertEqual(summary.calls, 1)
        self.assertEqual(summary.returns, 1)
        self.assertEqual(summary.mutations[0]["yes"], 1)
        self.assertEqual(summary.nested_lengths[0][8], 1)
        self.assertEqual(events["UPLAY_ABI_READY"], 1)
        self.assertEqual(errors, [])

    def test_reports_probe_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "abi.log"
            path.write_text(
                "UPLAY_ABI_ERROR reason=return-without-entry\n",
                encoding="utf-8",
            )
            _, events, errors = ANALYZER["parse_log"](path)

        self.assertEqual(events["UPLAY_ABI_ERROR"], 1)
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
