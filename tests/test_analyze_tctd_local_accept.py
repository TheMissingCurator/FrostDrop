#!/usr/bin/env python3
"""Tests for the loopback-only TCTD acceptance analyzer."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(PROJECT / "tools/analyze-tctd-local-accept.py"))


class AnalyzeTctdLocalAcceptTests(unittest.TestCase):
    def write_log(self, text: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        temporary.write(text)
        temporary.close()
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def test_counts_acceptance_and_tls_plaintext(self) -> None:
        stack = self.write_log(
            "TCTD_LOCAL_ACCEPT_READY tick_ms=1 detail=ready\n"
            "TCTD_LOCAL_ACCEPT_ARMED tick_ms=2 detail=armed\n"
            "TCTD_LOCAL_ACCEPT_APPLIED tick_ms=3 detail=applied\n"
        )
        listener = self.write_log(
            "TCTD_PC_TLS_ESTABLISHED connection=1 version=TLSv1.2\n"
            "TCTD_PC_CONNECTION_SUMMARY connection=1 stage=tls-established "
            "outcome=tls-idle-timeout client_preface_bytes=8 "
            "client_plaintext_bytes=24 client_plaintext_sha256=abc\n"
        )
        stack_events, errors = ANALYZER["count_events"](stack)
        listener_events, summaries = ANALYZER["parse_listener"](listener)
        self.assertEqual(stack_events["TCTD_LOCAL_ACCEPT_APPLIED"], 1)
        self.assertEqual(errors, [])
        self.assertEqual(listener_events["TCTD_PC_TLS_ESTABLISHED"], 1)
        self.assertEqual(summaries, [("tls-established", "tls-idle-timeout", 24)])

    def test_rejects_malformed_summary(self) -> None:
        listener = self.write_log(
            "TCTD_PC_CONNECTION_SUMMARY connection=1 malformed\n"
        )
        with self.assertRaisesRegex(ValueError, "malformed connection summary"):
            ANALYZER["parse_listener"](listener)


if __name__ == "__main__":
    unittest.main()
