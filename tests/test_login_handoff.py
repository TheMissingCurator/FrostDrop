import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("handoff", Path(__file__).resolve().parents[1] /
                                            "tools/analyze-login-handoff.py")
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


class HandoffAnalysisTest(unittest.TestCase):
    def test_missing_ready(self):
        self.assertIn("WARNING", handoff.summarize(""))

    def test_unknown_not_positive(self):
        result = handoff.summarize("LOGIN_HANDOFF_READY detail=ok\n"
            "LOGIN_HANDOFF_CHECKPOINT detail=stage=frontend-before-sync,services-ticket-present=-1\n")
        self.assertIn("Observed positive signals: none", result)
        self.assertIn("services-ticket-present=-1", result)

    def test_gates_and_no_payload_echo(self):
        result = handoff.summarize("LOGIN_HANDOFF_READY detail=ok\r\n"
            "LOGIN_HANDOFF_CHECKPOINT detail=stage=frontend-before-sync,services-ticket-present=1,"
            "auth-ticket-present=0,suppress-copy=1,secret=DO_NOT_ECHO\n"
            "LOGIN_HANDOFF_CHECKPOINT detail=stage=channel-before-state-gate,kind=0,manager-state=2\n"
            "LOGIN_HANDOFF_LIMIT detail=stage=services-poll\n")
        self.assertIn("kind-0-manager-state-2", result)
        self.assertIn("Record-limit events: 1", result)
        self.assertNotIn("DO_NOT_ECHO", result)
        self.assertIn("do not prove", result)

    def test_malformed(self):
        result = handoff.summarize("LOGIN_HANDOFF_CHECKPOINT detail=stage=services-poll,"
                                  "async-state=not-a-number\nLOGIN_HANDOFF_CHECKPOINT broken\n")
        self.assertNotIn("not-a-number", result)
        self.assertIn("services-poll: 1", result)

    def test_coverage_and_empty_hits(self):
        result = handoff.summarize("LOGIN_HANDOFF_READY detail=ok\n"
            "LOGIN_HANDOFF_COVERAGE detail=pass=2,seen=40,verified=40,repaired=39,"
            "conflicts=0,unverified=0,resume-failed=0,enumeration-error=0,secret=DO_NOT_ECHO\n")
        self.assertIn("verified=40", result)
        self.assertIn("zero checkpoint hits", result)
        self.assertIn("short-lived", result)
        self.assertNotIn("DO_NOT_ECHO", result)

    def test_coverage_failure(self):
        result = handoff.summarize("LOGIN_HANDOFF_COVERAGE detail=conflicts=1,unverified=2\n")
        self.assertIn("coverage reported conflicts", result)
        self.assertIn("no thread readback evidence", handoff.summarize(""))

    def test_sweep_control(self):
        log = "LOGIN_HANDOFF_CONFIG detail=sweep=off,exceptions=first-chance\n"
        result = handoff.summarize(log, "off")
        self.assertIn("Sweeping disabled intentionally", result)
        self.assertNotIn("no thread readback evidence", result)
        self.assertIn("does not match", handoff.summarize(log, "on"))
        self.assertIn("does not match", handoff.summarize("", "off"))

    def test_exception_metadata(self):
        result = handoff.summarize("LOGIN_HANDOFF_EXCEPTION detail=code=0xc0000005,"
            "game-rva=0x1234,access=0x1,secret=DO_NOT_ECHO,rip=bad\n")
        self.assertIn("code=0xc0000005", result)
        self.assertIn("not proof of a fatal crash", result)
        self.assertNotIn("DO_NOT_ECHO", result)
        self.assertNotIn("rip=bad", result)

    def test_zero_debug_resume(self):
        result = handoff.summarize("LOGIN_HANDOFF_ZERO_DEBUG_RESUMED detail=site=1\n")
        self.assertIn("Zero-debug checkpoint resume records: 1", result)
        self.assertIn("First-chance exception records: 0", result)

    def test_log_overflow_warning(self):
        result = handoff.summarize("STACK_PROBE_LOG_ERROR detail=status-format-or-size\n")
        self.assertIn("status logging dropped a record", result)


if __name__ == "__main__":
    unittest.main()
