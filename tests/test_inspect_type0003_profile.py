#!/usr/bin/env python3
"""Tests for the private type-0x0003 capture inspector."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    ControlIdentity,
    MessageFrame,
    Type0003,
    Type0003Bundle,
    Type0003TimedBlob,
    encode_length_prefixed_frame,
    encode_type0003,
)


class InspectType0003ProfileTests(unittest.TestCase):
    def test_summary_is_redacted_and_profile_is_private(self) -> None:
        secret = b"private-account-value"
        message = Type0003(
            1,
            Type0003TimedBlob(secret, 2),
            Type0003TimedBlob(b"ticket", 3),
            ControlIdentity(4, b"identity"),
            b"name",
            True,
            False,
            True,
            Type0003Bundle(False, True, False, True, False, True, False, (b"x",)),
            Type0003TimedBlob(b"last", 5),
        )
        body = encode_type0003(message, None)
        wire = encode_length_prefixed_frame(MessageFrame(0x0003, body))
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.bin"
            profile = Path(directory) / "profile.json"
            capture.write_bytes(wire)
            result = subprocess.run(
                (
                    sys.executable,
                    str(PROJECT_DIR / "tools/inspect-type0003-profile.py"),
                    str(capture),
                    "--write-profile",
                    str(profile),
                ),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertNotIn(secret.decode(), result.stdout)
            self.assertIn("timed_blob_0.bytes_0: length=21", result.stdout)
            self.assertEqual(
                stat.S_IMODE(profile.stat().st_mode),
                0o600,
            )
            self.assertEqual(json.loads(profile.read_text())["type0003_body_hex"], body.hex())


if __name__ == "__main__":
    unittest.main()
