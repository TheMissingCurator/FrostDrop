#!/usr/bin/env python3
"""Inspect a private captured type-0x0003 login frame without printing bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    Type0003,
    decode_length_prefixed_frame,
    decode_type0003,
)


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def describe_bytes(name: str, value: bytes) -> str:
    return f"{name}: length={len(value)} sha256_16={fingerprint(value)}"


def describe_capture(wire: bytes) -> tuple[object, Type0003, list[str]]:
    frame = decode_length_prefixed_frame(wire)
    if frame.type_id != 0x0003:
        raise ValueError(
            f"private capture contains type {frame.type_id:#06x}, not 0x0003"
        )
    message = decode_type0003(frame.body, None)
    lines = [
        f"frame: type=0x0003 wire_length={len(wire)} body_length={len(frame.body)}",
        f"frame: sha256={hashlib.sha256(wire).hexdigest()}",
        f"byte_0: {message.byte_0}",
        describe_bytes("timed_blob_0.bytes_0", message.timed_blob_0.bytes_0),
        f"timed_blob_0.uint64_0: {message.timed_blob_0.uint64_0}",
        describe_bytes("timed_blob_1.bytes_0", message.timed_blob_1.bytes_0),
        f"timed_blob_1.uint64_0: {message.timed_blob_1.uint64_0}",
        f"identity.byte_0: {message.identity.byte_0}",
        describe_bytes("identity.value", message.identity.value),
        describe_bytes("bytes_0", message.bytes_0),
        f"bools: {int(message.bool_0)},{int(message.bool_1)},{int(message.bool_2)}",
        "bundle_bools: "
        + ",".join(
            str(int(value))
            for value in (
                message.bundle.bool_0,
                message.bundle.bool_1,
                message.bundle.bool_2,
                message.bundle.bool_3,
                message.bundle.bool_4,
                message.bundle.bool_5,
                message.bundle.bool_6,
            )
        ),
        f"bundle_entries: count={len(message.bundle.entries)}",
    ]
    lines.extend(
        describe_bytes(f"bundle.entries[{index}]", entry)
        for index, entry in enumerate(message.bundle.entries)
    )
    lines.extend(
        (
            describe_bytes("timed_blob_2.bytes_0", message.timed_blob_2.bytes_0),
            f"timed_blob_2.uint64_0: {message.timed_blob_2.uint64_0}",
        )
    )
    return frame, message, lines


def write_private_profile(path: Path, body: bytes) -> None:
    document = {
        "description": (
            "Private captured retail type-0x0003 diagnostic profile; may "
            "contain account or short-lived session material"
        ),
        "expected_marker": 3,
        "login_request_type": 2,
        "control_request_type": 5,
        "control_request_channel": 10,
        "correlate_control_response": True,
        "type0003_body_hex": body.hex(),
        "type0006_body_hex": "0000",
    }
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2)
            output.write("\n")
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument(
        "--write-profile",
        type=Path,
        help="create a mode-0600 replay profile; refuses to overwrite",
    )
    args = parser.parse_args()
    try:
        wire = args.capture.read_bytes()
        frame, _, lines = describe_capture(wire)
        for line in lines:
            print(line)
        if args.write_profile is not None:
            write_private_profile(args.write_profile, frame.body)
            print(f"private_profile_written: {args.write_profile}")
            print(
                "warning: keep this file private; captured login fields may "
                "be account-specific or expire",
                file=sys.stderr,
            )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
