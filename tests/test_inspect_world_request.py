#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_DIR / "tools" / "inspect-world-request.py"
SPEC = importlib.util.spec_from_file_location("inspect_world_request", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

from isac_protocol import (  # noqa: E402
    MessageFrame,
    OutboundEnvelope,
    encode_outbound_envelope,
)


def main() -> None:
    wire = encode_outbound_envelope(
        OutboundEnvelope(
            marker=3,
            channel=0,
            frames=(MessageFrame(type_id=0, body=b"private-value"),),
        )
    )
    lines = MODULE.describe_capture(wire)
    output = "\n".join(lines)
    assert "marker=3 channel=0" in output
    assert "type=0x0000" in output
    assert "body_length=13" in output
    assert "private-value" not in output


if __name__ == "__main__":
    main()
