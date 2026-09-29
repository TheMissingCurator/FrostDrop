#!/usr/bin/env python3
"""Validate framing and chunk reassembly against plaintext-probe evidence."""

from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_protocol import (  # noqa: E402
    CLIENT_TO_SERVER,
    DecodedMessage,
    InboundFrameStreamDecoder,
    OutboundEnvelopeStreamDecoder,
    ReferenceTable,
    build_default_registry,
    decode_length_prefixed_frame,
    decode_outbound_envelope,
    encode_length_prefixed_frame,
    encode_outbound_envelope,
)


def _chunks(data: bytes) -> list[bytes]:
    sizes = (1, 2, 5, 13, 3, 8)
    chunks: list[bytes] = []
    offset = 0
    index = 0
    while offset < len(data):
        length = sizes[index % len(sizes)]
        chunks.append(data[offset : offset + length])
        offset += length
        index += 1
    return chunks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="project-isac-plaintext-probe.log")
    args = parser.parse_args()
    analyzer = runpy.run_path(str(PROJECT_DIR / "tools/analyze-plaintext-probe.py"))

    try:
        records, _events, probe_errors = analyzer["parse_log"](args.log)
        outbound = [record.data for record in records if record.direction == "outbound"]
        inbound = [record.data for record in records if record.direction == "inbound"]

        outbound_envelopes = []
        outbound_frames = 0
        for encoded in outbound:
            decoded = decode_outbound_envelope(encoded)
            if encode_outbound_envelope(decoded) != encoded:
                raise ValueError("outbound envelope did not round-trip")
            outbound_envelopes.append(decoded)
            outbound_frames += len(decoded.frames)

        inbound_frames = []
        for encoded in inbound:
            decoded = decode_length_prefixed_frame(encoded)
            if encode_length_prefixed_frame(decoded) != encoded:
                raise ValueError("inbound frame did not round-trip")
            inbound_frames.append(decoded)

        registry = build_default_registry()
        known_frames = 0
        opaque_frames = 0
        decode_table = ReferenceTable(assume_existing=True)
        encode_table = ReferenceTable(assume_existing=True)
        for frame in (
            inner
            for envelope in outbound_envelopes
            for inner in envelope.frames
        ):
            decoded = registry.decode(
                CLIENT_TO_SERVER,
                frame,
                decode_table,
                allow_unknown=True,
            )
            if isinstance(decoded, DecodedMessage):
                reencoded = registry.encode(
                    CLIENT_TO_SERVER,
                    decoded.type_id,
                    decoded.value,
                    encode_table,
                )
                if reencoded != frame:
                    raise ValueError(
                        f"registered type {frame.type_id:#06x} did not round-trip"
                    )
                known_frames += 1
            else:
                opaque_frames += 1

        outbound_stream = OutboundEnvelopeStreamDecoder()
        streamed_outbound = []
        for chunk in _chunks(b"".join(outbound)):
            streamed_outbound.extend(outbound_stream.feed(chunk))
        if streamed_outbound != outbound_envelopes or outbound_stream.buffered_bytes:
            raise ValueError("outbound chunk reassembly differs from record decoding")

        inbound_stream = InboundFrameStreamDecoder()
        streamed_inbound = []
        for chunk in _chunks(b"".join(inbound)):
            streamed_inbound.extend(inbound_stream.feed(chunk))
        if streamed_inbound != inbound_frames or inbound_stream.buffered_bytes:
            raise ValueError("inbound chunk reassembly differs from record decoding")
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Log: {args.log}")
    print(f"Outbound envelopes: {len(outbound_envelopes)}")
    print(f"Outbound nested frames: {outbound_frames}")
    print(f"Inbound frames: {len(inbound_frames)}")
    print(f"Byte-identical outbound round trips: {len(outbound_envelopes)}")
    print(f"Byte-identical inbound round trips: {len(inbound_frames)}")
    print(f"Registry-decoded outbound frames: {known_frames}")
    print(f"Opaque outbound frames: {opaque_frames}")
    print(f"Probe-reported errors retained in source log: {len(probe_errors)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
