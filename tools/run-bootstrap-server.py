#!/usr/bin/env python3
"""Run the Project ISAC application-plaintext bootstrap server."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
from pathlib import Path
from typing import Callable


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "src"))

from isac_backend import (  # noqa: E402
    BootstrapConnection,
    BootstrapProfile,
    BootstrapProtocolError,
    BootstrapStateMachine,
    BRIDGE_REPLAY_HEADER,
    WorldReplay,
)
from isac_protocol import (  # noqa: E402
    DecodeError,
    Type0002,
    Type0003,
    Type0006,
    decode_type0002,
    decode_type0003,
    decode_type0006,
)


def _decode_body(
    document: dict[str, object],
    key: str,
    decoder: Callable[[bytes, None], object],
    expected_type: type,
) -> object | None:
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a hexadecimal string or null")
    try:
        body = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{key} is not valid hexadecimal") from error
    decoded = decoder(body, None)
    if not isinstance(decoded, expected_type):
        raise ValueError(f"{key} decoded to an unexpected model")
    return decoded


def load_profile(path: Path | None) -> BootstrapProfile:
    if path is None:
        return BootstrapProfile(None, None)
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("bootstrap profile must contain a JSON object")
    legacy_login_response = _decode_body(
        document, "type0002_body_hex", decode_type0002, Type0002
    )
    retail_login_response = _decode_body(
        document, "type0003_body_hex", decode_type0003, Type0003
    )
    if legacy_login_response is not None and retail_login_response is not None:
        raise ValueError(
            "configure only one of type0002_body_hex and type0003_body_hex"
        )
    login_response = (
        retail_login_response
        if retail_login_response is not None
        else legacy_login_response
    )
    control_response = _decode_body(
        document, "type0006_body_hex", decode_type0006, Type0006
    )
    correlate_control_response = document.get("correlate_control_response", True)
    if not isinstance(correlate_control_response, bool):
        raise ValueError("correlate_control_response must be a Boolean")
    return BootstrapProfile(
        login_response=login_response,
        control_response=control_response,
        expected_marker=int(document.get("expected_marker", 3)),
        login_request_type=int(document.get("login_request_type", 0x0002)),
        control_request_type=int(document.get("control_request_type", 0x0005)),
        control_request_channel=int(document.get("control_request_channel", 0x0A)),
        correlate_control_response=correlate_control_response,
        world_request_channel=int(document.get("world_request_channel", 0)),
        world_request_type=int(document.get("world_request_type", 0x0000)),
        world_request_min_body_bytes=int(
            document.get("world_request_min_body_bytes", 512)
        ),
        world_request_max_body_bytes=int(
            document.get("world_request_max_body_bytes", 2048)
        ),
    )


async def replay_world(
    writer: asyncio.StreamWriter,
    write_lock: asyncio.Lock,
    replay: WorldReplay,
) -> None:
    loop = asyncio.get_running_loop()
    started = loop.time()
    async with write_lock:
        writer.write(BRIDGE_REPLAY_HEADER)
        await writer.drain()
    print(
        "world replay armed "
        f"records={len(replay.spans)} payload_bytes={replay.payload_bytes} "
        f"duration_ms={replay.duration_ms}",
        flush=True,
    )
    for span in replay.spans:
        target = started + span.delta_ms / 1000.0
        delay = target - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
        async with write_lock:
            writer.write(span.data)
            await writer.drain()
    print(
        "world replay complete "
        f"frames={replay.frame_count} gate_frame={replay.first_gate_frame}",
        flush=True,
    )


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    profile: BootstrapProfile,
    world_replay: WorldReplay | None,
) -> None:
    peer = writer.get_extra_info("peername")
    connection = BootstrapConnection(BootstrapStateMachine(profile))
    write_lock = asyncio.Lock()
    replay_task: asyncio.Task[None] | None = None
    raw_socket = writer.get_extra_info("socket")
    if raw_socket is not None:
        raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f"client connected peer={peer!r}", flush=True)
    try:
        while chunk := await reader.read(65536):
            batch = connection.feed_client_bytes(chunk)
            for event in batch.events:
                request_types = ",".join(
                    f"{type_id:#06x}" for type_id in event.request_type_ids
                ) or "-"
                response_types = ",".join(
                    f"{frame.type_id:#06x}" for frame in event.responses
                ) or "-"
                print(
                    f"channel={event.channel} phase={event.phase_before.value}->"
                    f"{event.phase_after.value} requests={request_types} "
                    f"responses={response_types} "
                    f"world_replay={'selected' if event.world_request_selected else '-'}",
                    flush=True,
                )
            if batch.server_bytes:
                async with write_lock:
                    writer.write(batch.server_bytes)
                    await writer.drain()
            if (
                world_replay is not None
                and replay_task is None
                and any(event.world_request_selected for event in batch.events)
            ):
                replay_task = asyncio.create_task(
                    replay_world(writer, write_lock, world_replay)
                )
    except (BootstrapProtocolError, DecodeError) as error:
        print(f"client protocol error peer={peer!r}: {error}", file=sys.stderr)
    finally:
        if replay_task is not None:
            if not replay_task.done():
                replay_task.cancel()
            await asyncio.gather(replay_task, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        print(f"client disconnected peer={peer!r}", flush=True)


async def serve(
    host: str,
    port: int,
    profile: BootstrapProfile,
    world_replay: WorldReplay | None,
) -> None:
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(
            reader,
            writer,
            profile,
            world_replay,
        ),
        host,
        port,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or ())
    print(f"Project ISAC plaintext bootstrap server listening on {sockets}")
    async with server:
        await server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        type=Path,
        help="local JSON response profile; omit for observe-only mode",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=55000)
    parser.add_argument(
        "--world-replay",
        type=Path,
        help="private ISACWBS1 timed world-bootstrap capture",
    )
    parser.add_argument(
        "--check-profile",
        action="store_true",
        help="validate the profile and exit without opening a socket",
    )
    args = parser.parse_args()
    try:
        profile = load_profile(args.profile)
        world_replay = (
            WorldReplay.from_file(args.world_replay)
            if args.world_replay is not None
            else None
        )
    except (OSError, ValueError, json.JSONDecodeError, DecodeError) as error:
        parser.error(str(error))
    if args.port < 0 or args.port > 65535:
        parser.error("port must be in range 0..65535")
    if args.check_profile:
        print(
            "Profile valid: "
            f"login={type(profile.login_response).__name__ if profile.login_response else 'disabled'}, "
            f"type0006={'configured' if profile.control_response else 'disabled'}, "
            f"world_replay={'configured' if world_replay else 'disabled'}"
        )
        return 0
    try:
        asyncio.run(serve(args.host, args.port, profile, world_replay))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
