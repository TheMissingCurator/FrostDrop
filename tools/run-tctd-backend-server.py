#!/usr/bin/env python3
"""Loopback backend transport endpoint; not yet a login/world server.

Serves the pre-TLS greeting, a bootstrap-CA-signed TLS identity and the
candidate backend version. Optional channel setup handles settings,
registrations and heartbeats; a sibling listener implements protocol 556.
Captures application messages privately without forwarding to retail servers.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import runpy
import signal
import selectors
import socket
import ssl
import sys
import threading
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from isac_protocol.codec import Cursor, DecodeError
from isac_protocol.compression import CompressedStreamDecoder, encode_compressed_stream
from isac_protocol.transport import TransportStreamDecoder, channel_payload, encode_protocol_version, encode_transport_frame
from isac_backend.channels import ChannelSetup, initial_settings
from isac_backend.services import local_service_advertisements, SERVICE_TYPES
from isac_protocol.service_advertisement import encode_service_advertisement
from isac_backend.latency import LatencySession, latency_greeting
from isac_backend.auth import AuthSession
from isac_backend.profiles import ProfileSession
from isac_backend.server_list import ServerListSession
from isac_backend.profile_store import ProfileStore
from isac_backend.world_startup import ExperimentalWorldTemplate, read_template
from isac_backend.world_continuation import ExperimentalWorldContinuation, read_continuation
from isac_backend.character_template import ExperimentalCharacterTemplate, read_character_template
from isac_backend.world_tutorial import ExperimentalTutorialActivation, read_tutorial_activation
from isac_backend.world_tutorial_objective import ExperimentalFirstObjective, read_first_objective
from isac_backend.world_tutorial_cover import ExperimentalCoverCompletion, read_cover_completion
from isac_backend.world_tutorial_stages import ExperimentalStageProgression, read_stage_progression
from isac_backend.world_tutorial_next import ExperimentalNextActivity, read_next_activity, read_dialogue_015a
from isac_backend.world_agent import ExperimentalAgentResponse, read_agent_response
from isac_protocol.profile_messages import decode_create_profile_request

TLS = runpy.run_path(str(PROJECT / "tools/run-tctd-pc-tls-probe.py"))
PUBLIC_SERVICE_NAMES = {name.encode('ascii'): name for name in SERVICE_TYPES}


def public_service_name(registration):
    # Known catalog categories only; never print arbitrary client names/IDs.
    return PUBLIC_SERVICE_NAMES.get(registration.name, 'unrecognized')


def capture_create_request(directory, identifier, channel, sequence, body):
    """Checkpoint ONLY the bounded create request, before dispatch can fail.

    This is uint32 request ID plus two booleans, not a token/profile/world dump.
    Unknown or oversized shapes aren't saved. No dependency on graceful exit.
    A diagnostic write failure must not change game responses.
    """
    prefix = (f'TCTD_PROFILE_CREATE_REQUEST connection={identifier} channel={channel} '
              f'sequence={sequence} body_bytes={len(body)}')
    try:
        if len(body) > 7:
            raise DecodeError('create request bound')
        request = decode_create_profile_request(body)
    except DecodeError:
        print(prefix + ' shape=unsupported artifact=not-saved', flush=True)
        return
    status = 'saved'
    try:
        TLS['private_write'](directory / f'backend-{identifier:04d}-create-{sequence:04d}.bin', body)
    except OSError:
        status = 'write-failed'
    print(prefix + f' request_id={request.request_id} flag_5={int(request.flag_5)} '
          f'flag_4={int(request.flag_4)} artifact={status}', flush=True)


def capture_agent_request(directory, identifier, channel, body):
    """Checkpoint one private bounded submission even if shutdown later hangs."""
    status = 'unsupported-shape'
    if len(body) == 147:
        try:
            TLS['private_write'](directory / f'backend-{identifier:04d}-agent-{channel:02d}.bin', body)
            status = 'saved'
        except OSError:
            status = 'write-failed'
    print(f'TCTD_AGENT_REQUEST connection={identifier} channel={channel} '
          f'body_bytes={len(body)} artifact={status}', flush=True)


def capture_cover_candidate(directory, identifier, channel, sequence, body, stage):
    """Checkpoint bounded private cover traffic before an abrupt game exit."""
    status = 'unsupported-shape'
    if len(body) == 67:
        try:
            TLS['private_write'](directory / f'backend-{identifier:04d}-cover-{sequence:02d}.bin', body)
            status = 'saved'
        except OSError:
            status = 'write-failed'
    print(f'TCTD_COVER_CANDIDATE connection={identifier} channel={channel} '
          f'sequence={sequence} body_bytes={len(body)} stage={stage} artifact={status}', flush=True)


def log_profile_failure(identifier, channel, frame, event):
    failure = event.failure
    if failure is not None:
        print(f'TCTD_PROFILE_FAILURE connection={identifier} channel={channel} '
              f'type=0x{frame.type_id:04x} operation={failure.operation} reason={failure.reason} '
              f'sqlite_code={failure.sqlite_code} os_errno={failure.os_errno}', flush=True)


@dataclass(frozen=True)
class BackendConfig:
    capture_dir: Path
    server_preface: bytes
    expected_client_preface: bytes
    protocol_version: int = 2056  # constructor call RVA 0x2f756; confirm in game
    io_timeout: float = 5.0
    idle_timeout: float = 20.0
    session_timeout: float | None = 90.0
    max_capture_bytes: int = 262144
    channel_setup: bool = False
    service_advertisements: bool = False
    experimental_auth: bool = False
    experimental_profiles: bool = False
    profile_store: ProfileStore | None = None
    world_template: ExperimentalWorldTemplate | None = None
    world_continuation: ExperimentalWorldContinuation | None = None
    agent_response: ExperimentalAgentResponse | None = None
    character_template: ExperimentalCharacterTemplate | None = None
    tutorial_activation: ExperimentalTutorialActivation | None = None
    first_objective: ExperimentalFirstObjective | None = None
    cover_completion: ExperimentalCoverCompletion | None = None
    stage_progression: ExperimentalStageProgression | None = None
    next_activity: ExperimentalNextActivity | None = None
    dialogue_015a: bytes | None = None

    def __post_init__(self):
        if self.service_advertisements and (not self.channel_setup or self.protocol_version != 2056):
            raise ValueError("service advertisements require protocol-2056 channel setup")
        if self.experimental_auth and not self.service_advertisements:
            raise ValueError("experimental auth requires local service advertisements")
        if self.experimental_profiles and not self.experimental_auth:
            raise ValueError("experimental profiles require local auth")
        if self.world_template is not None and not self.experimental_profiles:
            raise ValueError('experimental world template requires local profiles')
        if self.world_continuation is not None and self.world_template is None:
            raise ValueError('experimental world continuation requires world template')
        if self.agent_response is not None and self.world_continuation is None:
            raise ValueError('experimental agent response requires world continuation')
        if self.character_template is not None and self.agent_response is None:
            raise ValueError('experimental character template requires agent response')
        if self.tutorial_activation is not None and self.character_template is None:
            raise ValueError('experimental tutorial activation requires character template')
        if self.first_objective is not None and self.tutorial_activation is None:
            raise ValueError('first-objective test requires tutorial activation')
        if self.cover_completion is not None and self.first_objective is None:
            raise ValueError('cover-completion test requires first objective')
        if self.stage_progression is not None and self.cover_completion is None:
            raise ValueError('stage-progression test requires cover completion')
        if self.next_activity is not None and self.stage_progression is None:
            raise ValueError('next activity requires stage progression')
        if self.dialogue_015a is not None and self.next_activity is None:
            raise ValueError('dialogue candidate requires next activity')
        if self.experimental_profiles and self.profile_store is None:
            object.__setattr__(self, 'profile_store', ProfileStore())


def frame_metadata(frame) -> str:
    fields = f"control={int(frame.control)} type=0x{frame.type_id:04x} body_bytes={len(frame.body)}"
    if frame.control and frame.type_id == 3:
        cursor = Cursor(frame.body)
        version = cursor.read_uvarint(maximum_bits=32)
        if cursor.remaining:
            raise DecodeError("trailing protocol version bytes")
        fields += f" protocol_version={version}"
    elif not frame.control and frame.type_id == 3:
        channel, payload = channel_payload(frame)
        fields += f" channel={channel} inner_bytes={len(payload)}"
    return fields


def handle_connection(identifier, client, context, config, stop=None):
    stop = stop if stop is not None else threading.Event()
    tls = None
    plaintext = bytearray()
    client_root = bytearray()
    live_world = config.world_template is not None
    def retain(buffer, data):
        buffer.extend(data[:max(0, config.max_capture_bytes - len(buffer))])
    decoder = TransportStreamDecoder()
    # Protocol 2056's TLS plaintext is a compressed stream, unlike the
    # certificate, directory and plain-TCP latency services (finding 096).
    compression = CompressedStreamDecoder(None if live_world else config.max_capture_bytes) if config.protocol_version == 2056 else None
    encode_wire = encode_compressed_stream if compression is not None else bytes
    decode_layer = "root-framing"
    stage, outcome = "accepted", "unknown"
    frames = 0
    responses = 0
    inner_count = 0
    world_observed = set()
    create_observed = 0
    agent_observed = set()
    cover_observed = 0
    outbound = bytearray()
    channels = ChannelSetup() if config.channel_setup else None
    auth = AuthSession() if config.experimental_auth else None
    profiles = ProfileSession(auth, config.profile_store) if config.experimental_profiles else None
    server_list = ServerListSession(auth, profiles, config.world_template,
                                    config.world_continuation,
                                    config.agent_response,
                                    config.character_template,
                                    config.tutorial_activation, config.first_objective,
                                    config.cover_completion, config.stage_progression,
                                    config.next_activity, config.dialogue_015a) if profiles is not None else None
    try:
        client.settimeout(config.io_timeout)
        client.sendall(config.server_preface)
        stage = "server-preface-sent"
        preface = TLS["receive_exact"](client, len(config.expected_client_preface))
        TLS["private_write"](config.capture_dir / f"backend-{identifier:04d}-client-preface.bin", preface)
        # Historical backend greetings end in 00000000 and 02000000, while
        # the certificate service ends in 08000000. Preserve those opaque
        # four bytes; do not mistake a service-specific value for a mismatch.
        matches = (len(preface) == 8 and preface[:4] == config.expected_client_preface[:4])
        print(f"TCTD_BACKEND_PREFACE connection={identifier} bytes={len(preface)} "
              f"header_match={int(matches)} template_match={int(preface == config.expected_client_preface)}", flush=True)
        if not matches:
            outcome = "client-preface-mismatch"
            return
        client.sendall(TLS["SERVER_TRANSITION"])
        stage = "tls-handshake"
        tls = context.wrap_socket(client, server_side=True)
        stage = "tls-established"
        print(f"TCTD_BACKEND_TLS_ESTABLISHED connection={identifier} version={tls.version()} "
              f"client_certificate={int(bool(tls.getpeercert(binary_form=True)))}", flush=True)
        response = encode_protocol_version(config.protocol_version)
        if channels is not None:
            response += encode_transport_frame(initial_settings())
        advertisements = local_service_advertisements() if config.service_advertisements else ()
        for advertisement in advertisements:
            response += encode_transport_frame(encode_service_advertisement(advertisement))
        tls.sendall(encode_wire(response))
        retain(outbound, response)
        stage = "version-sent"
        print(f"TCTD_BACKEND_VERSION_SENT connection={identifier} version={config.protocol_version} "
              f"compression={'lz4-block-stream' if compression is not None else 'none'} "
              "client_acceptance=unconfirmed", flush=True)
        if channels is not None:
            print(f"TCTD_BACKEND_SETTINGS_SENT connection={identifier} policy_table=disabled "
                  "client_acceptance=unconfirmed", flush=True)
        if advertisements:
            print(f"TCTD_BACKEND_ADVERTISEMENTS_SENT connection={identifier} count={len(advertisements)} "
                  "catalog=local-v1 client_acceptance=unconfirmed services=not-implemented", flush=True)
        tls.settimeout(0.5)
        start = last_read = time.monotonic()
        while not stop.is_set():
            now = time.monotonic()
            if server_list is not None:
                for due in server_list.poll_due():
                    reply = encode_transport_frame(due.response)
                    tls.sendall(encode_wire(reply))
                    retain(outbound, reply)
                    responses += 1
                    sent = ','.join(f'0x{item:04x}' for item in due.response_types)
                    label = ('TCTD_TUTORIAL_CLOSE_SEND' if
                             due.stage == 'instance-experimental-activity-close-sent'
                             else 'TCTD_DIALOGUE_015A_SEND' if
                             due.stage == 'instance-experimental-dialogue-015a-sent'
                             else 'TCTD_NEXT_ACTIVITY_SEND')
                    print(f'{label} connection={identifier} '
                          f'stage={due.stage} frames={sent} '
                          'result=sendall-returned client_acceptance=unconfirmed', flush=True)
                    if due.stage == 'instance-experimental-activity-close-sent':
                        try:
                            (config.capture_dir / 'weapon-gate-activity-closed.ready').touch(
                                mode=0o600, exist_ok=True)
                        except OSError:
                            print('TCTD_WEAPON_GATE_CLOSE_MARKER write-failed', flush=True)
            if config.session_timeout is not None and now - start >= config.session_timeout:
                outcome = "session-limit"
                break
            if now - last_read >= config.idle_timeout:
                outcome = "idle-timeout"
                break
            remaining = config.max_capture_bytes - len(plaintext)
            if not live_world and remaining <= 0:
                outcome = "capture-limit"
                break
            try:
                data = tls.recv(4096 if live_world else min(4096, remaining))
            except socket.timeout:
                continue
            if not data:
                decode_layer = "compression"
                if compression is not None:
                    compression.finish()
                decode_layer = "root-framing"
                decoder.finish()
                outcome = "peer-closed"
                break
            last_read = time.monotonic()
            retain(plaintext, data)
            decode_layer = "compression"
            chunks = compression.feed(data) if compression is not None else [data]
            decode_layer = "root-framing"
            decoded = []
            for chunk in chunks:
                retain(client_root, chunk)
                decoded.extend(decoder.feed(chunk))
            for frame in decoded:
                decode_layer = "root-framing"
                frames += 1
                # No payloads, strings, account identifiers or tokens in public logs.
                metadata = frame_metadata(frame)
                if frames <= 512:
                    print(f"TCTD_BACKEND_FRAME connection={identifier} sequence={frames} {metadata}", flush=True)
                if channels is not None:
                    decode_layer = "channel-message"
                    event = channels.handle(frame)
                    reply = b"".join(encode_transport_frame(item) for item in event.responses)
                    if reply:
                        tls.sendall(encode_wire(reply))
                        retain(outbound, reply)
                        responses += len(event.responses)
                    if frames <= 512:
                        print(f"TCTD_BACKEND_CHANNEL connection={identifier} stage={event.stage} "
                              f"channel={event.channel} request_id={event.request_id} replies={len(event.responses)}", flush=True)
                    if auth is not None and event.stage == "channel-closed":
                        auth.close(event.channel)
                        if profiles is not None:
                            profiles.close(event.channel)
                            server_list.close(event.channel)
                    for inner in event.inner_frames:
                        inner_count += 1
                        auth_event = None
                        response_type = 'none'
                        if auth is not None:
                            auth_event = auth.handle(event.channel, channels.channels[event.channel].registration, inner)
                            response_type = '0x0003' if auth_event.response else 'none'
                            if profiles is not None and auth_event.stage == 'unbound-observe-only':
                                registration = channels.channels[event.channel].registration
                                if (inner.type_id == 5 and registration.name == b'profile_client'
                                        and registration.target in profiles.targets and create_observed < 128):
                                    create_observed += 1
                                    capture_create_request(config.capture_dir, identifier, event.channel,
                                                           create_observed, inner.body)
                                auth_event = profiles.handle(event.channel, channels.channels[event.channel].registration, inner)
                                log_profile_failure(identifier, event.channel, inner, auth_event)
                                response_type = f'0x{auth_event.response_type:04x}' if auth_event.response else 'none'
                            if server_list is not None and auth_event.stage == 'unbound-observe-only':
                                if (config.agent_response is not None and inner.type_id == 0x000c
                                        and event.channel not in agent_observed
                                        and registration.target in server_list.instances):
                                    agent_observed.add(event.channel)
                                    capture_agent_request(config.capture_dir, identifier,
                                                          event.channel, inner.body)
                                auth_event = server_list.handle(event.channel, channels.channels[event.channel].registration, inner)
                                if (config.cover_completion is not None and inner.type_id == 0x0014
                                        and registration.target in server_list.instances
                                        and event.channel in server_list.agent_sent
                                        and cover_observed < 64):
                                    cover_observed += 1
                                    capture_cover_candidate(config.capture_dir, identifier,
                                        event.channel, cover_observed, inner.body, auth_event.stage)
                                response_type = (','.join(f'0x{t:04x}' for t in
                                    (auth_event.response_types or (auth_event.response_type,)))
                                    if auth_event.response else 'none')
                            if auth_event.response is not None:
                                reply = encode_transport_frame(auth_event.response)
                                tls.sendall(encode_wire(reply))
                                retain(outbound, reply)
                                responses += 1
                                if ('tutorial-activated' in auth_event.stage and
                                        inner.type_id == 0x000c and
                                        0x00e6 in (auth_event.response_types or ())):
                                    # Uncapped: this handoff commonly occurs after the
                                    # ordinary per-message logging limit. A successful
                                    # sendall is only a transport milestone, not proof
                                    # that the client decoded or retained the activity.
                                    print(f'TCTD_TUTORIAL_SEND connection={identifier} '
                                          f'channel={event.channel} trigger=0x000c '
                                          f'activity=0x00e6 wire_bytes={len(reply)} '
                                          'result=sendall-returned client_acceptance=unconfirmed',
                                          flush=True)
                                    if config.first_objective is not None:
                                        print(f'TCTD_FIRST_OBJECTIVE_SEND connection={identifier} '
                                              f'channel={event.channel} frames=0x014d,0x00e6,0x0102 '
                                              'state=row1-active result=sendall-returned '
                                              'client_acceptance=unconfirmed', flush=True)
                                if auth_event.stage == 'instance-experimental-cover-completion-sent':
                                    sent = ','.join(f'0x{item:04x}' for item in
                                                    auth_event.response_types or ())
                                    print(f'TCTD_COVER_COMPLETION_SEND connection={identifier} '
                                          f'channel={event.channel} trigger=validated-0x0014 '
                                          f'frames={sent} state=row1-complete-row2-active '
                                          'result=sendall-returned client_acceptance=unconfirmed', flush=True)
                                if auth_event.stage in ('instance-experimental-shot-echo-sent',
                                                        'instance-experimental-shooting-stage-sent',
                                                        'instance-experimental-switch-stage-sent',
                                                        'instance-experimental-final-shot-stage-sent'):
                                    sent = ','.join(f'0x{item:04x}' for item in
                                                    auth_event.response_types or ())
                                    print(f'TCTD_STAGE_PROGRESSION_SEND connection={identifier} '
                                          f'channel={event.channel} trigger=0x{inner.type_id:04x} '
                                          f'stage={auth_event.stage} frames={sent} '
                                          'result=sendall-returned client_acceptance=unconfirmed', flush=True)
                                    if auth_event.stage == 'instance-experimental-shooting-stage-sent':
                                        # One-way diagnostic signal for the opt-in local
                                        # gate experiment. It carries no profile or wire data.
                                        try:
                                            (config.capture_dir / 'weapon-gate-shooting-stage.ready').touch(
                                                mode=0o600, exist_ok=True)
                                        except OSError:
                                            print('TCTD_WEAPON_GATE_MARKER write-failed', flush=True)
                        if inner_count <= 512:
                            print(f"TCTD_BACKEND_INNER connection={identifier} channel={event.channel} "
                                  f"service={'local-instance' if auth_event and auth_event.stage.startswith('instance-') else public_service_name(channels.channels[event.channel].registration)} "
                                  f"sequence={inner_count} type=0x{inner.type_id:04x} body_bytes={len(inner.body)} "
                                  f"stage={auth_event.stage if auth_event else 'observe-only'} "
                                  f"response={response_type} "
                                  "client_session_acceptance=unconfirmed", flush=True)
                        if (auth_event is not None and auth_event.stage == 'instance-world-message-unimplemented'
                                and inner.type_id not in world_observed and len(world_observed) < 64):
                            world_observed.add(inner.type_id)
                            print(f'TCTD_WORLD_UNIMPLEMENTED connection={identifier} channel={event.channel} '
                                  f'type=0x{inner.type_id:04x} body_bytes={len(inner.body)} '
                                  'action=observe-only', flush=True)
            if decoded:
                stage = "root-frames-received"
        else:
            outcome = "stopped"
    except DecodeError:
        outcome = f"invalid-{decode_layer}"
    except ValueError:
        outcome = 'response-construction-failed'
    except socket.timeout:
        outcome = "handshake-timeout"
    except ssl.SSLError as error:
        outcome = "tls-error"
        print(f"TCTD_BACKEND_TLS_ERROR connection={identifier} stage={stage} "
              f"{TLS['describe_ssl_error'](error)}", flush=True)
    except OSError as error:
        outcome = f"io-error-{error.errno}"
    finally:
        (tls if tls is not None else client).close()
        if plaintext:
            TLS["private_write"](config.capture_dir / f"backend-{identifier:04d}-plaintext.bin", bytes(plaintext))
        if client_root:
            TLS["private_write"](config.capture_dir / f"backend-{identifier:04d}-client-root.bin", bytes(client_root))
        if outbound:
            TLS["private_write"](config.capture_dir / f"backend-{identifier:04d}-server-root.bin", bytes(outbound))
        print(f"TCTD_BACKEND_SUMMARY connection={identifier} stage={stage} outcome={outcome} "
              f"client_bytes={len(plaintext)} frames={frames} pending_bytes={decoder.pending_bytes} "
              f"compression_blocks={compression.blocks if compression is not None else 0} "
              f"decoded_bytes={compression.decoded_bytes if compression is not None else len(plaintext)} "
              f"compressed_pending_bytes={compression.pending_bytes if compression is not None else 0} "
              f"application_responses={responses} inner_frames={inner_count} "
              f"login={'experimental-reply-only' if auth else 'not-implemented'} "
              f"world={'experimental-template-no-simulation' if config.world_template else 'not-implemented'}", flush=True)


def handle_latency(identifier, client, capture_dir, stop, timeout=10.0):
    """The sibling plain-TCP endpoint; no TLS preface, identity or upstream."""
    decoder = TransportStreamDecoder(maximum_frame_bytes=64)
    session = LatencySession()
    plaintext = bytearray()
    outcome = "unknown"
    started = time.monotonic()
    try:
        client.settimeout(0.5)
        client.sendall(latency_greeting())
        print(f"TCTD_LATENCY_GREETING connection={identifier} protocol_version=556 interval=200", flush=True)
        while not stop.is_set() and not session.complete:
            if time.monotonic() - started >= timeout:
                outcome = "timeout"
                break
            remaining = 4096 - len(plaintext)
            if remaining <= 0:
                outcome = "capture-limit"
                break
            try:
                data = client.recv(min(64, remaining))
            except socket.timeout:
                continue
            if not data:
                outcome = "peer-closed"
                break
            plaintext.extend(data)
            for frame in decoder.feed(data):
                response = session.handle(frame)
                if response is not None:
                    client.sendall(encode_transport_frame(response))
                    print(f"TCTD_LATENCY_PONG connection={identifier} sequence={session.next_sequence - 1}", flush=True)
        else:
            outcome = "complete" if session.complete else "stopped"
        if session.complete:
            decoder.finish()
    except DecodeError:
        outcome = "invalid-latency-framing"
    except OSError as error:
        outcome = f"io-error-{error.errno}"
    finally:
        client.close()
        if plaintext:
            TLS["private_write"](capture_dir / f"latency-{identifier:04d}-plaintext.bin", bytes(plaintext))
        print(f"TCTD_LATENCY_SUMMARY connection={identifier} outcome={outcome} "
              f"pings={session.next_sequence} client_bytes={len(plaintext)} pending_bytes={decoder.pending_bytes}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cert", "key", "capture-dir", "server-preface", "expected-client-preface"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--port", type=int, default=55001)
    parser.add_argument("--protocol-version", type=int, default=2056)
    parser.add_argument("--channel-setup", action="store_true",
                        help="send candidate settings and handle registration/heartbeat messages")
    parser.add_argument("--service-advertisements", action="store_true",
                        help="send local type-5 service metadata after settings (requires --channel-setup)")
    parser.add_argument("--experimental-auth", action="store_true",
                        help="validate local SDK tickets and send an unproven synthetic type-3 login reply")
    parser.add_argument("--experimental-profiles", action="store_true",
                        help="serve local profile lifecycle, normal discovery and instance admission observation (not world state)")
    parser.add_argument("--profile-store", type=Path,
                        default=PROJECT / "private/local-profiles/characters.sqlite3",
                        help="persistent local character database; used only with --experimental-profiles")
    parser.add_argument('--experimental-world-template', type=Path,
                        help='PRIVATE typed capture-derived startup experiment; no ongoing simulation')
    parser.add_argument('--experimental-world-continuation', type=Path,
                        help='PRIVATE capture-derived first-gate burst after character handoff')
    parser.add_argument('--experimental-agent-response', type=Path,
                        help='PRIVATE capture-derived one-shot response to local tutorial agent submission')
    parser.add_argument('--experimental-character-template', type=Path,
                        help='PRIVATE normalized capture-derived profile presentation nodes')
    parser.add_argument('--experimental-tutorial-activation', type=Path,
                        help='PRIVATE one-shot first-activity activation; no progression')
    parser.add_argument('--experimental-first-objective', type=Path,
                        help='PRIVATE one-shot first-objective display test; no progression')
    parser.add_argument('--experimental-cover-completion', type=Path,
                        help='PRIVATE gated first-cover completion test; no later progression')
    parser.add_argument('--experimental-stage-progression', type=Path,
                        help='PRIVATE bounded shooting/switch tutorial transitions; no completion')
    parser.add_argument('--experimental-next-activity', type=Path,
                        help='PRIVATE capture-derived first-close and safe-house activity handoff')
    parser.add_argument('--experimental-dialogue-015a', type=Path,
                        help='PRIVATE pinned post-handoff 0x015a dialogue candidate; opt-in test only')
    parser.add_argument("--latency-port", type=int,
                        help="also serve the known protocol-556 latency exchange on loopback")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0 <= args.protocol_version < 1 << 32:
        parser.error("invalid port or protocol version")
    if args.latency_port is not None and (not 1 <= args.latency_port <= 65535 or args.latency_port == args.port):
        parser.error("latency port must be valid and distinct from the TLS port")
    if args.channel_setup and args.protocol_version != 2056:
        parser.error("channel setup is only implemented for candidate protocol 2056")
    if args.service_advertisements and not args.channel_setup:
        parser.error("service advertisements require --channel-setup")
    if args.experimental_auth and not args.service_advertisements:
        parser.error("experimental auth requires --service-advertisements")
    if args.experimental_profiles and not args.experimental_auth:
        parser.error("experimental profiles require --experimental-auth")
    if args.experimental_world_template and not args.experimental_profiles:
        parser.error('experimental world template requires --experimental-profiles')
    if args.experimental_world_continuation and not args.experimental_world_template:
        parser.error('experimental world continuation requires --experimental-world-template')
    if args.experimental_agent_response and not args.experimental_world_continuation:
        parser.error('experimental agent response requires --experimental-world-continuation')
    if args.experimental_character_template and not args.experimental_agent_response:
        parser.error('experimental character template requires --experimental-agent-response')
    if args.experimental_tutorial_activation and not args.experimental_character_template:
        parser.error('experimental tutorial activation requires --experimental-character-template')
    if args.experimental_first_objective and not args.experimental_tutorial_activation:
        parser.error('experimental first objective requires --experimental-tutorial-activation')
    if args.experimental_cover_completion and not args.experimental_first_objective:
        parser.error('experimental cover completion requires --experimental-first-objective')
    if args.experimental_stage_progression and not args.experimental_cover_completion:
        parser.error('experimental stage progression requires --experimental-cover-completion')
    if args.experimental_next_activity and not args.experimental_stage_progression:
        parser.error('experimental next activity requires --experimental-stage-progression')
    if args.experimental_dialogue_015a and not args.experimental_next_activity:
        parser.error('experimental dialogue candidate requires --experimental-next-activity')
    try:
        world_template = read_template(args.experimental_world_template) if args.experimental_world_template else None
    except (OSError, ValueError):
        parser.error('invalid or unreadable private experimental world template')
    try:
        world_continuation = (read_continuation(args.experimental_world_continuation)
                              if args.experimental_world_continuation else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental world continuation')
    try:
        agent_response = (read_agent_response(args.experimental_agent_response)
                          if args.experimental_agent_response else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental agent response')
    try:
        character_template = (read_character_template(args.experimental_character_template)
                              if args.experimental_character_template else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental character template')
    try:
        tutorial_activation = (read_tutorial_activation(args.experimental_tutorial_activation)
                               if args.experimental_tutorial_activation else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental tutorial activation')
    try:
        first_objective = (read_first_objective(args.experimental_first_objective)
                           if args.experimental_first_objective else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental first-objective artifact')
    try:
        cover_completion = (read_cover_completion(args.experimental_cover_completion)
                            if args.experimental_cover_completion else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental cover-completion artifact')
    try:
        stage_progression = (read_stage_progression(args.experimental_stage_progression)
                             if args.experimental_stage_progression else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental stage-progression artifact')
    try:
        next_activity = (read_next_activity(args.experimental_next_activity)
                         if args.experimental_next_activity else None)
    except (OSError, ValueError, DecodeError):
        parser.error('invalid or unreadable private experimental next-activity artifact')
    try:
        dialogue_015a = (read_dialogue_015a(args.experimental_dialogue_015a)
                         if args.experimental_dialogue_015a else None)
    except (OSError, ValueError):
        parser.error('invalid or unreadable private experimental dialogue candidate')
    server_preface = TLS["read_exact_file"](args.server_preface, 36, "server preface")
    client_preface = TLS["read_exact_file"](args.expected_client_preface, 8, "client preface")
    if server_preface[:4] != bytes.fromhex("46010220") or client_preface[:4] != bytes.fromhex("0e010004"):
        parser.error("unsupported preface format")
    os.umask(0o077)
    args.capture_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.capture_dir, 0o700)
    context = TLS["create_tls_context"](args.cert, args.key, args.capture_dir / "backend-tls-keylog.txt")
    config = BackendConfig(args.capture_dir, server_preface, client_preface, args.protocol_version,
                           session_timeout=None if world_template is not None else 90.0,
                           max_capture_bytes=4 * 1024 * 1024 if world_template is not None else 262144,
                           channel_setup=args.channel_setup, service_advertisements=args.service_advertisements,
                           experimental_auth=args.experimental_auth,
                           experimental_profiles=args.experimental_profiles,
                           profile_store=ProfileStore(args.profile_store) if args.experimental_profiles else None,
                           world_template=world_template, world_continuation=world_continuation,
                           agent_response=agent_response, character_template=character_template,
                           tutorial_activation=tutorial_activation, first_objective=first_objective,
                           cover_completion=cover_completion, stage_progression=stage_progression,
                           next_activity=next_activity, dialogue_015a=dialogue_015a)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    workers = []
    with ExitStack() as resources:
        selector = resources.enter_context(selectors.DefaultSelector())
        endpoints = [(args.port, "backend")]
        if args.latency_port is not None:
            endpoints.append((args.latency_port, "latency"))
        for port, role in endpoints:
            listener = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(8)
            listener.setblocking(False)
            selector.register(listener, selectors.EVENT_READ, role)
        if args.latency_port is not None:
            print(f"TCTD_LATENCY_READY address=127.0.0.1 port={args.latency_port} transport=plain-tcp protocol_version=556", flush=True)
        print(f"TCTD_BACKEND_READY address=127.0.0.1 port={args.port} "
              f"protocol_version={args.protocol_version} transport=preface-tls "
              f"trust=bootstrap-ca mode={'channel-setup' if args.channel_setup else 'transport-only'}", flush=True)
        if world_template is not None:
            print('TCTD_WORLD_EXPERIMENT_READY source=typed-capture-derived '
                  'known_identities=local unknown_fields=retained simulation=none '
                  'session_limit=none', flush=True)
        if world_continuation is not None:
            print(f'TCTD_WORLD_CONTINUATION_READY source=private-first-gate '
                  f'frames={len(world_continuation.frames)} known_identities=local '
                  'unknown_fields=capture-derived simulation=none', flush=True)
        if agent_response is not None:
            print(f'TCTD_AGENT_RESPONSE_READY source=private-tutorial-window '
                  f'dictionary_updates={len(agent_response.dictionary_prelude)} '
                  f'response_frames={len(agent_response.response_frames)} '
                  'request_identity=local unknown_fields=capture-derived simulation=none', flush=True)
        if character_template is not None:
            print('TCTD_PROFILE_FINALIZATION_READY source=normalized-private-nodes '
                  'appearance=client-submission persistence=local-sqlite '
                  'world_progress=none', flush=True)
        if tutorial_activation is not None:
            print('TCTD_TUTORIAL_ACTIVATION_READY source=private-first-activity '
                  'trigger=authenticated-agent-submission progression=none', flush=True)
        if first_objective is not None:
            print('TCTD_FIRST_OBJECTIVE_TEST_READY source=private-first-active-row '
                  'trigger=one-shot-after-activation progression=none', flush=True)
        if cover_completion is not None:
            print('TCTD_COVER_COMPLETION_TEST_READY source=private-first-cover-transition '
                  'trigger=bounded-0x0014 row1=complete row2=active', flush=True)
        if stage_progression is not None:
            print('TCTD_STAGE_PROGRESSION_TEST_READY source=private-retail-transitions '
                  'triggers=bounded-0x006a-0x0088 final_completion=none rewards=none', flush=True)
        if next_activity is not None:
            print('TCTD_NEXT_ACTIVITY_TEST_READY source=private-retail-handoff '
                  'trigger=first-activity-close side_missions=not-implemented', flush=True)
        if dialogue_015a is not None:
            print('TCTD_DIALOGUE_015A_TEST_READY source=pinned-private-retail-frame '
                  'trigger=after-safe-house-start meaning=unconfirmed', flush=True)
        sequence = 0
        while not stop.is_set():
            for key, _ in selector.select(0.5):
                try:
                    client, _ = key.fileobj.accept()
                except BlockingIOError:
                    continue
                workers = [worker for worker in workers if worker.is_alive()]
                if len(workers) >= 8 or sequence >= 64:
                    client.close()
                    continue
                sequence += 1
                if key.data == "latency":
                    worker = threading.Thread(target=handle_latency,
                        args=(sequence, client, args.capture_dir, stop))
                else:
                    worker = threading.Thread(target=handle_connection,
                        args=(sequence, client, context, config, stop))
                worker.start()
                workers.append(worker)
    stop.set()
    for worker in workers:
        worker.join(timeout=6)
    if config.profile_store is not None and not any(worker.is_alive() for worker in workers):
        config.profile_store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
