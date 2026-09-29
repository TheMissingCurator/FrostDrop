"""Authenticated local discovery and instance connection admission.

This creates a transport-local route and acknowledges a valid game connection.
An explicitly supplied experimental template also sends a typed startup batch.
Neither path implements ongoing gameplay simulation.
"""
from dataclasses import dataclass, field
import hashlib
import secrets
import sqlite3
import time
import uuid

from isac_protocol.agent_submission import decode_agent_submission
from isac_protocol.codec import DecodeError, ReferenceTable, encode_uvarint
from isac_protocol.framing import MessageFrame, encode_length_prefixed_frame
from isac_protocol.world_messages import decode_type014d
from isac_protocol.world_start import decode_world_start
from isac_protocol.server_list import (decode_server_list_connect,
    decode_normal_join_request, encode_join_reply, JoinReply, decode_instance_connect)
from isac_protocol.transport import TransportFrame
from isac_protocol.game_connect import GameConnectReply, encode_game_connect_reply
from .profiles import ProfileEvent, profile_failure
from .profile_store import START_ZONE
from .services import local_service_advertisements
from .world_tutorial_stages import parse_final_shot_header


@dataclass(frozen=True)
class LocalInstance:
    name: bytes
    character_token: bytes = field(repr=False)
    service_token: bytes = field(repr=False)
    character: object = field(repr=False)
    expires_at: float
    fingerprint: bytes = field(repr=False)
    connection_identifier: bytes = field(default_factory=lambda: uuid.uuid4().bytes, repr=False)


def _reply(channel, type_id, body, stage):
    payload = encode_length_prefixed_frame(MessageFrame(type_id, body))
    return ProfileEvent(stage, TransportFrame(False, 3,
        encode_uvarint(channel, maximum_bits=32)
        + encode_uvarint(len(payload), maximum_bits=32) + payload), type_id)


class ServerListSession:
    def __init__(self, auth, profiles, world_template=None, world_continuation=None,
                 agent_response=None, character_template=None, tutorial_activation=None,
                 first_objective=None, cover_completion=None, stage_progression=None,
                 next_activity=None, dialogue_015a=None, clock=time.monotonic):
        self.auth, self.profiles = auth, profiles
        self.targets = {r.name for r in local_service_advertisements()
                        if (b'type', b'server_list') in r.attributes}
        self.connections, self.requests, self.instances = {}, {}, {}
        self.admissions = {}
        self.world_template = world_template
        if world_continuation is not None and world_template is None:
            raise ValueError('world continuation requires world startup')
        self.world_continuation = world_continuation
        self.continuation_sent = set()
        if agent_response is not None and world_continuation is None:
            raise ValueError('agent response requires world continuation')
        self.agent_response = agent_response
        if character_template is not None and agent_response is None:
            raise ValueError('character finalization requires agent response')
        self.character_template = character_template
        if tutorial_activation is not None and character_template is None:
            raise ValueError('tutorial activation requires character finalization')
        self.tutorial_activation = tutorial_activation
        if first_objective is not None and tutorial_activation is None:
            raise ValueError('first-objective test requires tutorial activation')
        self.first_objective = first_objective
        if cover_completion is not None and first_objective is None:
            raise ValueError('cover-completion test requires first objective')
        self.cover_completion = cover_completion
        if stage_progression is not None and cover_completion is None:
            raise ValueError('stage-progression test requires cover completion')
        self.stage_progression = stage_progression
        if next_activity is not None and stage_progression is None:
            raise ValueError('next activity requires stage progression')
        self.next_activity = next_activity
        if dialogue_015a is not None and (next_activity is None or len(dialogue_015a) != 35):
            raise ValueError('dialogue candidate requires next activity and 35-byte body')
        self.dialogue_015a = dialogue_015a
        self.clock = clock
        self.agent_sent = set()
        self.cover_sent = set()
        self.shooting_sent = set()
        self.switch_sent = set()
        self.final_sent = set()
        self.pending_close = {}
        self.pending_next = {}
        self.pending_dialogue = {}
        self.shot_sequences = {}
        self.shot_frames = {}
        self.switch_frames = {}
        self.cover_requests = {}
        # Construct once per route, reuse on reconnect; no simulation/persistence.
        self.world_batches = {}
        self.attempts = 0

    def close(self, channel):
        self.connections.pop(channel, None)
        self.requests.pop(channel, None)
        self.admissions.pop(channel, None)
        self.continuation_sent.discard(channel)
        self.agent_sent.discard(channel)
        self.cover_sent.discard(channel)
        self.shooting_sent.discard(channel)
        self.switch_sent.discard(channel)
        self.final_sent.discard(channel)
        self.pending_close.pop(channel, None)
        self.pending_next.pop(channel, None)
        self.pending_dialogue.pop(channel, None)
        self.shot_sequences.pop(channel, None)
        self.shot_frames.pop(channel, None)
        self.switch_frames.pop(channel, None)
        self.cover_requests.pop(channel, None)
        # A discovery channel can close before instance admission. Routes
        # therefore live until bearer/parent expiration, not channel close.

    def _valid(self, instance):
        return (self.auth.clock() < instance.expires_at
                and self.profiles.resolve_character_token(instance.character_token) == instance.character
                and self.auth.resolve_service_token(instance.service_token) == instance.character.owner)

    def poll_due(self):
        """Return one-shot capture-derived tutorial closes ready for sending."""
        ready = []
        now = self.clock()
        for pending, stage in ((self.pending_close, 'instance-experimental-activity-close-sent'),
                               (self.pending_next, 'instance-experimental-next-activity-sent'),
                               (self.pending_dialogue, 'instance-experimental-dialogue-015a-sent')):
            for channel, (deadline, instance, frames) in tuple(pending.items()):
                if channel not in self.admissions or not self._valid(instance):
                    del pending[channel]
                elif now >= deadline:
                    del pending[channel]
                    payload = b''.join(encode_length_prefixed_frame(frame) for frame in frames)
                    ready.append(ProfileEvent(stage,
                        TransportFrame(False, 3, encode_uvarint(channel, maximum_bits=32)
                            + encode_uvarint(len(payload), maximum_bits=32) + payload),
                        frames[0].type_id, tuple(frame.type_id for frame in frames)))
        return tuple(ready)

    def handle(self, channel, registration, frame):
        instance = self.instances.get(registration.target)
        if instance is not None:
            return self._admit(channel, instance, frame)
        if registration.name != b'server_list' or registration.target not in self.targets:
            return ProfileEvent('unbound-observe-only')
        self.attempts += 1
        if self.attempts > 128:
            return ProfileEvent('server-list-attempt-limit')
        if frame.type_id == 0:
            try:
                token, lifetime = decode_server_list_connect(frame.body)
            except DecodeError:
                return ProfileEvent('server-list-invalid-connect')
            if self.auth.resolve_service_token(token) is None:
                return ProfileEvent('server-list-token-rejected')
            previous = self.connections.get(channel)
            if previous is not None:
                return ProfileEvent('server-list-duplicate-connect-ignored' if previous == token
                                    else 'server-list-conflicting-connect')
            self.connections[channel] = token
            # Reader 0x2258ff0, consumer 0x8facf: ping-difference limit,
            # NOT a success/status enum. 1000ms is local policy, not retail data.
            return _reply(channel, 1, encode_uvarint(1000, maximum_bits=32),
                          'server-list-auth-policy-reply-sent')
        if frame.type_id != 5:
            return ProfileEvent('server-list-unsupported-message')
        token = self.connections.get(channel)
        owner = self.auth.resolve_service_token(token) if token is not None else None
        if owner is None:
            return ProfileEvent('server-list-not-authenticated')
        try:
            request = decode_normal_join_request(frame.body)
        except DecodeError:
            return ProfileEvent('server-list-invalid-or-unsupported-join')
        character = self.profiles.resolve_character_token(request.token)
        if character is None or character.owner != owner:
            return ProfileEvent('server-list-character-token-rejected')
        if request.instance_type != START_ZONE:
            return ProfileEvent('server-list-unsupported-zone')
        completed = self.requests.setdefault(channel, {})
        if request.request_id in completed:
            return ProfileEvent('server-list-duplicate-ignored' if completed[request.request_id] == frame.body
                                else 'server-list-conflicting-request')
        now = self.auth.clock()
        for name, prior in list(self.instances.items()):
            if not self._valid(prior):
                del self.instances[name]
                self.world_batches.pop(name, None)
        if len(self.instances) >= 32:
            return ProfileEvent('server-list-instance-limit')
        lifetime = min(900, request.lifetime, int(character.expires_at - now),
                       int((self.auth.service_token_deadline(token) or now) - now))
        if lifetime <= 0:
            return ProfileEvent('server-list-expired-join')
        name = b'isac-instance-' + secrets.token_hex(16).encode('ascii')
        bearer = b'isac-instance-' + secrets.token_hex(32).encode('ascii')
        route = LocalInstance(name, request.token, token, character, now + lifetime,
                              hashlib.sha256(bearer).digest())
        # Proxy ID 0 matches the local directory's backend entry. The returned
        # target has a real admission handler on that transport; no new socket,
        # retail endpoint, advertisement or world-ready ACK is invented.
        body = encode_join_reply(JoinReply(request.request_id, 0, name, bearer,
                                          lifetime, 0, name, START_ZONE))
        event = _reply(channel, 6, body, 'server-list-local-instance-reply-sent')
        self.instances[name] = route
        completed[request.request_id] = frame.body
        return event

    def _admit(self, channel, instance, frame):
        if not self._valid(instance):
            return ProfileEvent('instance-parent-session-rejected')
        if self.stage_progression is not None and frame.type_id in (0x006a, 0x0088):
            if channel not in self.cover_sent:
                return ProfileEvent('instance-stage-before-cover-ignored')
            final_shot = False
            counter = None
            if frame.type_id == 0x006a:
                if channel in self.shooting_sent:
                    if channel not in self.switch_sent:
                        return ProfileEvent('instance-shooting-stage-duplicate-ignored')
                    if channel in self.final_sent:
                        return ProfileEvent('instance-final-stage-duplicate-ignored')
                    final_shot = True
                else:
                    header = self.stage_progression.shot_header(frame.body, instance.character.identifier)
                    if header is None:
                        self.shot_sequences.pop(channel, None)
                        return ProfileEvent('instance-shot-candidate-ignored')
                    item, counter = header
                    if counter == 31:
                        self.shot_sequences[channel] = (item, 30)
                    elif self.shot_sequences.get(channel) != (item, counter):
                        self.shot_sequences.pop(channel, None)
                        return ProfileEvent('instance-shot-sequence-mismatch')
                    elif counter == 30:
                        self.shot_sequences[channel] = (item, 29)
            else:
                if channel not in self.shooting_sent:
                    return ProfileEvent('instance-switch-before-shooting-ignored')
                if channel in self.switch_sent:
                    return ProfileEvent('instance-switch-stage-duplicate-ignored')
                if not self.stage_progression.matches_switch(frame.body, instance.character.identifier):
                    return ProfileEvent('instance-switch-candidate-ignored')
            startup = self.world_batches.get(instance.name)
            if startup is None:
                return ProfileEvent('instance-stage-startup-missing')
            cover_request = self.cover_requests.get(channel)
            if cover_request is None:
                return ProfileEvent('instance-stage-cover-request-missing')
            try:
                final_item = final_type = None
                if final_shot:
                    seed = ReferenceTable()
                    decode_type014d(startup[0].body, seed)
                    world = decode_world_start(startup[1].body, seed.clone())
                    secondary = world.core.items_4d0[self.stage_progression.unequip_item_index]
                    final_item, final_type = secondary.reference_0.value, secondary.reference_1.value
                    if parse_final_shot_header(frame.body, instance.character.identifier,
                                               final_item, final_type) is None:
                        return ProfileEvent('instance-final-shot-candidate-ignored')
                continuation = self.world_continuation.bind(instance.character, startup[0].body)
                agent_frames = self.agent_response.bind(startup[0].body, continuation)
                activation = self.tutorial_activation.bind(startup[0].body, continuation, agent_frames)
                first_frames = self.first_objective.bind(startup[0].body, continuation,
                                                         agent_frames, activation)
                cover_frames = self.cover_completion.bind(startup[0].body, continuation,
                    agent_frames, activation, first_frames,
                    ack_request=cover_request)
                prior = (*continuation, *agent_frames, activation, *first_frames,
                         *cover_frames, *self.shot_frames.get(channel, ()),
                         *self.switch_frames.get(channel, ()))
                if frame.type_id == 0x006a:
                    if not final_shot and len(self.shot_frames.get(channel, ())) >= 12:
                        return ProfileEvent('instance-shot-echo-limit-reached')
                    if final_shot:
                        echo = self.stage_progression.shot_echo(startup[0].body,
                            prior, frame.body, instance.character.identifier,
                            final_item=final_item, final_type=final_type)
                        finish = self.stage_progression.final_shot_reply(startup[0].body,
                            (*prior, echo))
                        frames = (echo, finish, MessageFrame(0x0102, b''))
                        if self.next_activity is not None:
                            close_frames, next_frames = self.next_activity.bind(
                                startup[0].body, (*prior, echo, finish),
                                self.stage_progression, instance.character.identifier)
                        else:
                            close = self.stage_progression.activity_close_reply(startup[0].body,
                                (*prior, echo, finish))
                            close_frames = (close, MessageFrame(0x0102, b''))
                            next_frames = ()
                    elif counter == 29:
                        shooting = self.stage_progression.shooting_reply(startup[0].body, prior)
                        echo = self.stage_progression.shot_echo(startup[0].body,
                            (*prior, *shooting), frame.body, instance.character.identifier)
                        frames = (shooting[0], echo, shooting[1])
                    else:
                        echo = self.stage_progression.shot_echo(startup[0].body,
                            prior, frame.body, instance.character.identifier)
                        frames = (echo, MessageFrame(0x0102, b''))
                else:
                    frames = self.stage_progression.switch_reply(startup[0].body,
                        startup[1].body, instance.character.identifier, frame.body,
                        prior)
                payload = b''.join(encode_length_prefixed_frame(item) for item in frames)
            except (DecodeError, ValueError):
                return ProfileEvent('instance-stage-binding-rejected')
            if len(payload) > 2048:
                return ProfileEvent('instance-stage-size-rejected')
            stage = ('instance-experimental-final-shot-stage-sent' if final_shot else
                     'instance-experimental-shooting-stage-sent' if frame.type_id == 0x006a
                     and counter == 29 else 'instance-experimental-shot-echo-sent'
                     if frame.type_id == 0x006a else 'instance-experimental-switch-stage-sent')
            event = ProfileEvent(stage, TransportFrame(False, 3,
                encode_uvarint(channel, maximum_bits=32)
                + encode_uvarint(len(payload), maximum_bits=32) + payload),
                frames[0].type_id, tuple(item.type_id for item in frames))
            if frame.type_id == 0x006a:
                self.shot_frames.setdefault(channel, []).extend(frames)
                if final_shot:
                    self.final_sent.add(channel)
                    # Retail followed its final row with an activity-close
                    # batch about one second later. Do not wait for a client
                    # request: the observed close was server-originated.
                    self.pending_close[channel] = (self.clock() + 0.95, instance, close_frames)
                    if next_frames:
                        self.pending_next[channel] = (self.clock() + 4.95, instance, next_frames)
                        if self.dialogue_015a is not None:
                            self.pending_dialogue[channel] = (self.clock() + 5.20, instance,
                                (MessageFrame(0x015a, self.dialogue_015a), MessageFrame(0x0102, b'')))
                elif counter == 29:
                    self.shooting_sent.add(channel)
                    self.shot_sequences.pop(channel, None)
            else:
                self.switch_sent.add(channel)
                self.switch_frames[channel] = frames
            return event
        if frame.type_id == 0x0014 and self.cover_completion is not None:
            if channel not in self.agent_sent:
                return ProfileEvent('instance-cover-before-agent-ignored')
            if channel in self.cover_sent:
                return ProfileEvent('instance-cover-completion-duplicate-ignored')
            if not self.cover_completion.matches(frame.body, instance.character.identifier):
                return ProfileEvent('instance-cover-candidate-ignored')
            startup = self.world_batches.get(instance.name)
            if startup is None:
                return ProfileEvent('instance-cover-startup-missing')
            try:
                continuation = self.world_continuation.bind(instance.character, startup[0].body)
                agent_frames = self.agent_response.bind(startup[0].body, continuation)
                activation = self.tutorial_activation.bind(startup[0].body, continuation, agent_frames)
                first_frames = self.first_objective.bind(startup[0].body, continuation,
                                                         agent_frames, activation)
                frames = self.cover_completion.bind(startup[0].body, continuation,
                    agent_frames, activation, first_frames,
                    ack_request=frame.body if self.stage_progression is not None else None)
                payload = b''.join(encode_length_prefixed_frame(item) for item in frames)
            except (DecodeError, ValueError):
                return ProfileEvent('instance-cover-completion-binding-rejected')
            if len(payload) > 2048:
                return ProfileEvent('instance-cover-completion-size-rejected')
            event = ProfileEvent('instance-experimental-cover-completion-sent',
                TransportFrame(False, 3, encode_uvarint(channel, maximum_bits=32)
                    + encode_uvarint(len(payload), maximum_bits=32) + payload),
                0x00e6, tuple(item.type_id for item in frames))
            self.cover_sent.add(channel)
            if self.stage_progression is not None:
                self.cover_requests[channel] = frame.body
            return event
        if frame.type_id == 9 and channel in self.admissions and self.world_continuation is not None:
            if not secrets.compare_digest(frame.body, instance.character.identifier):
                return ProfileEvent('instance-world-handoff-character-rejected')
            if channel in self.continuation_sent:
                return ProfileEvent('instance-world-handoff-duplicate-ignored')
            startup = self.world_batches.get(instance.name)
            if startup is None:
                return ProfileEvent('instance-world-handoff-startup-missing')
            try:
                frames = self.world_continuation.bind(instance.character, startup[0].body)
                payload = b''.join(encode_length_prefixed_frame(item) for item in frames)
            except (DecodeError, ValueError):
                return ProfileEvent('instance-world-handoff-binding-rejected')
            if len(payload) > 262144:
                return ProfileEvent('instance-world-handoff-size-rejected')
            event = ProfileEvent('instance-experimental-first-gate-sent',
                TransportFrame(False, 3, encode_uvarint(channel, maximum_bits=32)
                    + encode_uvarint(len(payload), maximum_bits=32) + payload),
                0x0012)
            self.continuation_sent.add(channel)
            return event
        if frame.type_id == 0x000c and channel in self.admissions and self.agent_response is not None:
            if channel not in self.continuation_sent:
                return ProfileEvent('instance-agent-before-world-handoff-rejected')
            if len(frame.body) != 147 or not secrets.compare_digest(
                    frame.body[:16], instance.character.identifier):
                return ProfileEvent('instance-agent-character-rejected')
            if channel in self.agent_sent:
                return ProfileEvent('instance-agent-duplicate-ignored')
            startup = self.world_batches.get(instance.name)
            if startup is None:
                return ProfileEvent('instance-agent-startup-missing')
            try:
                continuation = self.world_continuation.bind(instance.character, startup[0].body)
                frames = self.agent_response.bind(startup[0].body, continuation)
                if self.tutorial_activation is not None:
                    agent_frames = frames
                    activity = self.tutorial_activation.bind(
                        startup[0].body, continuation, frames)
                    # The capture's five-row update belongs to the next
                    # receive batch. Without a following 0x0102 it parses
                    # into the client's queue but is not visibly applied.
                    frames = (*frames, activity, MessageFrame(0x0102, b''))
                    if self.first_objective is not None:
                        # Deliberately separate batch; this is a display
                        # sufficiency test, not a gameplay-trigger model.
                        frames += self.first_objective.bind(
                            startup[0].body, continuation, agent_frames, activity)
                payload = b''.join(encode_length_prefixed_frame(item) for item in frames)
            except (DecodeError, ValueError):
                return ProfileEvent('instance-agent-binding-rejected')
            if len(payload) > 262144:
                return ProfileEvent('instance-agent-size-rejected')
            stage = 'instance-experimental-agent-response-sent'
            if self.character_template is not None:
                try:
                    submission = decode_agent_submission(frame.body)
                    if not secrets.compare_digest(submission.character_id, instance.character.identifier):
                        return ProfileEvent('instance-agent-character-rejected')
                    character_blob = self.character_template.bind(submission)
                    promoted = self.profiles.store.finalize(
                        instance.character.owner.profile_id, instance.character.identifier,
                        character_blob)
                except (OSError, sqlite3.Error, DecodeError, ValueError) as error:
                    return ProfileEvent('instance-agent-finalization-rejected',
                        failure=profile_failure('store-finalize', error))
                if promoted:
                    self.profiles.invalidate_lists()
                stage = ('instance-agent-profile-finalized' if promoted
                         else 'instance-agent-profile-already-finalized')
                if self.tutorial_activation is not None:
                    stage += '-tutorial-activated'
            event = ProfileEvent(stage,
                TransportFrame(False, 3, encode_uvarint(channel, maximum_bits=32)
                    + encode_uvarint(len(payload), maximum_bits=32) + payload),
                0x0012, tuple(item.type_id for item in frames))
            self.agent_sent.add(channel)
            return event
        if frame.type_id != 0:
            return ProfileEvent('instance-world-message-unimplemented' if channel in self.admissions
                                else 'instance-not-authenticated')
        try:
            tokens, extra = decode_instance_connect(frame.body)
        except DecodeError:
            return ProfileEvent('instance-invalid-connect')
        # Retail fingerprint lineage (finding 116): slots are auth blob 0,
        # discovery-issued instance bearer, auth blob 2. Authorize only the
        # second slot; do not scan/fall back to another credential position.
        token, lifetime = tokens[1]
        if not secrets.compare_digest(hashlib.sha256(token).digest(), instance.fingerprint):
            return ProfileEvent('instance-token-rejected')
        prior = self.admissions.get(channel)
        digest = hashlib.sha256(frame.body).digest()
        if prior is not None:
            return ProfileEvent('instance-duplicate-connect-ignored' if prior == digest
                                else 'instance-conflicting-connect')
        # Auth-blob lineage is known, but those two presented blobs are not
        # independently validated here. Parent auth/character validity is
        # checked above. Reader 0x22556c0 and consumer 0x9e690 establish
        # false = connection accepted, not world ready. The 16-byte field is
        # locally generated per route, never copied from a retail capture or
        # equated with the character ID. Its wider semantics remain unknown.
        body = encode_game_connect_reply(GameConnectReply(instance.connection_identifier, False))
        if self.world_template is None:
            event = _reply(channel, 2, body, 'instance-connect-reply-sent-world-pending')
        else:
            batch = self.world_batches.get(instance.name)
            if batch is None:
                batch = self.world_template.startup_frames(instance.character)
            # Flush connection acceptance, then seed and flush the startup.
            # All serialization succeeds before admission/batch state commits.
            frames = (MessageFrame(2, body), MessageFrame(0x0102, b''), *batch)
            payload = b''.join(encode_length_prefixed_frame(item) for item in frames)
            if len(payload) > 262144:
                raise ValueError('experimental startup batch exceeds bound')
            event = ProfileEvent('instance-experimental-startup-batch-sent',
                TransportFrame(False, 3, encode_uvarint(channel, maximum_bits=32)
                    + encode_uvarint(len(payload), maximum_bits=32) + payload),
                2, tuple(item.type_id for item in frames))
            self.world_batches[instance.name] = batch
        self.admissions[channel] = digest
        return event
