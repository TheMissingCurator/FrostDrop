"""Opt-in authenticated local character listing and unfinished lifecycle."""
from dataclasses import dataclass, field
import hashlib
import secrets
import sqlite3

from isac_protocol.codec import DecodeError, encode_uvarint
from isac_protocol.framing import MessageFrame, encode_length_prefixed_frame
from isac_protocol.profile_messages import (
    ProfileList, CreateProfileReply, decode_profile_connect, decode_unfiltered_profile_list_request,
    encode_profile_list, decode_create_profile_request, encode_create_profile_reply,
    ProfileTokenReply, decode_profile_token_request, encode_profile_token_reply,
    DeleteProfileReply, decode_delete_profile_request, encode_delete_profile_reply,
)
from isac_protocol.transport import TransportFrame
from .services import local_service_advertisements
from .profile_store import ProfileStore, START_ZONE
from .auth import LocalSession


@dataclass(frozen=True)
class ProfileFailure:
    operation: str
    reason: str
    sqlite_code: int | None = None
    os_errno: int | None = None


def profile_failure(operation, error):
    """Allowlisted categories only: never expose exception text or identities."""
    if isinstance(error, sqlite3.Error):
        code = getattr(error, 'sqlite_errorcode', None)
        return ProfileFailure(operation, 'sqlite-error', code if type(code) is int else None)
    if isinstance(error, OSError):
        return ProfileFailure(operation, 'os-error', os_errno=error.errno)
    reason = {
        'unsupported local creation mode': 'unsupported-create-flags',
        'conflicting unfinished character mode': 'conflicting-stored-create-flags',
        'invalid unfinished character store entry': 'invalid-stored-character',
        'invalid character store entry': 'invalid-stored-character',
        'invalid customized character store entry': 'invalid-stored-character',
        'completed character already occupies local slot': 'completed-slot-occupied',
        'character not owned by local account': 'character-not-owned',
        'conflicting finalized character record': 'conflicting-finalization',
        'invalid finalized character record': 'invalid-finalization',
        'unsupported unfinished character deletion mode': 'unsupported-delete-mode',
        'unfinished character was not removed from the active slot': 'archive-row-count',
    }.get(str(error), 'value-validation-error')
    return ProfileFailure(operation, reason)


@dataclass(frozen=True)
class ProfileEvent:
    stage: str
    response: TransportFrame | None = None
    response_type: int | None = None
    response_types: tuple[int, ...] = ()
    failure: ProfileFailure | None = None


@dataclass(frozen=True)
class CharacterSession:
    owner: LocalSession = field(repr=False)
    identifier: bytes
    expires_at: float
    auth_token: bytes = field(repr=False)


class ProfileSession:
    def __init__(self, auth, store=None):
        self.auth = auth
        self.store = store if store is not None else ProfileStore()
        self.targets = {r.name for r in local_service_advertisements()
                        if (b"type", b"profile_client") in r.attributes}
        self.connections = {}
        self.requests = {}
        self.attempts = 0
        # Ephemeral character bearers, NOT credentials persisted in the store.
        # Fingerprint keys prevent accidental public token logging. They
        # outlive profile-channel close but are confined to this transport.
        self.character_sessions = {}

    def close(self, channel):
        self.connections.pop(channel, None)
        self.requests.pop(channel, None)

    def invalidate_lists(self):
        """A committed world-channel finalization changes subsequent lists."""
        for requests in self.requests.values():
            for key in list(requests):
                if key[0] == 1:
                    del requests[key]

    def resolve_character_token(self, token):
        session = self.character_sessions.get(hashlib.sha256(token).digest())
        if session is None or self.auth.clock() >= session.expires_at:
            return None
        if self.auth.resolve_service_token(session.auth_token) != session.owner:
            return None
        try:
            entries = self.store.list(session.owner.profile_id)
        except (OSError, sqlite3.Error, ValueError):
            return None
        return session if any(p.identifier == session.identifier for p in entries) else None

    def handle(self, channel, registration, frame):
        if registration.name != b"profile_client" or registration.target not in self.targets:
            return ProfileEvent("unbound-observe-only")
        self.attempts += 1
        if self.attempts > 128:
            return ProfileEvent("profile-attempt-limit")
        if frame.type_id == 0:
            try:
                token, lifetime = decode_profile_connect(frame.body)
            except DecodeError:
                return ProfileEvent("profile-invalid-connect")
            if not lifetime or self.auth.resolve_service_token(token) is None:
                return ProfileEvent("profile-token-rejected")
            previous = self.connections.get(channel)
            if previous is not None and previous != token:
                return ProfileEvent("profile-conflicting-connect")
            self.connections[channel] = token
            # No evidence of an inner connect ACK on this service. Do not invent one.
            return ProfileEvent("profile-local-token-bound")
        if frame.type_id not in (1, 3, 5, 7):
            return ProfileEvent("profile-unsupported-message")
        token = self.connections.get(channel)
        owner = self.auth.resolve_service_token(token) if token is not None else None
        if owner is None:
            return ProfileEvent("profile-not-authenticated")
        try:
            request = (decode_create_profile_request(frame.body) if frame.type_id == 5 else
                       decode_profile_token_request(frame.body) if frame.type_id == 7 else
                       decode_delete_profile_request(frame.body) if frame.type_id == 3 else None)
            request_id = request.request_id if request else decode_unfiltered_profile_list_request(frame.body)
        except DecodeError:
            return ProfileEvent({5: "profile-unsupported-create-request", 7: "profile-invalid-token-request",
                                 3: "profile-invalid-delete-request", 1: "profile-unsupported-list-request"}[frame.type_id])
        completed = self.requests.setdefault(channel, {})
        key = (frame.type_id, request_id)
        if key in completed and completed[key] != frame.body:
            return ProfileEvent("profile-conflicting-request")
        if key in completed:
            return ProfileEvent("profile-duplicate-ignored")
        operation = 'dispatch'
        try:
            if frame.type_id == 3:
                operation = 'store-archive'
                success, archived = self.store.archive_unfinished(owner.profile_id, request.identifier)
                operation = 'encode-delete-reply'
                body = encode_delete_profile_reply(DeleteProfileReply(request_id, success))
                response_type = 4
                stage = ("profile-unfinished-character-archived" if archived else
                         "profile-unfinished-character-already-archived" if success else
                         "profile-delete-not-owned")
                if archived:
                    # List/create/selection request IDs can be reused following
                    # cleanup. Keep delete duplicate/conflict guards intact.
                    for requests in self.requests.values():
                        for old in list(requests):
                            if old[0] in (1, 5, 7):
                                del requests[old]
                    for fingerprint, prior in list(self.character_sessions.items()):
                        if prior.owner.profile_id == owner.profile_id and prior.identifier == request.identifier:
                            del self.character_sessions[fingerprint]
            elif frame.type_id == 7:
                operation = 'store-list-for-token'
                entry = next((p for p in self.store.list(owner.profile_id) if p.identifier == request.identifier), None)
                if entry is None:
                    return ProfileEvent("profile-character-not-owned")
                # Strict normal unfinished-character experiment only. Broader
                # optional-group/survival/world-session semantics are unknown.
                if (entry.is_locked or entry.is_survival
                        or entry.instance_type != START_ZONE or entry.instance_name):
                    return ProfileEvent("profile-token-mode-unsupported")
                now = self.auth.clock()
                deadline = self.auth.service_token_deadline(token)
                lifetime = min(900, int(min(owner.expires_at, deadline or now) - now))
                if lifetime <= 0:
                    return ProfileEvent("profile-token-expired")
                issued = (b'isac-character-' + secrets.token_hex(32).encode('ascii'))
                operation = 'encode-token-reply'
                body = encode_profile_token_reply(ProfileTokenReply(request_id, 2, issued, lifetime,
                                                                    entry.instance_type, entry.instance_name))
                # One active bearer per account/character; a renewal retires
                # its predecessor. No unbounded registry growth on retries.
                for fingerprint, prior in list(self.character_sessions.items()):
                    if (prior.expires_at <= now or
                            (prior.owner.profile_id == owner.profile_id and prior.identifier == entry.identifier)):
                        del self.character_sessions[fingerprint]
                if len(self.character_sessions) >= 32:
                    return ProfileEvent("profile-character-session-limit")
                self.character_sessions[hashlib.sha256(issued).digest()] = CharacterSession(
                    owner, entry.identifier, now + lifetime, token)
                response_type, stage = 8, "profile-character-token-reply-sent"
            elif request:
                operation = 'store-create'
                identifier, created = self.store.create(owner.profile_id, request.flag_5, request.flag_4)
                operation = 'encode-create-reply'
                body = encode_create_profile_reply(CreateProfileReply(request_id, 0, identifier))
                response_type = 6
                stage = "profile-character-created" if created else "profile-unfinished-character-reused"
                # The client can reuse list ID 0 after creation. Invalidate
                # cached list requests across this transport's profile channels.
                for requests in self.requests.values():
                    for old in list(requests):
                        if old[0] == 1:
                            del requests[old]
            else:
                operation = 'store-list'
                entries = self.store.list(owner.profile_id)
                operation = 'encode-list-reply'
                body = encode_profile_list(ProfileList(request_id, True, False, False, 1800, START_ZONE, entries))
                response_type = 2
                stage = "profile-character-list-reply-sent" if entries else "profile-empty-list-reply-sent"
        except (OSError, sqlite3.Error, ValueError) as error:
            # Never acknowledge success before persistence or invent an error enum.
            return ProfileEvent("profile-store-or-mode-rejected", failure=profile_failure(operation, error))
        payload = encode_length_prefixed_frame(MessageFrame(response_type, body))
        completed[key] = frame.body
        return ProfileEvent(stage, TransportFrame(False, 3,
            encode_uvarint(channel, maximum_bits=32)
            + encode_uvarint(len(payload), maximum_bits=32) + payload), response_type)
