"""Experimental auth-channel reply, not a character/world session server.

Only the local SDK can validate the presented ticket. The type-3 layout is
known, but locally synthesized opaque blobs/identity semantics are unproven.
"""
from dataclasses import dataclass
import hashlib
import http.client
import json
import math
import re
import secrets
import time
import uuid

from isac_protocol.codec import Cursor, DecodeError, encode_uvarint
from isac_protocol.control_messages import (
    ControlIdentity, Type0003, Type0003Bundle, Type0003TimedBlob, encode_type0003, decode_type0003,
)
from isac_protocol.framing import MessageFrame, encode_length_prefixed_frame
from isac_protocol.transport import TransportFrame
from .services import local_service_advertisements

INTERNAL_AUTH_PATH = "/isac/internal/validate-ticket"
LOCAL_TICKET = re.compile(rb"isac-local-[0-9a-f]{64}")


@dataclass(frozen=True)
class LocalSession:
    session_id: str
    profile_id: str
    display_name: str
    expires_at: float

    def __post_init__(self):
        uuid.UUID(self.session_id)
        uuid.UUID(self.profile_id)
        if not 1 <= len(self.display_name.encode("utf-8")) <= 63 or "\0" in self.display_name:
            raise ValueError("invalid local display name")
        if not math.isfinite(self.expires_at):
            raise ValueError("invalid local session expiry")


def validate_with_sdk(ticket: bytes, *, port=55003) -> LocalSession | None:
    """Fixed numeric loopback, no redirects/proxies or external URL input."""
    if not LOCAL_TICKET.fullmatch(ticket):
        return None
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("POST", INTERNAL_AUTH_PATH,
                           json.dumps({"ticket": ticket.decode("ascii")}),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            return None
        body = response.read(2049)
        if len(body) > 2048:
            return None
        document = json.loads(body)
        return LocalSession(document["session_id"], document["profile_id"],
                            document["display_name"], float(document["expires_at"]))
    except (OSError, http.client.HTTPException, ValueError, KeyError, TypeError, AttributeError):
        return None
    finally:
        connection.close()


def decode_local_auth_request(body: bytes) -> bytes:
    # Findings-108: 90-byte request = varint(75), SDK ticket, opaque 14-byte
    # tail. Refuse other shapes; don't infer fields from the old 3328-byte
    # retail request or treat its leading string length as a request ID.
    if len(body) != 90:
        raise DecodeError("unsupported local auth request shape")
    cursor = Cursor(body)
    ticket = cursor.read_length_prefixed_bytes(maximum_length=75)
    if not LOCAL_TICKET.fullmatch(ticket) or cursor.remaining != 14:
        raise DecodeError("unsupported local auth credential shape")
    return ticket


def experimental_login_response(session: LocalSession, now: float) -> MessageFrame:
    ttl = min(8640, int(session.expires_at - now))
    if ttl <= 0:
        raise ValueError("expired local session")
    def blob(size):
        # Shape-only local placeholders, NOT retail tokens or verified token
        # formats. Never claim these grant an accepted game session.
        value = ("isac-experimental-" + secrets.token_urlsafe(size)).encode("ascii")[:size]
        return Type0003TimedBlob(value, ttl)
    reply = Type0003(
        byte_0=0, timed_blob_0=blob(240), timed_blob_1=blob(240),
        identity=ControlIdentity(2, session.profile_id.encode("ascii")),
        bytes_0=session.display_name.encode("utf-8"), bool_0=False, bool_1=True, bool_2=True,
        # Observed flag pattern; no invented entitlement/locale bundle entries.
        bundle=Type0003Bundle(True, True, True, True, False, False, True, ()),
        timed_blob_2=blob(272),
    )
    return MessageFrame(3, encode_type0003(reply, None))


@dataclass(frozen=True)
class AuthEvent:
    stage: str
    response: TransportFrame | None = None


class AuthSession:
    """Per-transport state; route by registration target, never channel number."""
    def __init__(self, validator=validate_with_sdk, clock=time.time):
        self.validator, self.clock = validator, clock
        self.auth_targets = {r.name for r in local_service_advertisements()
                             if (b"type", b"auth") in r.attributes}
        self.sent: dict[int, tuple[bytes, LocalSession]] = {}
        # Issued service tokens outlive the auth channel, but not this transport.
        # Keep only fingerprints; retain SDK ticket privately for revocation checks.
        self.service_tokens: dict[bytes, tuple[bytes, LocalSession, float]] = {}
        self.attempts = 0

    def resolve_service_token(self, token: bytes) -> LocalSession | None:
        issued = self.service_tokens.get(hashlib.sha256(token).digest())
        if issued is None:
            return None
        ticket, owner, expires = issued
        if self.clock() >= expires:
            return None
        current = self.validator(ticket)
        return current if current == owner and current.expires_at > self.clock() else None

    def service_token_deadline(self, token: bytes) -> float | None:
        """Issued deadline only; callers must independently revalidate owner."""
        issued = self.service_tokens.get(hashlib.sha256(token).digest())
        return issued[2] if issued is not None else None

    def close(self, channel):
        self.sent.pop(channel, None)

    def handle(self, channel, registration, frame) -> AuthEvent:
        if registration.name != b"auth" or registration.target not in self.auth_targets:
            return AuthEvent("unbound-observe-only")
        if frame.type_id != 2:
            return AuthEvent("auth-unknown-message")
        self.attempts += 1
        if self.attempts > 8:
            return AuthEvent("auth-attempt-limit")
        try:
            ticket = decode_local_auth_request(frame.body)
        except DecodeError:
            return AuthEvent("auth-unsupported-request")
        session = self.validator(ticket)
        now = self.clock()
        if session is None or session.expires_at - now < 1:
            return AuthEvent("auth-ticket-rejected")
        fingerprint = hashlib.sha256(frame.body).digest()
        if channel in self.sent:
            prior, owner = self.sent[channel]
            return AuthEvent("auth-duplicate-ignored" if prior == fingerprint and owner == session
                             else "auth-conflicting-request")
        response = experimental_login_response(session, now)
        issued = decode_type0003(response.body, None).timed_blob_0
        self.service_tokens[hashlib.sha256(issued.bytes_0).digest()] = (
            ticket, session, min(session.expires_at, now + issued.uint64_0))
        payload = encode_length_prefixed_frame(response)
        self.sent[channel] = (fingerprint, session)
        return AuthEvent("auth-experimental-reply-sent", TransportFrame(False, 3,
            encode_uvarint(channel, maximum_bits=32) + encode_uvarint(len(payload), maximum_bits=32) + payload))
