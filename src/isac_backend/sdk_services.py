"""Experimental local SDK contract from findings-072/073; never a proxy.

This models a synthetic session, not ownership verification or a saved character.
Only the loopback listener may use it. Retail parser acceptance is unverified.
"""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac
import json
import re
import secrets
import uuid
from .auth import INTERNAL_AUTH_PATH, LOCAL_TICKET, LocalSession

ACCOUNT_ID = "49534143-0000-4000-8000-000000000001"  # local.c
SPACE_ID = "49534143-0000-4000-8000-000000000002"
ORIGIN = "http://127.0.0.1:55003"
FEATURES = (
    "ApplicationUsed Connection ContentFiltering EntitiesProfile EntitiesSpace Event "
    "ExtendSession FixAccountIssues FriendsLookup FriendsRequest HttpClient Messaging "
    "News Populations Profiles ProfilesExternal PrimaryStore SecondaryStore "
    "SendPopulationsInPlayerStart SendPrimaryStoreEvent Socialfeed UplayFriends "
    "UplayLaunch UplayWinActions UplayWinChallenges UplayWinRewards Users "
    "UsersManagement WebSocketClient Everything"
).split()


def configuration():
    # Explicit switches: omission retains constructor defaults. These are SDK
    # gates, NOT a firewall. Only understood resources are supplied.
    return {
        "resources": [
            {"name": "sessions", "url": ORIGIN + "/{version}/profiles/sessions", "version": 1},
            {"name": "applications", "url": ORIGIN + "/{version}/applications/{applicationId}/configuration", "version": 1},
        ],
        "featuresSwitches": [{"name": name, "value": name in ("Everything", "HttpClient")}
                             for name in FEATURES],
        "sdkConfig": {
            "timeoutSec": 10, "ticketTTL": 10800000, "lspPort": 0,
            "popEventsTimeoutMsec": 3000, "connectionPingIntervalSec": 30,
            "httpRetry": {"maxCount": 0, "initialDelayMsec": 5000,
                          "incrementFactorMsec": 5000, "randomDelayMsec": 5000},
            "websocketRetry": {"maxCount": 0, "initialDelayMsec": 5000,
                               "incrementFactorMsec": 5000, "randomDelayMsec": 5000},
            "remoteLogs": {"ubiservicesLogLevel": 0, "prodLogLevel": 0},
        },
    }


class SDKServices:
    def __init__(self, clock=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sessions = {}

    def create_session(self):
        now = self.clock()
        self.sessions = {sid: record for sid, record in self.sessions.items() if record[1] > now}
        if len(self.sessions) >= 64:
            return None
        sid, ticket = str(uuid.uuid4()), "isac-local-" + secrets.token_hex(32)
        expiry = now + timedelta(hours=3)
        self.sessions[sid] = (ticket, expiry)
        stamp = lambda dt: dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return {
            "sessionId": sid, "token": "isac-token-" + secrets.token_hex(32),
            "ticket": ticket, "profileId": ACCOUNT_ID, "userId": ACCOUNT_ID,
            "nameOnPlatform": "ProjectISAC", "spaceId": SPACE_ID,
            "environment": "Prod", "expiration": stamp(expiry), "serverTime": stamp(now),
            "clientIp": "127.0.0.1", "initializeUser": False, "platformType": "uplay",
            "accountIssues": [], "rememberMeTicket": "", "hasAcceptedLegalOptins": True,
        }

    def authorized(self, headers):
        record = self.sessions.get(headers.get("Ubi-SessionId", ""))
        return bool(record and record[1] > self.clock() and hmac.compare_digest(
            headers.get("Authorization", "").encode("utf-8"),
            ("Ubi_v1 t=" + record[0]).encode("ascii")))

    def validate_ticket(self, ticket):
        if not isinstance(ticket, str) or not LOCAL_TICKET.fullmatch(ticket.encode("utf-8")):
            return None
        now = self.clock()
        for sid, (issued, expiry) in self.sessions.items():
            if expiry > now and hmac.compare_digest(ticket, issued):
                return LocalSession(sid, ACCOUNT_ID, "ProjectISAC", expiry.timestamp())
        return None


class SDKServer(HTTPServer):
    def __init__(self, port=55003, emit=print):
        self.services = SDKServices()
        self.emit = emit
        self.event_count = 0
        super().__init__(("127.0.0.1", port), SDKHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


class SDKHandler(BaseHTTPRequestHandler):
    # One request per connection: no ambiguous request-body reuse/pipelining.
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass  # Never print incoming URL, headers, body, or credentials.

    def respond(self, status, route, document=None):
        body = b"" if document is None else json.dumps(document, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)
        self.server.event_count += 1
        if self.server.event_count <= 1000:
            self.server.emit(f"SDK_HTTP route={route} status={status} response_bytes={len(body)}")
        elif self.server.event_count == 1001:
            self.server.emit("SDK_HTTP log_limit=1000")

    def dispatch(self):
        # No host forwarding, URL fetching, persistent identities, or payload logs.
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
            return self.respond(400, "invalid-framing")
        try:
            size = int(lengths[0]) if lengths else 0
        except ValueError:
            return self.respond(400, "invalid-length")
        if not 0 <= size <= 65536:
            return self.respond(413, "body-limit")
        body = self.rfile.read(size)
        if len(body) != size:
            return self.respond(400, "short-body")
        path = self.path.split("?", 1)[0]
        if path == INTERNAL_AUTH_PATH and self.command == "POST":
            try:
                if len(body) > 256:
                    raise ValueError("oversized ticket lookup")
                document = json.loads(body)
                if not isinstance(document, dict) or set(document) != {"ticket"}:
                    raise ValueError("invalid lookup")
                session = self.server.services.validate_ticket(document["ticket"])
            except (ValueError, UnicodeError):
                return self.respond(400, "local-ticket-invalid")
            if session is None:
                return self.respond(401, "local-ticket-rejected")
            return self.respond(200, "local-ticket-validated", {
                "session_id": session.session_id, "profile_id": session.profile_id,
                "display_name": session.display_name, "expires_at": session.expires_at,
            })
        session_route = re.fullmatch(r"/v[0-9]{1,3}/profiles/sessions", path)
        config_route = re.fullmatch(r"/v[0-9]{1,3}/applications/[A-Za-z0-9-]{1,64}/configuration", path)
        if session_route and self.command == "POST":
            try:
                if body and not isinstance(json.loads(body), dict):
                    raise ValueError("not an object")
            except (ValueError, UnicodeError, RecursionError):
                return self.respond(400, "session-invalid-json")
            session = self.server.services.create_session()
            return self.respond(200 if session else 503, "session-create", session)
        if (config_route and self.command == "GET") or (session_route and self.command == "DELETE"):
            if not self.server.services.authorized(self.headers):
                return self.respond(401, "session-required")
            if config_route:
                return self.respond(200, "configuration", configuration())
            del self.server.services.sessions[self.headers["Ubi-SessionId"]]
            return self.respond(204, "session-delete")
        return self.respond(404, "unsupported", {"error": "unsupported_local_route"})

    do_POST = dispatch
    do_GET = dispatch
    do_DELETE = dispatch
