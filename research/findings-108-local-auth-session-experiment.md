# Auth binding confirmed; local SDK-ticket validation and experimental reply

Date: 2026-09-27

## Game evidence, before this implementation

`evidence/20260927-032927-119267-sdk-adapter-linux/` establishes that the
24 local type-5 records were assigned normally. The name-lineage trace then
reports registry_count=24, preferred lookup/parse success, source-pointer and
copy equality, and gate_empty=0. No gate patch was used.

The private root capture decodes to registration request 1 with name `auth`
and target equal to a local advertised auth instance ID. The server allocates
channel 0; the client then sends inner type 2 with 90 body bytes on it. This
confirms the service binding for this path, rather than guessing from type 2
or channel 0 alone. Its leading varint is a string length, 75, followed by a
ticket matching the locally generated SDK format and a still-opaque 14-byte
tail. The prior live-ticket request was much larger; do not reuse its size or
misinterpret its leading length as a correlation ID.

The old server intentionally sent no inner response. The client subsequently
closed the channel/connection. We do not claim its displayed error or eventual
termination mechanism from this trace alone. At host inspection time there
were no game, Wine, debugger or custom launcher processes left.

## New local path

`isac_backend/auth.py` only responds when both registration name `auth` and
target match the local catalog, and the request has the observed bounded
shape. It validates the SDK ticket against the issuing SDK's in-memory
session table, through a fixed numeric-loopback HTTP endpoint. There are no
redirects, configurable remote hosts, external requests or retail tokens.
The SDK checks exact issued-ticket equality and expiry; DELETE revokes it.
Its response associates the ticket with the existing local session/profile
ID, display name and expiry. This is local test-session validation, **not**
Ubisoft ownership verification or a persisted character profile.

The server wraps the type-3 reply in inner length framing, then root type-3
channel framing, compression and existing TLS. Channel ID is taken from the
actual registration. Duplicate requests on a channel are ignored after ticket
revalidation; conflicting requests are refused; close discards channel state.
At most eight auth attempts are examined per transport connection. Other
service/message types remain observe-only. No old world replay is connected.

The custom bundle opts into `--experimental-auth`, which requires local
advertisements/channel setup. Without it, the prior observe-only behavior
remains. Logs distinguish a sent response from client session acceptance and
never print credentials, identities or request bodies. Private transport
captures still contain authentication-bearing fields and must remain private.

## Explicitly unproven response fields

Type-3 structure is supported by the existing codec and prior retail decode.
The experiment uses byte_0=0, identity discriminator 2, local UUID text and
local display name, the observed top-level/bundle flags, and an empty entry
list. The field interpretation of identity/display is still provisional.
Three fresh ASCII blobs of observed lengths 240/240/272 begin with
`isac-experimental-`. They are placeholders, not signed retail tokens, nor
known valid client token formats. Lifetime candidates are capped at 8640 and
the remaining SDK session lifetime; their precise client semantics are also
unproven. No captured account values, entitlements or expiring retail tickets
are replayed. The earlier all-empty type-3 experiment failed to establish
login; this nonempty local experiment may also fail. Sending it is not success.

## Tests and next run

- Six auth tests: issued/forged/expired/revoked tickets, strict partial request
  schema, correct nonzero-channel reply, local profile/blob shapes, wrong
  service binding, unknown messages, duplicate/conflicting requests, attempt
  budget, expiry cap and close cleanup.
- Eight SDK tests pass, including real loopback validation, malformed input,
  revocation and public-log redaction.
- Six backend TLS tests and ten main-channel/latency tests pass.
- Nine adapter-transport tests pass with isolated integration enabled. The
  full synthetic bundle creates an SDK session, receives advertisements,
  registers auth, rejects a forged ticket, receives/decodes the experimental
  reply for the valid ticket, ignores its duplicate, and rejects it after SDK
  logout. Auth input is fragmented byte-by-byte through TLS/compression.
- Fifteen launcher/tool tests pass. Recovery now skips unrelated system-owned
  tasks but still refuses inaccessible tasks owned by this desktop user.

The old 03:29 record could not be auto-archived because this user's systemd
process also has an unreadable namespace. A scoped manual recovery verified
Steam's logged reaping of launcher PID 213606, that PID's absence, no managed
game/debugger processes, the free supervisor lock and exact capture/net
identity. Its metadata was preserved in
`private/sdk-session-stale-verified-281bwa5p/sdk-adapter-session.json`.
No processes were killed, and no game files or prefix data were changed.

Next run: same isolated custom Steam option, desktop networking on. No DLL
rebuild or extra terminal. Look for local-ticket-validated and
auth-experimental-reply-sent, then independently inspect any new registration
or inner request to establish advancement. Do not label the session accepted
solely from a server log or claim character/world support.
