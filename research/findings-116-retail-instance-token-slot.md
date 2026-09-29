# Retail instance token lineage and local admission correction

Date: 2026-09-27. Supersedes the first-slot admission assumption in finding 114.

## Retail evidence

Capture: `evidence/20260927-061433-retail-handshake-9fgftv_k/`.
The game-process observer recorded all four target events as complete:

| Event | Captured token lengths | Lineage |
| --- | --- | --- |
| Auth reply | 240, 240, 272 | Three issued auth blobs |
| Successful discovery join reply | 208 | Discovery-issued instance bearer |
| Instance connect request | 240, 208, 272 | Auth blob 0, join bearer, auth blob 2 |
| Game connect reply | No timed tokens | Parsed type 2: nonzero 16-byte field, false boolean |

Instance slot 1 has the same fingerprint/length as auth slot 1; instance slot
2 matches the join bearer; instance slot 3 matches auth slot 3. There is no
fourth token in this observed request. Join lifetime is approximately 300s;
instance connect observes approximately 299s remaining. These are deadline-
derived estimates, not exact incoming wire TTLs.

The join reply's unknown uint32 and descriptor proxy ID are both 35 in this
sample. Equality in one session does not establish that they have the same
semantics; neither is copied into local replies. The game-connect boolean is
false after a successful parse, not a proven failure-status field. Its meaning
and the producer/consumer of the nonzero 16-byte field remain to be established.

Four hits produced four complete results; last coverage has zero register
conflicts and zero resume failures, with one thread-arming failure. Neither
process has an end record. Complete flushed events are usable; absent events
would not be conclusive. A targeted Proton log scan found no unhandled
exception, access violation or page-fault markers. No reusable bearer bytes
were saved or copied into local responses.

## Bug and implementation

The prior isolated local capture
`20260927-053714-510505-sdk-adapter-linux/tctd-backend.log` reached discovery
success and instance channel 10, then logged `instance-token-rejected` for its
602-byte type-0 body. `ServerListSession._admit` checked `tokens[0]` against
the discovery-issued instance bearer, contradicting the confirmed retail order.

Admission now compares only `tokens[1]` (second slot) against that bearer using
the existing SHA-256 and constant-time comparison. It does not scan other slots
or accept an old swapped order as a compatibility fallback. Exact local route
selection, parent auth and character ownership, expiry/revocation, request
digest duplicate/conflict detection and close semantics are unchanged.

The first and third blobs' origin is confirmed, but they are not independently
authenticated at instance admission by this change. Parent validity is checked
through the existing issued local service and character bearer bindings. The
wire decoder remains a structural parser, not an authorization policy.

No DLL rebuild, profile database change, retail credential replay or new response
is introduced. The handler still reports `instance-token-bound-world-pending`
with no response on valid admission. This does not implement playable-world
startup or establish a complete DELTA fix.

## Verification

Updated unit fixtures use the locally issued first/third auth blobs with the
discovery-issued bearer between them. Before the backend change the new tests
reproduced rejection of that order and acceptance of the old swapped order.
After correction, the targeted 41-test suite passed (40 passed, one opt-in
integration skipped). Cases include forged/empty/misplaced instance tokens,
successful retry after refusal, duplicate/conflicting requests, parent expiry,
revocation, character renewal and route lifetime.

The opt-in isolated transport suite subsequently passed all nine tests. Its
real compressed TLS flow rejects the swapped token order, admits the corrected
three-token order after discovery close, checks the exact admission log stages,
and verifies no invented game-server response. This uses synthetic local
credentials, not the retail account or real game. The real-client corrected
custom run remains untested.

The retail observer DLL was restored to the verified original loader after the
completed capture; the original backup and probe build were retained. Next custom
run uses the existing custom Steam option and desktop networking on, with the
game/backend isolated by that mode. Expect admission to advance to
`instance-token-bound-world-pending`; loading can still time out because the
game-server reply and initial world/session state remain unimplemented.
