# Authenticated unfinished-profile cleanup

Date: 2026-09-27. Builds on findings 111/112. No new DLL, launcher mode,
registration patch or retail capture is required for this implementation.

## Observed blocker, distinct from character-token rejection

`evidence/20260927-050135-066725-sdk-adapter-linux/tctd-backend.log` shows
successful auth and profile lists followed by inner type 3, body length 17,
on profile channels 3, 7 and 9. The backend reported
`profile-unsupported-message` and emitted no reply. There is no type-7
selection or type-8 character-token reply in that run. It therefore does not
test client acceptance of the token implementation in finding 112.

Static profile-list handling at 0x185e861 collects the identifiers of
uncustomized, unlocked profiles into the owner's collection at +0xc0.
The frontend state string includes `AUTOLOGIN_WAIT_FOR_DELETE_PROFILES`.
Together with the persisted unfinished local profile, this supports the
startup-cleanup explanation. The current run's private backend root streams
had not been flushed when inspected, so its requested identifier was not
correlated against the database. Do not claim that correlation as established.

## Verified delete schema and consumer

Verified text SHA-256:
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

Writer 0x225cbb0 emits delimiter 3, uint32 varint request ID from object+0,
then raw identifier storage from object+4 via 0x223f200. No length prefix
is written. This implementation admits only the observed 16-byte identifier
shape; the local request is ID + 16 bytes, with no trailing data.

Reader 0x2257eb0 checks delimiter 4, reads uint32 varint request ID via
0x223dad0 into object+0 and a boolean via 0x223d530 into object+4.
Consumer 0x959bd matches the ID against the pending delete request at
client+0x38. At 0x959d7, true dispatches callback result 4 at 0x959e1;
false dispatches result 3 at 0x95a9f. The pending request is destroyed and
cleared at 0x95aae–0x95acf. This is a success boolean, not creation's
status-0 enum or character-token status 2.

## Implemented local lifecycle

Only an exact advertised `profile_client` binding with a currently valid
issued local auth token can invoke type-3 deletion. The account comes from
that token, never from client-supplied account metadata. Foreign and unknown
identifiers receive the same type-4 false reply without mutation.

For an owned normal unfinished character, a `BEGIN IMMEDIATE` transaction:

1. Validates the stored identifier, normal creation flags, uncustomized and
   unlocked/non-survival state, default start zone and empty instance name.
2. Inserts its exact account, identifier, request flags and encoded entry,
   plus local archive time, into `archived_unfinished_characters`.
3. Removes exactly that account/identifier from `unfinished_characters`.
4. Commits before returning success to the request handler.

Storage errors, malformed entries or unsupported modes receive no success
ACK; both tables roll back together. Deletion is a recoverable archive,
not a database reset or irreversible character wipe. Repeating deletion of
an archived identifier owned by the same account returns true without
removing a newer character or invalidating its caches. Same-channel duplicate
requests retain the existing ignore/conflict policy.

New archive moves invalidate list/create/selection request caches across this
transport's profile channels so the client can reuse IDs during cleanup and
creation. They remove this transport's character bearers for the deleted
account/identifier. Other transports' bearer resolution already rechecks
database ownership and therefore rejects a removed active profile.

Schema version 2 adds the archive table transactionally and retains existing
version-1 active rows byte-for-byte. The database remains private (0600).
Archived rows contain no issued SDK/auth/character bearer. There is no
automatic restore, purge, finalized-character deletion or profile-customization
shortcut. Recovery data is retained in the same private database; close the
game/backend before inspecting or restoring it manually. Tests use temporary
databases and do not migrate/delete the production character.

Auth/list/create/token response formats, advertisements, service routing,
isolation and game hooks are unchanged. Only the authenticated type-3 handler
and its type-4 response are added. No world/session server is implemented.

## Verification and next game run

Tests cover exact request/reply bytes and bounds, authentication/expiry/
revocation, foreign IDs, persistence, v1 migration, rollback, ignored-delete
refusal, concurrent deletion, retry scope, cache invalidation, recreation and
character-bearer invalidation. The synthetic isolated SDK/TLS/compression
exchange additionally exercises fragmented delete -> committed archive ->
empty list -> creation -> token selection, duplicate deletion and an old
delete retry after recreation.

Verification: 77 unit/regression tests ran with 76 passing and one opt-in retail
Proton test skipped; all 16 backend/isolated-transport tests passed. The latter
required execution outside the coding sandbox because that sandbox forbids
socket creation. Total: **92 passed, 1 skipped**. No actual game acceptance
of the new delete reply is claimed by these synthetic checks.

Restart the previous custom run; Python handlers are loaded at backend start.
Use the unchanged custom Steam launch option with desktop networking on.
Expected marker is `profile-unfinished-character-archived response=0x0004`,
followed by subsequent client requests. A repeated completed deletion may show
`profile-unfinished-character-already-archived`. Neither marker proves client
acceptance or world loading. Stop at the first stable menu/error and inspect
the next actual messages; no gameplay is required for this startup test.
