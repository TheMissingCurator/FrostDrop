# Focused creation-rejection diagnostics

Date: 2026-09-27. Diagnostics only: creation policy, profile database, wire
responses, world template, launcher and game DLL remain unchanged.

## Confirmed boundary

The 08:28:31 run authenticated, archived the old unfinished character, and
returned an empty list. Its next profile-client type-5 request (three bytes)
received `profile-store-or-mode-rejected`, with no reply. No world snapshot
was sent. The 06:21 run passed the same cleanup and created a replacement.

The latest run lacks final backend root streams and a summary; its request
flags and exact exception cannot be recovered from the available public log.
Host process inspection after exit found no game, Wine, debugger or backend
remaining. No process was killed for diagnosis.

Read-only database integrity checking passed. Creation succeeded against an
in-memory copy with `(true, false)` and failed with the other three flag pairs.
No active unfinished character remained after cleanup. Production data was
not changed. Different flags are a hypothesis, not a confirmed fact; this
check does not exclude a transient storage failure.

## Changes

Profile failures now carry an operation and allowlisted reason, plus numeric
SQLite/OS codes where available. Reasons distinguish unsupported creation
flags, conflicting stored flags, invalid stored character, archival errors,
SQLite errors, OS errors and other value-validation errors. Operations
distinguish `store-create` from `encode-create-reply`, including failure after
creation committed. Existing stages and responses are retained. Exception
text, account/character IDs and credentials are never printed.

For the exact local profile service, up to 128 creation requests per connection
are checkpointed **before dispatch**. Only a decoded uint32 request ID plus
two booleans (at most seven bytes) are written to exclusive-create mode-0600
`transport-private/backend-NNNN-create-NNNN.bin` files. Unknown shapes aren't
saved. Each file closes immediately, independent of final backend cleanup.
Diagnostic I/O failure does not change the game response. This is not a repair
of full-stream shutdown flushing or a power-loss durability guarantee.

New flushed public markers are `TCTD_PROFILE_CREATE_REQUEST` (both neutral
flag names and checkpoint status) and `TCTD_PROFILE_FAILURE` (operation,
reason and numeric error codes). Neither flag's business meaning is assumed.

## Verification and next run

36 profile tests, 13 discovery/admission tests and eight world-startup tests
pass. The 10-test isolated transport suite passes both default and startup
modes. It sends unsupported flags, verifies the checkpoint and diagnosis
while the connection is open, then completes normal creation and the existing
flow. Namespace setup required approved execution outside the coding sandbox.
No game or retail service was used by these tests.

Repeat the same `custom --world-startup` launch, desktop network on, existing
game/backend isolation retained. No rebuild, reinstall, database reset or
new probe is required. Inspect flags and rejection operation before changing
accepted modes or world startup values.
