# Second observed local character-creation variant

Date: 2026-09-27. Backend-only change; no game DLL, launcher, world-template,
database schema, existing active/archive row, or retail account was modified.

## Evidence and boundary

The latest isolated game run saved exactly one decoded type-5 create request:
request ID 0, `flag_5=false`, `flag_4=false`. Its backend refused at
`store-create` with `unsupported-create-flags`; SQLite and OS error codes were
absent. Thus this was the old mode check, not the world-startup template,
database corruption or character-cleanup request. The prior retail reference
captured `true,false`; both are now observed client requests. The full business
meaning of each flag is not established by that comparison alone.

Static writer 0x225cb10 and poller 0xb4897..0xb48cd confirm the wire order:
pending +0x10 becomes writer +5 / first serialized flag, and pending +0x11
becomes writer +4 / second serialized flag. The latest local request is
canonical, not a swapped-byte decoder error. Existing retail data pairs the
first flag true with a newly created entry whose `is_male` field is true;
using the flag for the local presentation field is a **provisional inference**,
not proof of every upstream meaning. The second flag remains neutral/unknown.

## Implementation

`ProfileStore.create` admits `(true,false)` and `(false,false)`, retaining
the exact pair in its current `request_flags` column. The first flag is used
as the presented entry's `is_male` value for this experiment. Both variants
retain the same version-8 starting-character blob and normal starting zone;
no alternate-mode, survival or world-state response is invented.

The existing one-unfinished-slot policy still applies. Repeated requests with
the same pair reuse the stored identifier. A conflicting pair while an active
unfinished character exists is refused, rather than silently mutating that
character. `archive_unfinished` now accepts either of the two normal stored
pairs, verifies that the entry's presentation flag matches it, and archives
the exact record transactionally. Locked, customized, survival, wrong-zone and
foreign records remain protected as before. Archived historical entries are
not deleted or rewritten. No schema migration or database reset is necessary.

## Verification and next game run

37 profile tests, 13 discovery/admission tests and eight world-startup tests
pass. The isolated transport suite passes all 10 tests in default and
startup-enabled modes: an unsupported second-flag=true request is refused
without a success reply, normal first-flag=true creation/discovery works,
cleanup archives it, and first-flag=false creation is persisted and can be
selected. Only synthetic clients were used; real game acceptance is still
unverified. The suite required approved execution outside the coding sandbox
for private namespace setup.

Repeat the unchanged `custom --world-startup` Steam option with desktop
networking on (the game/backend remain isolated). No DLL rebuild/install or
local database reset is required. If the client proceeds past creation, inspect
the next backend stage before expanding creation semantics or world defaults.
