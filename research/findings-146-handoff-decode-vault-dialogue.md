# Finding 146: activity-linked `0x006c`, recurring state masks, and vault lead

Date: 2026-09-28. Sources: marked retail tutorial capture
`20260927-064853-retail-tutorial-x3s3v01n`, local runs
`20260928-204534-271428-sdk-adapter-linux` and
`20260928-211120-675192-sdk-adapter-linux`, plus the verified client text/rdata
snapshots. No game files or backend responses changed. Payloads and private
identifiers are not copied into source or this document.

## Safe-house handoff, retail versus local

The four-row retail `0x00e6` activity start is accompanied by more than the
local `0x014d,0x00e6,0x0102` batch. The ordered retail frames around it are:

| Relative time | Retail inbound frames | Newly decoded observation |
| ---: | --- | --- |
| -151 ms | `0x015b`, `0x0025` | `0x015b`: signed `4647`, component mask `0x17f`; `0x0025` remains opaque |
| 0 ms | `0x014d`, `0x00e6`, `0x01ae`, `0x006c` | `0x01ae`: six zero signed values, two false flags; `0x006c` bit 18 references activity index 1081 |
| +152 ms | `0x014d`, `0x006c` | `0x006c` bit 12 carries references at indices 5 and 1083 |
| +254 ms | `0x015a` | signed `4647`, component mask `0x1167`; component body unresolved |

Both `0x006c` frames carry the *same* kind-2, 36-byte identifier. The first
reference (capture-local index 1081) equals the new activity's root reference
in the accompanying `0x00e6`; the second frame's index 1083 was introduced by
the intervening `0x014d`. Earlier `0x006c` messages with that same identifier
show the same bit-18/bit-12 pattern around earlier activity state. This is
strong evidence for activity-linked object/state association, not evidence
that `0x006c` directly plays dialogue. The two handoff bodies now parse and
re-encode byte-for-byte after adding bit 18 to the bounded `0x006c` codec;
that bit is a single compact reference, confirmed at reader RVA `0xeb908d` to
`0xeb9098` (reference reader `0xf7f5f0`). Other `0x006c` presence bits remain
unsupported; do not treat this as a full schema.

The client readers for both `0x015a` and `0x015b` first read a signed32 value
at object offset `+0x360`, then an unsigned32 mask at component-container
offset `+0xb8`, followed by polymorphic component readers. Across this retail
capture all 117 `0x015a` messages have mask `0x1167`, and all 85 `0x015b`
messages have mask `0x17f`, despite varied body lengths. The new prefix codec
recovers those fields and preserves the unresolved component bytes; it does
*not* decode component values or assert voice semantics. The `0x01ae` codec
fully covers its six signed32 values and two booleans; all 11 captured frames
round-trip and contain zeros/false, including frames before this handoff.

The opt-in local `0x015a` experiment closed the session immediately after
send. Combined with its recurring mask, this makes a standalone timed
`0x015a` replay a poor dialogue fix. The missing coordinator speech could be
triggered by the activity-linked state, another inbound event, or a local
script. The existing capture has no marker for the actual voice onset, so
none of those possibilities is established. A targeted audio/event consumer
trace or voice-onset-marked retail capture is needed before adding a reply.

## Vaulting

The static string neighborhood changes the weight of the candidate names.
`HasParkour` is looked up with `IsHealed`, `IsDamaged`, `HasAgent`, and
`HasEnemyTarget` in the same property-handle constructor (RVA `0x157d498`),
which looks like an AI-behavior property set; it is *not* a validated player
vault gate. `VaultBlocked` is adjacent to `User Edge Types`, `TypeMask`, and
AI pathfinding data, so it may describe navigation edges rather than the
player's current action. `CoverVaultIsAllowed` sits in a family including
`Sprinting`, `CoverToCoverIsAllowed`, and `InCoverToCover`, and is the best
named player-action lead, but the observed RVA `0x286d5f0` only registers it.
There is no measured local/retail value or proven consuming branch yet.

The player can sprint and move cover-to-cover after the bounded running-count
override but still cannot vault. The next discriminating observation should
be a read-only, same-obstacle comparison of vault input, whether an action
candidate is offered, and the live `CoverVaultIsAllowed`/navigation result in
retail and local. No vault flag or refcount should be forced from the current
string evidence alone.

## Validation

Synthetic codec tests pass; all 11 retail `0x01ae` frames and all 202
`0x015a`/`0x015b` prefixes round-trip. Both handoff `0x006c` frames round-trip
with unresolved private references. Full local test suite: 548 tests, OK,
18 skipped, when run with loopback socket access. The initial sandboxed run
failed socket tests because socket operations were denied; focused codec tests
passed there as well.
