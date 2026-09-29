# Finding 136: first tutorial objective transition

Date: 2026-09-28. Read-only comparison of the marked retail tutorial capture
and the complete decompressed local client-root stream from the 13:17 run.
No game code, server response, profile, or capture was modified. Times below
use the world-channel request as the retail origin. Reference indices are
capture-local and do not identify an account or character.

## What the retail client actually receives

The first five-row `0x00e6` arrives at +83.484 s (129-byte body), with row
states `(0,0,0,0,0)`. The next `0x00e6` arrives at +88.498 s (145-byte body),
with states `(0,1,0,0,0)`. A structural decode of both shows that **only row
1 differs**: its third signed32 field changes from 0 to 1 and it gains one
subrow. The new subrow contains a compact reference, a nonzero position
vector, signed value 0, and false flag. All top-level fields and the other
four rows compare equal after decoding. This is an observed wire shape, not
proof that state 1 is the sole semantic condition for objective display.

The added subrow's reference is dictionary index 1017. The server sends a
one-reference `0x014d` dictionary update immediately before the active
`0x00e6` in the same capture tick (+88.498 s), introducing that index. A
nine-reference `0x014d` arrives 36 ms earlier. Any experiment that emits the
145-byte frame without preserving or rebuilding this dictionary lineage risks
an invalid reference, even if the `0x00e6` body is otherwise correct.

Two client `0x014a` frames precede the active update at +87.356 s and
+87.391 s. Both are 23 bytes. Their parsed reference values are different
from each other and neither equals the activity, row, or subrow references in
the first activity sequence. They share the same third scalar while their
second scalars differ. Other `0x014a` frames occur before the five-row state
and later in the tutorial, and a previous retail fast-travel capture recorded
a large `0x014a` burst. Therefore their temporal proximity alone does **not**
establish an objective-start request. The outbound compact-reference table
is only partially decoded across message types, so this comparison is limited
to the fully parsed 23-byte frames and exact 16-byte values, not a complete
semantic interpretation of `0x014a`.

## Local comparison and next discriminating test

The local 13:17 capture sent the all-zero five-row `0x00e6` and a following
`0x0102`; the client parsed, queued, and transferred that activity object, and
the player saw the mission shell. Parsing the entire saved local client-root
stream, including traffic beyond the log's per-message cap, found **zero
`0x014a` frames** before or after the `0x000c` appearance submission. It did
show subsequent client `0x000a`, `0x0014`, `0x006a`, and other world traffic,
so the client did not simply stop sending. The local backend does not emit
the retail first-active `0x00e6` or the preceding dictionary update.

The immediate missing *server state* is now well bounded: the row-1-active
update plus its new compact reference and batch flush. The cause of its retail
production is **not** established. A safe next experiment is an explicitly
opt-in, one-shot local state-delivery test that binds the first-active update
to local dictionary state and emits its required dictionary update and
`0x0102` after the already confirmed five-row batch. If the objective appears,
that proves sufficiency of the state delivery for display, not a correct
gameplay trigger. Do not put this on a five-second timer, advance later rows,
or grant rewards based on the retail timeline. The causal trigger and progression
logic still need separate work, ideally comparing a controlled retail
objective-start action to local world events or tracing the client request
producer/consumer at that boundary.

## Opt-in display test prepared

The separate `--first-objective-test` mode now extracts only the observed
subrow reference and position into a 36-byte owner-only per-run artifact.
The backend reconstructs the row-1-active update from its *local* five-row
baseline, inserts the new reference at the current local dictionary index,
and sends `0x014d`, `0x00e6`, `0x0102` as a second one-shot batch. The test
rejects unexpected source-row changes, identity collisions, baseline states,
and dictionary misalignment. It does not modify the normal tutorial mode.

## First local run of the opt-in test

The 2026-09-28 13:45 capture logged both `TCTD_TUTORIAL_SEND` and
`TCTD_FIRST_OBJECTIVE_SEND` after the authenticated `0x000c`. The player
reported that reselecting the mission made its first objective play, but the
objective did not advance. This is evidence of client-side retention/display
of the active state after a UI selection; it does not establish automatic
mission selection or server-side progression. The read-only client trace
stopped after confirming the earlier five-row batch flush, before the second
active batch, so it does not independently prove application of that batch.

Parsing the complete saved local client-root stream, rather than relying on
the log's capped per-message lines, found 28 post-submission `0x0014` frames
with 67-byte bodies and zero `0x014a` frames. The earlier all-zero-state run
had 11 post-submission `0x0014` frames, also 67 bytes. In the marked retail
tutorial, a 67-byte outbound `0x0014` at +102.316 s precedes the first
`(0,1,0,0,0)` to `(0,4,1,0,0)` activity update at +102.694 s. This is a
useful candidate input for the first completion transition, **not** proof of
its meaning or of which local frame corresponds to the player's action.
The backend presently observes but does not handle `0x0014`, and it never
emits a row-completed/next-row-active update. The first completion condition
and response should be decoded and tested separately, without accepting
arbitrary `0x0014` traffic as completion.

## Take-cover clarification and bounded `0x0014` decode

The player clarified that the visible first objective was **take cover** and
that taking cover locally did not advance it. The analyzed-build writer
(`0x18a6910` → `0x18a3a20`) and reader (`0x1791a40` → `0x178dc10`) support
a 67-byte observed `0x0014` shape: two raw 16-byte references, three signed
integers, two vec3 positions, one float, and four small byte fields. A
strict read-only codec round-trips all three relevant retail frames and all
28 post-submission frames in the local test. The first reference equals the
respective retail/local character ID. The second reference in the retail
cover-entry frame equals the second reference in multiple local frames; it
identifies the same static cover object across these captures, though the
protocol field's general meaning remains unproven.

The retail frame at +102.316 s has signed fields `(1,0,0)`, byte fields
`(1,0,0,85)`, and a destination at approximately `(372.3,-0.1,639.0)`.
The local test sent a frame matching those state fields, exact cover-object
reference, and destination vicinity. The retail frame is 378 ms before the
first completed/next-active `0x00e6`; the local backend ignored the matching
event. This strongly supports a missing server-side cover/progression path,
but not an exact trigger rule: a cover-entry report could be necessary yet
insufficient, and other world state may also be checked.

The retail follow-up `0x00e6` is a 161-byte body with row states
`(0,4,1,0,0)`. Relative to the 145-byte first-active state, only row 1's
state changes and row 2 gains state 1 plus a positioned subrow. A one-entry
`0x014d` introduces that subrow's reference immediately before the update,
followed by the usual batch boundary. This bounds a potential *future*
opt-in completion test. No local completion response or gate was added in
this investigation.

## Opt-in cover-gated completion experiment prepared

A separate `--cover-completion-test` mode now prepares an owner-only 64-byte
artifact containing only the observed cover-object reference/point and the
next objective's subrow reference/point. Its `0x0014` gate requires the local
character ID, exact cover-object reference, retail entry-state fields, and
a two-metre horizontal / one-metre vertical cover-point vicinity. A match
after agent submission emits the first completion batch once per admitted
channel: local-index `0x014d`, 161-byte `(0,4,1,0,0)` `0x00e6`, then `0x0102`.
Nonmatching or premature traffic is ignored. The first objective display
mode is unchanged unless this additional flag is present. Tests prove the
recorded local cover event matches the gate and validate negative cases,
batch order, dictionary lineage, and one-shot behavior. **No game run has
yet tested this response's client-side effect.** The gate is deliberately
capture-derived and may not generalize to other cover objects or locations.
