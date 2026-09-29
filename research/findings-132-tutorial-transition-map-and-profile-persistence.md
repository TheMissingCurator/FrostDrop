# Finding 132: marked intro transition map and local profile persistence

Date: 2026-09-27. Read-only analysis of the existing marked retail tutorial
capture, local backend code/log, and local SQLite schema/counts. No game,
backend response, or profile data was changed. Reference numbers below are
capture-local dictionary indices; no raw identifiers or payloads are published.

## Intro activity transition map

Source: `evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin`
and its `.jsonl` marker file. Times are relative to the world-channel request.
The state vector is the third signed32 field of each `0x00e6` row for activity
reference index 1001. `0 -> 1 -> 4` is an observed sequence, not a proven
business enum. The human numpad markers were approximate and cannot establish
the exact instant an objective changed.

| Time | `0x00e6` state | Nearby observed event | What it supports |
| ---: | --- | --- | --- |
| +80.510 s | no rows, header 0 | Client `0x000c` appearance submission at +80.324 s | Initial empty activity state follows character submission; not yet activated. |
| +83.484 s | `0,0,0,0,0`, header 7 | Client `0x014a` at +82.860 and +83.314 s | Five rows become available; `0x014a` is a candidate interaction, not a proven trigger. |
| +88.498 s | `0,1,0,0,0` | Client `0x014a` at +87.356 and +87.391 s; first human start marker is later, +95.833 s | Row 1 becomes active; marker latency prevents exact objective labeling. |
| +102.694 s | `0,4,1,0,0` | Client `0x0014` at +102.316 s; human completion marker +104.358 s | Row 1 completes and row 2 activates before the marker. |
| +110.898 s | `0,4,4,1,0` | Client `0x000a` at +110.759 s and `0x006a` traffic; start marker +109.752 s, completion marker +112.266 s | Row 2 completes and row 3 activates. Neither message type recurs for every transition. |
| +114.204 s | `0,4,4,4,1` | Client `0x0088` at +113.941 s; later start marker +116.176 s | Row 3 completes and row 4 activates. Temporal association only. |
| +122.352 s | `0,4,4,4,4` | Client `0x006a` at +122.121 s; completion marker +123.835 s | Final row completes before the marker. |
| +123.358 s | no rows, header 19 | Client `0x0003` at +123.418 s | Activity closes; `0x0003` follows this update and could be acknowledgment or a subsequent action. |

The same ordered row progression appears in activity reference 1081 after
+127.353 s and in later side-mission-period reference 1814. The first intro
row stays zero throughout; its role is unknown. Three nonzero subrow references
occur in the first activity, but **none** occurs as an exact 16-byte value in
the observed first-activity-window outbound `0x000a`, `0x014a`, `0x0014`,
`0x0003`, or `0x006a` bodies. Thus these requests cannot yet be matched to a
specific row by raw-ID equality. Routine outbound `0x000f`/`0x0011` and
server-side world/AI state are not decoded enough to rule them in or out.
This is a transition/correlation map, not a causal trigger map. A focused
next step is to decode the changing client action/interaction fields or trace
the server's `0x00e6` producer, then compare repeated events across captures.

The local experimental agent batch contains only the +80.510-s no-row
`0x00e6`, not the five-row activation or progression. The local backend also
labels later world messages `instance-world-message-unimplemented`; it has
no objective simulation or durable progression writer. This is consistent
with the intro sequence not running correctly locally, but replaying these
states on timers would not establish correct input gating.

## Profile-saving status

The local `ProfileStore` has a persistent SQLite `unfinished_characters`
table and transactional `create`/archive operations. The 2026-09-27
19:14 local run logged a successful archive, empty list, character create,
list, and character-token reply. This supports **unfinished-slot creation and
listing**, not permanent customized-character persistence. A read-only check
of `private/local-profiles/characters.sqlite3` during this analysis found
schema version 2, zero active unfinished slots, and nine archived unfinished
slots. The database may have changed after that run; those counts should not
be used to infer which particular run removed the active slot.

`ProfileStore._entries` explicitly rejects customized records, and `create`
persists the 161-byte starting record. The world `0x000c` handler sends an
experimental response but does not write the appearance, 1261-byte customized
record, tutorial progress, or world state to the store. Retail evidence in
[finding 128](findings-128-agent-submission-schema-and-profile-lineage.md)
links the 32 appearance floats in `0x000c` to the later customized record,
but its 18 additional node structures are not yet independently produced.
So the answer to “does the profile save?” is: **the unfinished character slot
can persist, but customization/finalization and gameplay progress do not.**
