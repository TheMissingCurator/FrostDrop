# Finding 130: marked tutorial shows evolving per-object `0x00e6` state

Date: 2026-09-27. Offline analysis of the existing retail tutorial capture;
no game installation, backend response, or local profile was modified.
Identifiers and payloads remain private. This is a candidate mission/activity
state family, **not yet a proven mission schema**.

## Reconstructed timeline

Times below are relative to the capture's sole world request. Human markers
are approximate observations, not exact engine event timestamps.

| Event | Time |
| --- | ---: |
| First `world_loaded` marker | +15.484 s |
| Second `world_loaded` marker | +58.614 s |
| Character appearance submission, outbound `0x000c` | +80.324 s |
| First `objective_started` marker | +95.833 s |
| First safe-house marker | +175.809 s |

Inbound `0x00e6` changes its first compact reference as the marked sequence
advances. These references are neither zero nor the created-character ID;
the second compact reference in all examined `0x00e6` frames is zero.

| First-reference dictionary index (private value omitted) | First dictionary seed | Selected `0x00e6` observations | Context |
| --- | ---: | --- | --- |
| 891 | +14.549 s | 52 bytes at +14.55 s | Initial world-entry phase. |
| 1001 | +80.510 s | 52, 129, 145, 161, 177 bytes from +80.51 to +122.35 s; 44 bytes at +123.36 s | Starts 186 ms after appearance submission; overlaps first four marked objective starts/completions. |
| 1081 | +127.353 s | 128, 144, 160, 176 bytes from +127.35 to +193.55 s; 44 bytes at +201.74 s | Begins before objective-start marker 11; spans the remaining intro and safe-house transition. |
| 1814 | +180.387 s | 44 bytes at +207.95 s; 197 to 421 bytes from +231.92 to +333.88 s; 48 bytes at +338.92 s | Later objective/side-mission period. |

The first-reference changes, associated dictionary seeds, and repeated body
growth around both intro and later objectives make `0x00e6` a much stronger
activity-state candidate than raw type-count comparisons. They do **not**
show which field means objective completion or prove that each reference is a
mission rather than another evolving world object. The unchanged second
reference is a zero/sentinel value, not an XP-stat identity.

For this analyzed build, type ordinal `0x00e6` maps to reader RVA `0x17937c0`,
which delegates to `0x178f2c0`. Static code reads two compact references,
three signed 32-bit varints, a boolean, packed/byte fields, then a signed
32-bit row count and a collection of 0x48-byte *in-memory* rows through
`0x178cd80`, followed by further fields. A prefix-only parse finds row counts
5 for reference 1001, 4 for 1081, and 9 for 1814 in their extended forms;
these are structural counts, not proven objective counts. A full neutral
decoder and byte-identical round-trip are still needed before generating
responses from these observations.

## Local-vs-retail boundary

The current private `ISACAUT1` agent-response artifact contains **one**
`0x00e6` in its 142-frame, first-500-ms response window after `0x000c`.
The backend emits this window once and then has no continuing world/mission
simulation. Retail's next `0x00e6` for the same first reference arrives
about 3.16 s after `0x000c`, grows again at about 8.17 s, and continues
through the marked objectives. This gives a concrete missing continuation
to investigate. It does not prove `0x00e6` alone is sufficient for tutorial
progression; other state and client actions may be required.

## Next investigation

Finish the `0x00e6` structural decoder, compare row-level changes for the
same reference across the intro markers, and correlate them with outbound
actions and other inbound messages. In particular, distinguish persistent
per-object state from new dictionary entries and scheduled world updates.
Only then implement an event-driven local activity sequence; do not replay
the retail timeline blindly or mark the tutorial complete by elapsed time.
