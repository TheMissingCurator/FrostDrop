# Finding 131: complete observed `0x00e6` codec and objective-row progression

Date: 2026-09-27. Offline static/capture analysis and neutral protocol-codec
changes only. No game installation, local backend responses, retail account,
or profile data was modified. Private identifiers and message bodies remain
private. Follow-up to [finding 130](findings-130-marked-tutorial-activity-state-candidate.md).

## Wire structure and validation

For the analyzed game build, inbound type ordinal `0x00e6` uses reader
`0x17937c0` → `0x178f2c0`; its repeated row delegates to `0x178cd80`, and
its nested subrow to `0x1795e20`. The new `type00e6.py` codec follows the
reader's field order:

1. Two compact references; three signed32 varints; boolean, packed/byte
   values; signed32 row count.
2. Each row: three signed32 values, two booleans, float32, boolean, float32,
   reference, signed32 nested count, nested subrows, and signed8 tail.
3. Each subrow: reference, vec3f, signed32, boolean.
4. Two unsigned64 varints, float32, vec3f, unsigned32, five unsigned32 values,
   unsigned32, unsigned16, byte; two bounded reference/value collections;
   boolean, byte, two booleans, final reference.

The decoder is atomic with respect to its reference table and rejects
noncanonical observed encodings, truncation, extra bytes, oversized bodies,
and excessive nested counts. All **38** `0x00e6` frames in the existing
marked tutorial capture decode and re-encode byte-for-byte with identical
dictionary state. This is complete coverage of *observed frames*, not a
claim that every game variant is supported. The public analyzer now reports
only capture-relative times, local dictionary indices, row-state candidates,
and subrow counts; it prints no message bodies or raw identifiers.

## First marked tutorial activity (capture-local reference index 1001)

Times are relative to the world request. The five row slots remain in fixed
order. Values below are each row's **third signed32 field** (`signed_0_2[2]`),
not a business-label enum recovered from symbols.

| Time | Header byte | Row values | Nested subrow counts |
| ---: | ---: | --- | --- |
| +80.510 s | 0 | no rows | none |
| +83.480 s | 7 | 0, 0, 0, 0, 0 | 0, 0, 0, 0, 0 |
| +88.500 s | 7 | 0, 1, 0, 0, 0 | 0, 1, 0, 0, 0 |
| +102.690 s | 7 | 0, 4, 1, 0, 0 | 0, 1, 1, 0, 0 |
| +110.900 s | 7 | 0, 4, 4, 1, 0 | 0, 1, 1, 0, 0 |
| +114.200 s | 7 | 0, 4, 4, 4, 1 | 0, 1, 1, 0, 1 |
| +122.350 s | 7 | 0, 4, 4, 4, 4 | 0, 1, 1, 0, 1 |
| +123.360 s | 19 | no rows | none |

The first human objective-start marker is +95.833 s, after the row-1 value
first becomes 1; its completion marker is +104.358 s, after that value
becomes 4 and row 2 becomes 1. Subsequent human markers similarly fall near
the 1→4 and next-row 0→1 changes. The final no-row, byte-19 message is 475 ms
before completion marker 10. Marker timing is approximate and may lag the
actual client transition.

The pattern repeats on a different first reference (index 1081): four rows
progress from `1,0,0,0` at +127.353 s through `4,1,0,0`, `4,4,1,0`, and
`4,4,4,1`, followed by a no-row, byte-19 message at +201.740 s. Later
side-mission-period reference 1814 has nine rows and the same left-to-right
0→1→4 pattern, including rows with multiple nested subrows. This repeated,
ordered behavior makes an objective/progression interpretation **high
confidence**, though the exact meanings of 1 and 4 and the first row's role
remain inferred rather than symbol-proven. In particular, a row can become
active without a new nested subrow, so subrow count alone is not progress.

## Local backend implication

The opt-in local agent response after `0x000c` contains only the +80.510-s
52-byte `0x00e6` for reference 1001, with no rows. It does not deliver the
five-row +83.480-s activation or any subsequent objective-state updates.
That is a concrete missing activation/progression path consistent with the
client entering the world without a functioning intro tutorial. The codec
does not authorize replaying retail identities or timer-driven completion:
the next task is to establish which client actions/conditions cause each
transition and to bind an independent local activity instance.
