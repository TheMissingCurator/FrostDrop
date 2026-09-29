# Finding 140: structures of the tutorial close-adjacent messages

Date: 2026-09-28. Read-only analysis of the marked retail tutorial capture
`20260927-064853-retail-tutorial-x3s3v01n` and the verified runtime text/rdata
snapshots used by `tools/map-retail-message-type.py`. No backend replies or game
files changed. Reference numbers below are capture-local dictionary indices;
private identifier values and payload bytes are intentionally omitted.

## Recovered wire layouts

| Type | Static reader RVA | Decoded structure | Retail observations |
| --- | ---: | --- | --- |
| `0x014d` | `0x17939e0` | Count followed by compact references; appends to the per-session reference dictionary | 716 frames, all already round-trip in the existing codec |
| `0x0064` | `0xc4b680` (jumps to `0xc47d50`) | Three compact references, unsigned32 varint, two booleans | 21 nine-byte frames; all parse exactly with no trailing bytes |
| `0x01ae` | `0x1102d80` | Six signed32 varints, two booleans | 11 eight-byte frames; all six numbers are zero and both booleans false in every frame |

All 21 `0x0064` and 11 `0x01ae` frames decode without leftover bytes and
re-encode byte-for-byte under these layouts.

The close-adjacent `0x014d` at +123.239 seconds introduces dictionary
index 1073. The accompanying `0x0064` resolves as three references with
indices `(329, 1073, 1073)`, integer `1`, flags `(false, false)`. Index 329
matches the captured created character. The next batch at +123.294 seconds
contains the no-row `0x00e6` activity close followed by `0x01ae` with six
zeros and two false flags. Times here are relative to the first inbound
world record, approximately 119 ms after the world-channel request; human
markers are approximate.

The new `0x0064` reference is **not** the closing `0x00e6` activity reference
(index 1001), and none of the 21 second/third `0x0064` references occurs in
any decoded `0x00e6` structure in this capture. Their role remains unknown.
The `0x0064` shape recurs around earlier objective transitions at +80.363,
+90.420, +102.591, +110.786, and +114.140 seconds, as well as after the next
four-row activity starts. It is therefore not specific to mission completion.
Some later `0x0064` frames change both boolean flags, so those flags may carry
meaning, but no interpretation is established yet.

`0x01ae` also appears at +14.432 seconds, long before this tutorial closes,
and all 11 captured bodies are identical zero/false values. This argues
against treating its payload as a mission-specific completion record. It could
still be a state/synchronization signal whose context lies outside its body.
`0x014d` is a dictionary update, not itself a mission ledger write. None of
these observations identifies a durable completed-mission record or a reward
message; Agent Activation has no observed reward.

The prior local attempt combined these close companions and disconnected
before the next-activity batch. This structural decode does not establish
which companion, ordering, reference binding, or client state caused that
disconnect. Keep the known-good simple close for the next live test.
