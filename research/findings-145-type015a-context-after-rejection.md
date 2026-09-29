# Finding 145: `0x015a` needs state context, not just retail timing

Date: 2026-09-28. Read-only analysis of the marked retail tutorial capture,
the failed local `20260928-211120-675192-sdk-adapter-linux` run, and the
verified client text snapshot. No game files or backend replies changed.

The local opt-in frame was not simply sent too early relative to the safe-house
activity start. In retail, the selected `0x015a` arrives 254 ms after the
four-row `0x00e6`; locally it was scheduled 250 ms after that activity start.
The local connection closes immediately after the frame, so receipt is not
proof that its expected prior state existed or that its payload applied.

Retail's nearby *ordered* inbound context on the same stream is:

| Relative to four-row activity start | Frames |
| ---: | --- |
| -151 ms | `0x015b`, `0x0025` |
| 0 ms | `0x014d`, `0x00e6`, `0x01ae`, `0x006c` |
| +152 ms | `0x014d`, `0x006c` |
| +254 ms | `0x015a` |

The local path sends only `0x014d`, `0x00e6`, `0x0102` at the start, then
`0x015a`, `0x0102`. It does not reproduce the preceding `0x015b`, `0x0025`,
`0x01ae`, or `0x006c` state. This is a concrete context gap, though none of
these missing types is individually proven to be a prerequisite.

The static serializers for `0x015a` and `0x015b` have the same structure but
the client registers separate handlers. The `0x015a` callback at RVA
`0x1355280` reaches `0x1ad15a0` and then broad dispatcher `0x1a8f940`,
which calls many subsystem handlers. This does not resemble a dedicated,
confirmed voice-play opcode. The first signed field is `4647` in the selected
frame and in 112 of 117 retail `0x015a` frames; it cannot distinguish the
safe-house cue. One dictionary update at +152 ms introduces a token that
does not occur literally in the selected `0x015a` body, so direct dependence
on that specific token is not established.

Recreating every retail call verbatim would likely import unrelated,
identity-bound and transient state. The next useful pass is a causal one:
trace which `0x015a` sub-handler rejects or consumes the selected frame,
decode the fields it actually reads, and compare the referenced owner/object
and prior `0x015b`/`0x0025`/`0x006c` state to local. Then implement only the
minimal typed prerequisite sequence, driven by state rather than elapsed
time. Do not retry the standalone `0x015a` injection as a dialogue fix.
