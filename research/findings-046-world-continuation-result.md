# Finding 046: post-gate world and labeled transitions captured

Date: 2026-09-25

The continuation run produced a structurally complete and replay-valid
`ISACWBS1` corpus: 7,082 spans, 1,489,416 payload bytes, 51,280 complete
frames, 99 types, one gate marker, zero buffered tail bytes, and 328,562 ms of
request-relative time. The first type-`0x0012` was frame 691 at 17,028 ms.
The user marked the stable Post Office at 58,081 ms, leaving about 41 seconds
and 7,148 inbound frames of initialization after the first gate.

The selected main world stream remained reader 12 through walking outside,
ammo-box use, region entry, and fast travel. Additional readers continued to
appear, but the main transition traffic stayed on the captured stream.

## Action correlations

The ammo-box window ran from 146,099 through 156,978 ms. All 31 observed
outbound type-`0x0082` frames formed a roughly 232-ms burst inside this
window. Outbound `0x0161` and `0x016c` were also present. The selected inbound
stream contained four type-`0x0076` frames and one type-`0x0094`. These are
high-value candidates for the interaction/refill transaction, but roles are
not assigned until a no-op or second controlled comparison confirms them.

The region window ran from 259,730 through 279,763 ms and contained 4,618
inbound frames, about 230 frames per second. It sharply increased types
`0x0023` (154), `0x001f` (58), `0x006c` (47), and `0x006f` (31), and also
introduced outbound `0x016a` plus new channel activity. This strongly supports
server-backed entity or regional-state streaming in addition to client asset
loading.

The fast-travel window ran from 297,824 through 324,286 ms. All 168 post-gate
inbound type-`0x0011` frames occurred in this window. It also contained the
only outbound `0x0104` and `0x0105`, a 39-frame outbound `0x000a` burst, and a
large outbound `0x014a` burst. This is the cleanest transition signature in
the capture and establishes a bounded target for later request/response
schema work.

## Next replay boundary

Replaying the entire action corpus would inject captured responses without
reproducing their triggering client actions. The next causal experiment
should therefore slice the corpus at the `hub_stable` marker, on the nearest
complete frame boundary, and replay only login through fully initialized Post
Office state. If that repairs the Base presentation and exit availability,
the missing state is conclusively in the 41-second post-gate initialization
segment. Action-specific windows should remain analysis fixtures rather than
unconditional replay data.
