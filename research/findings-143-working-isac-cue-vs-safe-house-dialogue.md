# Finding 143: working creation cue versus missing safe-house dialogue

Date: 2026-09-28. Read-only comparison of the existing retail tutorial
capture, the local agent-response artifact, and the current next-activity
builder. No game files, backend replies, or profile data were changed.

The player reports that ISAC dialogue plays after local character creation,
whereas the coordinator lines associated with the safe-house handoff do not.
This shows that local audio playback and at least one dialogue path work; it
does **not** establish that both lines use the same trigger mechanism.

The local post-submission response (`private/tutorial-agent.isacaut`) includes
one 28-byte inbound `0x015a`. That body is byte-identical to the retail
`0x015a` arriving 103 ms after outbound appearance submission `0x000c` in
`20260927-064853-retail-tutorial-x3s3v01n`. It is the only `0x015a` in that
bounded local response. However, the retail capture contains 117 inbound
`0x015a` frames of 23 different lengths. Proximity and body equality do not
prove this type is a voice command: it could be state needed by a client-local
script, or unrelated state arriving at the same time.

At the retail safe-house handoff, the first `0x015a` after the four-row
activity start has a 35-byte body and arrives about 254 ms later. It does
not match the local post-submission 28-byte body. The retail handoff also has
nearby `0x015b`, `0x0025`, `0x001f`, `0x01ae`, and `0x006c`. The current local next-activity
batch sends only `0x014d`, `0x00e6`, and `0x0102`; its default close batch
sends only `0x00e6` and `0x0102`. Thus the missing dialogue is consistent
with an incomplete handoff, but no specific omitted message has yet been
identified as the cue.

The static reader shared by `0x0159` and `0x015a` at RVA `0x178cd30` reads
one scalar into object offset `+0x360`, then delegates a component collection
at `+0x20` to `0x1793940`; that sub-reader iterates polymorphic component
readers. This is not a simple confirmed audio opcode. The discriminating
next step is to mark actual voice onset in a retail run or trace the client's
audio/event consumer, then correlate that event with the inbound batch. If
testing a local addition, add only the confirmed event and preserve the
known-good mission-close response, rather than replaying every nearby frame.

An opt-in `--dialogue-015a-test` now sends precisely the first 35-byte
`0x015a` observed 254 ms after the retail four-row safe-house start, with a
following `0x0102` batch flush. The frame is pinned by digest and extracted
from the private capture at launch. The known-good close and activity-start
batches are unchanged. This tests client behavior; it does not assert that
`0x015a` is a voice cue or solve its general schema.

## First opt-in result

The `20260928-211120-675192-sdk-adapter-linux` run used this mode. The
backend sent the known-good activity close and next-activity start, then the
single `0x015a,0x0102` batch. Its world connection closed immediately after
that send, and the player saw DELTA C-0-1302. The debugger log does not show
a native game crash. This strongly implicates the new frame or its missing
context as a session-rejection trigger; it does **not** prove that `0x015a`
means dialogue. The opt-in mode should be omitted in the next gameplay run.
