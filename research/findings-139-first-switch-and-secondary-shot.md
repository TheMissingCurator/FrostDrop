# Finding 139: first switch request and secondary-shot transition

Date: 2026-09-28. Sources: local capture
`20260928-161259-736732-sdk-adapter-linux` and the existing marked retail
tutorial capture `20260927-064853-retail-tutorial-x3s3v01n`. Both are private
capture artifacts; no identities or payload bytes are published here.

The opt-in weapon gate observer saw one positive
`PreventWeaponSwitchingRefCount` value and cleared it after the local shooting
stage. The client then sent nine `0x0088` equipment requests. The first was a
108-byte request for the expected local item. The stage handler, however,
required exactly 105 bytes, so it did not answer this first request. It
answered a later 105-byte request instead. The 105-byte length came from the
retail example; it was not a general constraint of the decoded `0x0088`
schema. The handler now accepts either observed size and still validates the
owner and item lineage against the local world startup before replying.

After switching, the local client sent a secondary-shot `0x006a` with header
counter 14, scalar 36, and three children. Its item and asset references
matched the local secondary equipment item. The backend previously ignored
all `0x006a` after the first three primary shots. In retail, a secondary shot
with counter 14 and scalar 36 precedes an inbound compact `0x006a` and the
five-row `0x00e6` state `(0,4,4,4,4)`. The local handler now recognizes only
that bounded first-secondary-shot shape, echoes it, and sends the matching
final-row state update. It does not synthesize the later retail activity-close
message, rewards, or a general firing loop.

An offline regression test reconstructs the first 108-byte local switch and
the first local secondary shot with fresh local character/item bindings. It
checks acceptance on the first switch, dictionary-consistent shot echo, final
row state, and duplicate suppression. The full suite ran 542 tests with 18
skipped and no failures. Client acceptance and objective presentation remain
to be verified in the next opt-in game run.
