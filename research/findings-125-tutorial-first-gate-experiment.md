# Finding 125: local 0x0009 first-gate experiment

Date: 2026-09-27. The custom run `20260927-181450-073440-sdk-adapter-linux`
reached the intro cinematic and then sent world-channel type 0x0009 with a
16-byte body. The backend observed it without replying. No game run has yet
tested the continuation implementation described below.

## Retail correlation

The existing tutorial capture `20260927-064853-retail-tutorial-x3s3v01n`
contains one outbound type 0x0009 with a 16-byte body equal to that capture's
newly created character ID, not the game-connect reply ID. It occurs 13,495 ms
after 0x0007. The large server burst begins 122 ms later, and the first
0x0012 state update arrives 124 ms after 0x0009. This is strong ordering and
identity evidence, not proof that 0x0009 alone causes every later message.

The bounded slice from after 0x0009 through first 0x0012 and following 0x0102
flush contains 322 frames, 18,309 body bytes and 43 distinct type IDs.
The typed startup's 341 unique references have exactly the same order as the
retail pre-0x0007 dictionary. All 143 continuation 0x014d updates decoded and
round-tripped against that initial table without an unresolved index. Known
created-character and account occurrences each appear twice outside 0x014d;
the captured display name also appears twice. The preparer requires those
counts and replaces them before writing its owner-only private artifact.
Unclassified values and unknown message schemas remain capture-derived.

The immediate retail 0x00dd following 0x0007 is three bytes and identical in
the tutorial, first-gate hub and stable-hub captures. Static reader RVA
0xeb6310 calls 0x1161040, which reads signed32 then unsigned32 varints; the
observed values are 4634 and 0. The local typed startup now emits this
capture-derived pair. Its business meaning is not established.

## Implementation boundary

The existing `custom --world-startup` path freezes both private templates.
After a valid local instance admission, type 0x0009 must equal the selected
local character ID. Only then does the backend rebind the private continuation
to the authenticated local character/account/display name, verify its 0x014d
updates against the local seed, and send the first-gate frames in captured
order. Duplicates on the same channel do not resend. Wrong IDs, unsupported
display-name field shapes, malformed artifacts and oversized output fail
closed. The two observed name fields carry one-byte length prefixes; those
prefixes are adjusted for the local SDK's longer `ProjectISAC` name.
No retail network route, live-server fallback or world-ready assertion is
introduced. The first captured 0x0012 is not continuing state simulation.

Unit tests cover the real private artifact's rebinding and a synthetic
character handoff. The isolated synthetic-client transport test exercises
0x0009 through the actual local TLS/compressed backend. None of these proves
the game accepts the 322-frame burst or starts the in-game scene; that needs
the next custom game run.
