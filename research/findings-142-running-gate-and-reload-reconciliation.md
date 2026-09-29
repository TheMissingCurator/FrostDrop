# Finding 142: local running gate and retail reload reconciliation

Date: 2026-09-28. Local source: `20260928-202810-687709-sdk-adapter-linux`.
Retail source: marked tutorial capture
`20260927-064853-retail-tutorial-x3s3v01n`. Private identifiers and message
bodies are omitted. This investigation did not modify backend responses.

## Running gate

The local debugger sampled the same player owner after the shooting stage:
`PreventRunningRefCount=1`, while sprinting, cover-to-cover, cover, and
exit-cover prevention counts were all zero. The previous capture sampled
`PreventSprintingRefCount=0` again after the activity close; this latest run
did not reach a post-close weapon-gate debugger stop, so its running count
was not directly measured after close. The user reports that sprint remained
blocked. Static client code at RVA `0x16742c5` checks the running-prevention
getter (`0xd16710`) and at `0x16742e9` checks sprint prevention
(`0xd172c0`) before passing the results to movement handler `0x16765f0`.
Running count one is therefore a concrete candidate, not yet a proven sole
cause of sprint/vault/cover-to-cover failure.

An opt-in one-shot local diagnostic now clears an exactly-one running count
only after the backend writes the Agent Activation close marker, on the same
owner whose weapon-switch count was earlier cleared, and only when the
existing weapon-gate breakpoint fires again. It does not alter any other
movement count or backend reply. The user must trigger a weapon-switch check
after mission completion; look for `ISAC_RUNNING_GATE_OVERRIDE applied=1`.
Whether this restores sprint or other traversal remains to be tested.

## Reload boundary

The local world stream contains reload-shaped outbound `0x006a` messages
with zero children: primary `(counter=32, reserve-like scalar=892, children=0)`
and secondary `(15,4,0)` followed later by `(15,12,0)`. The current backend
only answers the bounded Agent Activation shot sequence; after its final shot
it treats subsequent `0x006a` messages as duplicates and sends no response.
The scalar is correlated with ammunition but not independently named by a
client consumer trace.

In the retail capture, four post-tutorial `0x006a` messages with
`counter=32, children=0` are each followed within 59 to 102 ms by **three**
inbound nine-byte `0x0094` messages. The preceding reserve-like scalar values
are 881, 852, 820, and 796. Static reader RVA `0x1042020` gives `0x0094` the
layout: signed32, two compact references, signed64, boolean, unsigned8.
All twelve frames at these four reload boundaries parse exactly. In each
triplet the fields are `(0, character, shared reference, reserve, false, 14)`,
then the same with `reserve+32`, then `reserve` again. The shared reference is
capture-local dictionary index 673 and is not identical to either raw
`0x006a` item/type reference. This strongly suggests ammunition/resource
reconciliation, but the exact business meaning and local reference lineage
are not yet proven. The local backend sends no `0x0094` frames. Do not replay
the retail triplet blindly; first identify the local corresponding reference
and client-side consumer, and check whether `PreventFiringRefCount` remains
positive during the player's post-reload pause.
