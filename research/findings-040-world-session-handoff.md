# Finding 040: Continue starts a distinct world-session handoff

Date: 2026-09-25

## Evidence

The private type-`0x0003` replay was injected successfully and the matching
retail type-`0x0003` response on reader 1 was suppressed. The client continued
building its bootstrap channels without a reader-2 retry, proving the local
response cleared the first account-login gate.

The run contained only one outbound type-`0x0002` login request. Continue did
not send another account-login request. Its best causal selector was instead a
740-byte channel-0 envelope containing one type-`0x0000` frame with declared
length 734. A new reader appeared 99 milliseconds later, began with a complete
type-`0x0002` frame, and subsequently carried the large world stream. Inbound
type `0x0012` arrived roughly 16.15 seconds after the request.

Later apparent type-`0x0003` values on this reader were prefixes of arbitrary
transport chunks whose total delivery was much larger than the declared
frame. They are not valid evidence of additional login frames. The existing
delivery logger described chunk starts, not a persistent application stream.

## Implementation consequence

`ISAC_WORLD_BOOTSTRAP_PROBE=1` now performs two bounded diagnostics after a
successful local login injection:

1. captures the first matching large channel-0 type-`0x0000` envelope to a
   private, create-once file outside normal evidence; and
2. selects the first post-request reader, synchronizes on its initial complete
   type-`0x0002` frame, and reassembles frame boundaries across all later
   chunks while logging metadata only.

The first milestone remains local login, local character selection, a captured
static world snapshot, and standing/walking without a retail session. The
probe does not suppress the retail world stream yet because doing so before a
replacement exists would only force an infinite load.
