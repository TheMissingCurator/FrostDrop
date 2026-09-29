# Finding 049: outbound writer fanout defeats pointer-scoped isolation

Date: 2026-09-25

The first stationary outbound-isolation run did not clear the safety gate. It
replayed the world corpus and suppressed 1,182 retail inbound deliveries, but
the plaintext probe observed 774 valid outbound envelopes across 41 writer
object IDs. Only five envelopes, all from writer stream 1, were suppressed.
The packet capture retained sustained application traffic on both retail
port-55000 flows.

The writer argument at serializer handoff RVA `0x00d6bbf` is constructed from
a stack slot (`lea rdx,[rsp+0x20]`). Its pointer therefore identifies a
temporary per-call/per-thread writer, not a logical backend stream. Pinning the
writer that carried login merely selected one recurring stack address and let
the other producer threads continue to retail.

The bridge still uses the first structurally valid type-`0x0002` envelope as
its activation proof. After activation, however, it now copies every complete
Division envelope whose marker and nested lengths validate. Once replay arms,
the same validated set is suppressed at the verified transport call, except
for the single initial world request whose retail delivery is still required
to discover the inbound reader/source pair. Unrelated calls and malformed
buffers at the boundary remain untouched.

The replacement build must repeat the stationary safety run. A valid result
requires broad `WORLD_REPLAY_OUTBOUND_SUPPRESSED` progress, no outbound or
inbound isolation errors, successful world replay, and no sustained post-arm
application payload on the retail port-55000 flows. Movement remains outside
the test scope until those conditions hold.

## Replacement-run result

The `outbound-isolation-all-envelopes` run reached the replay gate without an
injection, isolation, bridge-drop, or disconnect error. The plaintext probe
observed 827 valid envelopes after the replay arm across 38 writer IDs; all
meet the new suppression predicate. This intentionally produced hundreds of
local server event lines, because the local backend now receives the complete
outbound envelope fanout instead of five records from one recurring stack
slot.

The main retail world flow fell from 570 outbound payload packets and 42,278
bytes in the pointer-scoped run to 18 packets and 1,876 bytes for the whole
connection, including its handshake, setup, and the deliberately retained
world request. Small post-arm retail writes remain visible through the wire
audit, with no time-local match to the suppressed application envelopes. They
therefore require a labeled stationary-versus-movement comparison before the
wire path can be classified as transport control rather than a second state
path. The broad application serializer leak itself is closed.
