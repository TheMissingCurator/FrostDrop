# Generated game-connect reply and complete observed world-start shape

Date: 2026-09-27. Backend Python and offline codec changes. No new capture,
game execution, DLL rebuild, prefix modification or launch-option change.

## Implemented backend change

After a valid local instance admission, `ServerListSession` now sends the
game-service type 2 response: a locally generated 16-byte identifier followed
by boolean false. Previously this handler recorded admission without replying.
The log milestone is `instance-connect-reply-sent-world-pending`.

The identifier is a UUID generated per local route, retained across a channel
reconnect during that route's lifetime. It is not copied from retail evidence
and is not the character ID. This is a local policy choice; the identifier's
wider semantics are not established. Token, parent-session, character-expiry,
duplicate and conflicting-request checks remain in place. As before, the
second token slot authorizes admission; the first/third presented auth blobs
are not independently validated. Response construction precedes admission
commit. Duplicate requests do not produce extra acknowledgments.

### Client evidence for the boolean

Addresses are RVAs in the verified saved text snapshot from finding 118.
Reader **0x22556c0** reads raw 16 bytes through 0x223d640, then a boolean.
Its call at **0x9e70d** belongs to consumer **0x9e690**:

- The parsed boolean is checked at **0x9eb7a**.
- True takes **0x9ecb9**, closes the channel via vtable +0x30, writes state
  +0x58 = 3, and calls back with R8D = 3 and R9 = null.
- False takes **0x9ecdb**, transfers the channel at +0x70 and clears its old
  owner. At **0x9ee28**, state +0x58 becomes 0; the callback at **0x9ee3d**
  receives R8D = 0 and R9 = the channel.

Thus false means connection acceptance, **not world readiness**. The 16-byte
member is not consumed by the examined success path. It must not be confused
with the control-service type 2 schema; the new codec is namespace-specific.

## Complete 0x0007 codec for the observed shape

`isac_protocol/world_start.py` serializes typed fields only. It neither reads
capture files nor copies opaque tail bytes. The codec is separate from the
default registry because nonempty dynamically typed groups remain unsupported.

The final 146 bytes previously excluded in finding 119 are now accounted for:

| Tutorial wire boundary | Structure | Captured shape |
| --- | --- | --- |
| 8304–8433 | +710 uint8-counted uint8/float rows | 24 rows |
| 8433–8434 | +720 sint32-counted reference/child groups | Empty |
| 8434–8435 | +730 sint32-counted reference/float rows | Empty |
| 8435–8436 | +740 uint32 group count | Six |
| 8436–8448 | Each group: uint32 subobject count, sint8 | All counts zero, signed values -1 |
| 8448–8449 | +750 sint8 | -1 |
| 8449–8450 | +758 uint16-counted references | Empty |

Reader 0xc49ba0 supplies +710/+720/+730. A +720 group's child count comes
**before** its reference. Each child is reference, uint8, boolean, and a
float only when the boolean is false. Reader 0xeb7ee0 supplies +740; nonzero
subobject counts would delegate by runtime discriminator to 0xfe7b60. The
codec rejects that variant explicitly, without committing dictionary changes.

All three existing initial snapshots decode and re-encode exactly, including
resulting dictionary state: tutorial **8,450**, first gate **11,179**, stable
hub **11,666** bytes. Every captured dynamic group is empty. This establishes
wire structure for these variants, not all gameplay semantics or all worlds.

The raw 16-byte member at parent **+0x4f0** equals the successful create-profile
identifier in the tutorial evidence. It differs from the connect identifier
and the startup's first compact reference (+0x20). This corrects the earlier
tentative bitset interpretation and grounds one character-binding field.
No private identifier values are printed or embedded in backend defaults.

## Deliberate remaining boundary

The backend sends **only the generated connection acceptance** in this change.
It does not send 0x014d or 0x0007, does not replay a retail snapshot, and does
not implement tutorial simulation. It still reports world=not-implemented.
The existing launcher picks up the Python change without a DLL rebuild.

The next required work is a semantic local-world model: identify the asset
references and required startup defaults, bind the local character, then
encode its dictionary and snapshot. Item structures, stat arrays, spawn
values and tagged fields cannot be assumed valid merely because they can be
encoded. An all-zero snapshot is not represented here as a usable world.
No new capture is required just to continue that analysis of existing data.

## Verification

- Synthetic codec tests exercise nested groups, both conditional-float paths,
  all supported fields, raw/compact references, strict rejection, and atomic
  dictionary handling; private regressions cover the three initial snapshots.
- Redacted tutorial analysis now exposes `type0007_complete_observed_shape`
  separately from the retained legacy prefix diagnostics. It validates all
  8,450 bytes with zero remaining and confirms the created-character binding.
- Admission tests cover generated replies, invalid/expired tokens, duplicate
  suppression, reconnect identity, and response-failure atomicity.
- The isolated transport integration test receives the generated reply through
  the real local backend, then verifies duplicate suppression and continued
  transport liveness. No game or Ubisoft connection is used by this test.

An actual game run has not validated this change yet; a playable world is
not an expected result of the connection acknowledgment alone.
