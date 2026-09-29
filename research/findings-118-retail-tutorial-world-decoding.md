# Tutorial dictionary, world prefix and completion rewards

Date: 2026-09-27. Offline decoding only; game files, capture installation and
backend responses are unchanged. No runtime replay response has been added.

Follow-up: [finding 119](findings-119-world-core-fixed-block-and-tail.md)
establishes a constant 16-byte block (bitset semantics remain unproven) and
extends the decoded prefix to 8,304 bytes, leaving 146. The 5,920-byte
boundary below records this finding's original stopping point.

## Evidence and boundaries

Analyzed the gameplay file from `20260927-064853-retail-tutorial-x3s3v01n`.
It contains 63,745 inbound frames, no pending framing bytes, and an initial
connect reply matching the separately reconstructed parsed reply. This does
not establish exhaustive observer coverage: an end record is absent and the
last thread-arming report has 32 failures. Unknown message bodies remain
private and undecoded. No raw payloads, identifiers or captured names are
included in this report or the analyzer's output.

There are 41 numpad markers: world 2, objective start 13, objective completion
18, AI 5, safe house 2, merchant 1. The two world annotations are 43.130 seconds
apart; they are not evidence of two world requests. The user reports one
completed tutorial side mission, not 18 completed missions. The immediately
preceding movement/shooting tutorial begins just after character creation,
before the safe house or merchant, and gives no reward. It must not be
identified with either reward-shaped message below.

## Static reader identification

Used the existing verified runtime text snapshot, SHA256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.
Its offset zero corresponds to RVA `0x1000`. Static rdata has a 16-byte
`ISACRD01` header; its data begins at RVA `0x2901000`.

The CRT initializer pointer sequence contains 450 initializer functions
of the form `lea rcx,<type-id-global>; jmp 0x1160b60`. Corroborated ordinal
assignments against previously observed runtime mappings, then followed
the ID global's getter to its containing vtable and reader slot. This helped
locate readers absent from the older pre-world runtime trace. Ordinals must
not be assumed portable: the initialization helper has an optional randomized
9-bit assignment path, and different builds can change ordering.

| Type | Vtable RVA | Reader RVA | Result |
| --- | --- | --- | --- |
| `0x014d` | `0x319c258` | `0x17939e0` | Complete dictionary seeding/update |
| `0x0007` | `0x30e7228` | `0xeb63d0` | Partial world-start structure |
| `0x0157` | `0x31988c8` | `0xc4a690` | Complete reward-shaped structure |
| `0x0167` | `0x31a06e8` | `0x1795550` | Complete single compact reference |
| `0x00e8` | `0x319bca8` | `0x1793680` | Complete small mixed-field structure |

## Identifier dictionary: 0x014d

Reader `0x17939e0..0x1793a53` reads a uint32 varint count, then that many
compact references through `0xf7f5f0`. The output temporary is reused rather
than retained as a message array; the important effect is populating the
session reference table. A compact token's index is `token >> 1`. Existing
indices resolve to stored 16-byte identifiers; odd existing tokens also carry
a discarded 16-byte side value. New entries read 16 bytes and append.

All 716 messages round-trip byte-for-byte with matching resulting table state.
The first contains 341 rows and arrives 878 ms after the world request. Across
this capture there are 2,271 seed rows and 2,271 resulting dictionary entries;
every newly seeded index is sequential. This supports resolving references
in the known schemas here. It does not prove that every unknown message's
dictionary side effects are understood. Midstream captures without bootstrap
still require unresolved-reference mode.

## World startup: partial 0x0007

The first message body is 8,450 bytes, at request +879 ms. Its top-level reader
calls the large core reader `0x1161090`, with core base at parent `+0x20`.
The recovered prefix consumes **5,920 bytes**, leaving **2,530 bytes** unknown.

Recovered wire order, using parent-relative memory offsets as neutral names:

1. `+20` reference, `+30` uint32, `+34` sint32, `+38` sint8.
2. Three arrays of ten sint32 at `+3c/+64/+8c`.
3. Nine fixed rows at `+b4`, through `0xebca80`: six sint32, six float32,
   two booleans each; memory stride `0x34`.
4. Sint32 `+288/+28c`, vec3f `+290`, float32 `+29c`, reference `+2a0`.
5. Bounded byte string `+2b0`, sint32 `+3b0`, bounded byte string `+3b8`,
   reference `+4b8`, boolean `+4c8`.
6. Sint32 collection count at `+4d0`: 199 captured records. Its elements use
   **the same `0xc47de0` item reader already recovered for 0x0088**.
7. Reference `+4e0`.

The two observed strings have lengths 9 and 7; their contents are not printed.
The first reference does not match the reconstructed created-character ID;
do not label it the character owner. Likewise, 199 item-shaped records are
not proof of 199 owned inventory items. Their business role remains unresolved.

Refactored the existing 0x0088 codec to expose cursor-level equipment-item
read/write helpers without changing that message's wrapper or wire schema.
The prefix reader operates on a cloned dictionary and **does not commit it**:
an unknown suffix could contain additional state. Type 0x0007 is deliberately
not registered as a complete codec and has no generated response encoder.

The next exact boundary is the bitset at parent `+4f0` (core `+4d0`), whose
wire width is supplied through the size calculation near `0x116135a`.
Resolve that width, then continue the existing core reader. This can proceed
from current static code and this capture; another broad probe is not required
merely to continue decoding this message.

## Completion reward: 0x0157

Reader `0xc4a690..0xc4b4f7` is fully recovered. It reads two references
separated by a uint8 field, followed by fourteen uint8-counted collections:
byte/sint pairs, reference/sint pairs, references, signed values, more
reference collections, mixed rows, and nested scalar/list rows. The mixed
row's six sint32 fields are read in memory-offset order `3c/24/28/20/30/2c`,
not numeric offset order. All field names in the structural model remain
neutral. Both captured bodies (30 and 42 bytes) round-trip exactly.

Both messages contain `(0,1500)` in `byte_signed_rows_48` and a value `35`
in `reference_signed_rows_58`. The first arrives at request +235,017 ms,
21.796 seconds after its nearest completion annotation; do not assign it
to a specific objective on timing alone.

The second arrives at request +338,920 ms, **2.219 seconds before final
completion marker 41**, and has one mixed row. In the same incoming chunk,
0x002a reports a +1,500 change for the reconstructed created character:
the same owner's same stat increases **126 -> 1,626**. That stat reference
equals 0x0157's first reference. The first reward reference is therefore
not simply the reward recipient/character ID.

External corroboration requested by the user: the [Restore Brooklyn wiki
reward tables](https://thedivision.fandom.com/wiki/Restore_Brooklyn), retrieved
through search on 2026-09-27, list **1,500 XP and 35 credits plus an item**
for Retrieve Food Supplies, Rescue Civilians, and Find Morphine Supply.
This matches **both** captured numeric rewards and the additional structured
row, giving high confidence that 1,500 is XP and 35 is credits in the
completion-time message. The wiki alone does not establish protocol field
semantics globally or resolve the item identifier. All three missions share
the numbers, so they do not identify which mission was completed. The earlier
0x0157 message's context also remains unassigned.

The user subsequently identified the completed side mission as Retrieve Food
Supplies ("food drive"). This is mission context supplied by the user;
the mission identifier has not yet been mapped from protocol fields. The
first reward-shaped message falls after the merchant marker, so it cannot be
the reward for the earlier movement/shooting tutorial. Its cause remains
unassigned.

## Other codecs and verification

0x0167 is one compact reference (9 exact round trips); no gameplay-event name
is assigned. 0x00e8 is bool, reference, sint32, uint8, bool, bounded bytes,
uint8 (2 exact round trips). Its observed reader byte-string bound is 65,532.

The analyzer also round-trips prior known types: 0020 (39), 0023 (337),
0024 (132), 002a (15), 002d (23), 0067 (75), 006c (548), 0088 (16),
019d (79). Fourteen 006c bodies have masks outside the existing codec's
supported observations; these are reported as unsupported, not silently
decoded. Early control 0002/0003/0006 codecs are excluded because their
namespace differs from world-connect traffic.

Run the redacted analysis with:

```sh
python3 tools/decode-retail-world.py evidence/20260927-064853-retail-tutorial-x3s3v01n
```

Synthetic tests cover dictionary sequencing/fragmentation, side values, raw
and midstream references, all reward collections, malformed/trailing input,
atomic table rollback, bounds, partial world parsing and shared item reuse.
Existing item, framing, registry, tutorial-observer and replay tests pass.
The optional actual-Proton observer fixture was not rerun for this offline
decoding change.

This is schema progress, **not yet a valid generated world state**, mission
implementation, AI spawn decoder or reward persistence implementation.
