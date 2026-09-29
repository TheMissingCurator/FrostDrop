# World-start fixed block and core-tail reader

Date: 2026-09-27. Offline static tracing and decoder changes only. No new
probe, game modification, launch-option change or backend response change.

Follow-up: [finding 120](findings-120-generated-connect-and-complete-startup-shape.md)
completes the remaining 146 bytes for the observed empty-subobject shape,
identifies the fixed block's equality to the created character ID, and adds
a generated backend connection acknowledgment. The partial status below
records the earlier investigation, not the current codec coverage.

## Outcome and correction

The field previously tentatively called a bitset has a **constant 16-byte
wire width**, not a variable bit count. Its purpose is not yet established;
the decoder names it `fixed_bytes_4f0`, not gameplay flags or an identifier.
Followed the rest of the core reader from this boundary and extended the
partial 0x0007 decoder from **5,920 to 8,304 bytes** of the tutorial's
8,450-byte body. **146 bytes remain outside the core.**

The new 2,384-byte core component round-trips byte-for-byte, including
reference-table mutations, against the tutorial capture. The same layout
also succeeds on two older world-start captures with different body sizes:

| Private capture | Body bytes | Decoded prefix bytes | Remaining | New core component round-trip |
| --- | ---: | ---: | ---: | --- |
| Tutorial 20260927-064853 | 8,450 | 8,304 | 146 | Exact |
| First gate 20260925 | 11,179 | 11,033 | 146 | Exact |
| Stable hub 20260925 | 11,666 | 11,520 | 146 | Exact |

This is structural coverage of this message, not a percentage of backend or
playable-world completion. Values and their consumers still need semantic
identification. Capture/observer limitations from finding 118 remain.

## Exact size and read lineage

All addresses are RVAs in the saved verified text snapshot from finding 118.
The top-level reader 0xeb63d0 calls core reader 0x1161090 on parent +0x20;
therefore add 0x20 to core-relative offsets when labeling message fields.

After the reference at core +0x4c0 / parent +0x4e0:

1. At 0x1161366, RCX receives core +0x4d0 / parent +0x4f0.
2. Call at 0x116136d goes to **0x12ae0**, whose entire body is
   `mov eax,0x10; ret`. No field, configuration, table or constructor is
   consulted to compute the size in this build.
3. Call at 0x116137b goes to **0x129d0**, whose body is
   `mov rax,rcx; ret`. The destination is the object member itself.
4. At 0x1161389, **0x223d5d0** receives R8D = 16 and reads exactly that many
   raw bytes through the source's vtable +0x18 method. It compares returned
   byte count to requested count; the core reader rejects short reads.

There is no wire length prefix and no bits-to-bytes conversion here.
Observed nonzero bytes alone do not prove bitset semantics. The allocation
branches later in the function use high bits of container capacity fields
as inline-storage/ownership flags; those are **client memory metadata, not
additional wire flags**. Do not transcribe those branches into a schema.

## Following tagged text

Next is core +0x4e0 / parent +0x500, read by **0x64e50**:

- uint8-varint tag;
- uint8-varint byte length, maximum **61**;
- that many raw bytes (the client adds a terminator locally, not on the wire).

`0xbc7e0` validates nonempty data according to the tag's low nibble through
`0xaa680`. Valid low-nibble kinds are 0–5. Kinds 0/1/5 require signed bytes
at least 0x20; kind 2 permits lowercase ASCII letters/digits/hyphens; kind 3
permits digits; kind 4 permits 3–16 ASCII letters/digits/hyphens/underscores.
Empty data bypasses the kind check. The captured field has tag 2 and length
36; its text remains private, and no identifier meaning is assigned from
length/character class alone.

## Counted collections after the fixed block

The following recovered collections use sint32-varint counts. The decoder
applies explicit nonnegative counts and safety bounds. Offsets below are
parent-relative memory offsets, **not positions in the wire body**.

| Offset | Row schema | Tutorial count |
| --- | --- | ---: |
| +540 | compact reference | 0 |
| +550 | float32 | 27 |
| +560 | compact reference, three booleans | 1 |
| +570 | two compact references | 3 |
| +580 | compact reference (nested +570 second collection) | 0 |
| +590 | compact reference | 0 |
| +5a0 | compact reference, sint32 | 0 |
| +5b0 | compact reference, sint32, boolean | 0 |
| +5c0 | float32 | 3 |
| +5d0 | float32 | 3 |
| +5e0 | compact reference, sint32 | 12 |
| +5f0/+600/+610/+620 | compact references in four distinct lists | 0/0/6/6 |
| +630 | compact reference, uint8-varint | 0 |
| +640/+650 | compact references in two distinct lists | 0/0 |
| +660 | uint32-length-prefixed bytes | 37 |

Nested reader **0xc48440** handles the +570/+580 paired-reference/reference
collections. The remaining lists are read inline by 0x1161090. Byte strings
use helper 0x223ce30 with maximum 0xfffd and a length+1 check, making their
maximum payload **65,532** bytes. They are stored as opaque bytes in the
analysis model; contents are neither printed nor replayed.

Following the lists, recovered the exact interleaved scalar wire order,
including six booleans, sint64 values, float pairs, sint32 pairs, two compact
references, uint32 values, five booleans, two further counted byte-string
collections, and final numeric/boolean fields through parent +0x70c.
The neutral model records memory-offset names rather than assigning mission,
position, XP or world-ready semantics to those fields.

Float helper 0x223d5f0 invokes **0x1d4b0**, whose predicate is stricter than
finiteness: after removing the sign bit it rejects bit magnitudes 1 through
0x007fffff and >=0x7f000000. The new core-tail decoder/encoder reproduces
that check, retaining exact accepted float32 bits, including negative zero.

## Remaining top-level 146 bytes and next seam

The core reader returns at 0x11625df. Top-level **0xeb63d0** then processes:

1. Parent +0x710 through **0xc49ba0**. Static tracing shows a uint8-counted
   list of uint8/float rows, followed by sint32-counted nested reference
   groups (child reference, uint8, boolean, float only when boolean false),
   followed by a sint32-counted reference/float list.
2. Parent +0x740: uint32-counted groups through **0xeb7ee0**. Each group
   begins with a uint32 subobject count; nonempty groups read a sint32
   runtime type discriminator and delegate to **0xfe7b60**. Each group
   ends with a sint8-varint field.
3. Parent +0x750 sint8-varint, then parent +0x758 uint16-counted references.

A diagnostic parse of this tutorial's top-level +710 structure has 24
uint8/float rows, zero nested groups and zero final reference/float rows,
reaching wire offset 8,435. Reading the +740 group count gives six and
reaches 8,436, leaving 14 bytes. The decoder currently stops earlier, at
8,304, because these top-level structures and dynamic subobjects are not
implemented as validated codecs yet. This note does not claim those
remaining 14 bytes are decoded or that all six groups are empty.

Next: implement and test the +710 reader, inspect the six group bodies,
and follow 0xfe7b60's runtime type dispatch if any group is nonempty. No
length guessing, opaque-tail replay or invented world-ready response.

## Implementation and verification

`src/isac_protocol/world_messages.py` now exposes a neutral core-tail
component model and encoder and extends the partial prefix reader. Prefix
decoding still uses a cloned session dictionary and does not commit it.
Its component round-trip witness compares both bytes and resulting table
state. **Type 0x0007 remains unregistered as a complete codec**; the backend
still has no generated world-start response.

`tools/decode-retail-world.py` reports the fixed width, tagged-text length,
collection counts, exact component round-trip and remaining byte count,
without printing raw identifiers, text, tokens or payloads.

Tests cover every recovered list kind, raw and compact references, sint64
limits, string bounds and client tag rules, strict float validation, fixed
sequence sizes, truncation, invalid collection counts and transactional
encoding. Private regressions verify the tutorial's 5,920/8,304 boundaries
and the static size/pointer helper signatures when local evidence exists.
Separate synthetic analyzer tests check redaction, duplicated annotations,
actual repeated world requests and incomplete framing.

The user also identifies the completed tutorial mission as Retrieve Food
Supplies ("food drive"); this supplies the mission context missing from
finding 118's numeric XP/credits inference. It is a user annotation, not a
decoded mission-ID mapping.
