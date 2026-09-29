# Finding 128: 0x000c appearance lineage and intro-tutorial boundary

Date: 2026-09-27. Offline analysis only. No game installation, retail
account, local profile database or backend response was modified. Payloads,
character IDs and appearance values remain private.

## Static mapping and wire schema

The verified runtime text/rdata snapshots contain a 450-entry initializer
pointer table at rdata RVA `0x2907c98`. The type-ID initializer for captured
ordinal `0x000c` writes global `0x4688318`; its getter at `0x17d7330`
appears at vtable `0x3198ce8` slot `+0x18`. That vtable's writer slot `+0x30`
is `0x18a6920` (delegates to `0x18a3b90`), and reader slot `+0x38` is
`0x1791a50` (delegates to `0x178dd10`). The reader independently confirms
the field sequence and a maximum of 32 float values. Known 0x014d and
0x0157 mappings validate this ordinal approach for the captured build;
runtime randomized type IDs or a different build would require remapping.

The sole 147-byte retail world-channel `0x000c` from
`20260927-064853-retail-tutorial-x3s3v01n` decodes exactly as:

| Wire field | Observed shape |
| --- | --- |
| Raw character ID | 16 bytes; equals the newly created character ID |
| Branch flag | zero |
| Float collection count | 32 |
| Float values | 32 little-endian float32 values, all finite |
| Final flag | one; business meaning not recovered |

The alternate branch and shorter float collections allowed by client code
are not observed and are deliberately unsupported by the new codec. The
observed branch round-trips byte-for-byte. The local test client's 147-byte
`0x000c` has **the same 131 non-ID bytes** as this retail request. Thus the
local client is already sending a structurally valid observed submission;
the missing local persistence is not explained by a different payload in
that test.

## Profile data lineage

The exact retail character ID from that tutorial request appears in the
later connected profile list of `20260927-195420-retail-finalization-96i4fgh9`
as a customized 1261-byte version-8 record. The record's **32 float-slot bit
patterns exactly equal** the 32 float values in the earlier `0x000c` request.
This is bit-for-bit cross-capture correspondence for the same character. It
strongly supports `0x000c` as an appearance
submission. It does not prove that this is the only server operation required
to finalize the slot, nor explain the record's 18 additional node structures.

The existing local `ProfileStore` persists only unfinished 161-byte records;
its world `0x000c` path sends an experimental response but does not update
that store. This is a concrete local implementation gap. Turning the request
into a durable customized profile should wait until the 18-node record's
normal inputs and ownership are understood, or be labeled an explicitly
capture-derived experiment.

## Immediate tutorial window

In the same retail tutorial capture, `0x000c` occurs 15.509 seconds before
the first human objective-start marker and 95.485 seconds before the first
safe-house marker. Six start and six completion markers, plus two AI markers,
precede that safe-house entry. Those markers describe substeps of the
unrewarded movement/shooting tutorial, not six missions. The capture contains
their raw world traffic, but this analysis does not yet identify a unique
objective-state message or AI-spawn schema.

A 95-second intro/post-safe-house count comparison does not isolate an
intro-only client message: outbound `0x0003`, `0x000a` and `0x001c` occur on
both sides of the boundary. `0x000a` is one raw 16-byte reference according
to static writer `0x18a9030`, appears 28 times overall, and its bodies do not
equal the created character ID. Message-type presence alone therefore cannot
label tutorial objective changes; the reference targets and receiving client
state need tracing.

One 28-byte inbound `0x015a` arrives 103 ms after `0x000c`. Static mapping
places its reader at `0x178cd30`. However, 0x015a occurs 117 times with many
body lengths in the capture and has not been decoded; proximity alone does
not make that frame a finalization acknowledgment.

`tools/map-retail-message-type.py` now performs this build-specific static
mapping for other captured message types. The `0x000c` observed-shape codec
is registered for client-to-server messages and covered by synthetic and
private round-trip/lineage tests. Neither change alters runtime responses.
