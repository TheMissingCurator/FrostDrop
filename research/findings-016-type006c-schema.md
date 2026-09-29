# Finding 016: type `0x006c` presence-mask schema

Date: 2026-09-23

Evidence: `evidence/20260923-164825-schema-miner-wide-3-linux`

## Result

Type `0x006c` is a presence-mask-driven state message, not a fixed structure
with an unexplained three-byte prefix. Its codec in
`src/isac_protocol/type006c.py` decodes and byte-identically re-encodes all 179
complete captured bodies.

Every message begins with:

```text
uint64-varint presence_mask
uint8         identifier_kind
uint8         identifier_length
bytes         identifier_value[identifier_length]
```

All observed identifiers used kind `2` and contained 36 bytes formatted as a
textual UUID. The codec retains bytes rather than assuming text or UUID
semantics.

The client deserializer defines optional fields through at least mask bit 50.
This capture exercised nine bits:

```text
bit 2   vec3f
bit 12  uint8 count + compact_reference[count]
bit 16  uint16 varint
bit 17  uint8 varint
bit 26  compact_reference
bit 28  float32 x 3
bit 29  float32 x 3
bit 32  bool
bit 35  bool
```

The complete static deserializer does not process every field in numerical bit
order. The codec follows the client control-flow order exactly.

## Captured mask families

```text
bits=2       length=51 bodies=170
bits=12      length=43 bodies=1
bits=12      length=44 bodies=1
bits=17      length=42 bodies=2
bits=26      length=43 bodies=1
bits=28,29   length=67 bodies=1
bits=32      length=44 bodies=1
bits=26,32   length=46 bodies=1
bits=2,16,35 length=59 bodies=1
```

The two bit-12 lengths result from different compact-reference token widths,
not different schemas.

## Interpretation boundary

The dominant form is an identifier plus a 3D vector and occurred 170 times
during active gameplay. This strongly suggests a frequently streamed
entity/world-state update, potentially position-related. That is an inference
from shape and frequency; no controlled event test yet proves the message's
gameplay meaning.

The static deserializer exposes many additional mask bits that this capture did
not exercise, including strings, vectors, references, integers, booleans,
bitsets, and a nested structure. The current codec deliberately rejects those
unobserved bits. This prevents an unknown variant from being accepted with the
wrong cursor layout while still covering 100 percent of present evidence.

## Reproduction

```bash
./tools/validate-type006c.py \
  evidence/20260923-164825-schema-miner-wide-3-linux/project-isac-dispatch-probe.log
```

The validator prints aggregate mask/length counts without message bodies or
identifier values.
