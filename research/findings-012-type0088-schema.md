# Finding 012: type 0x0088 structural schema

Date: 2026-09-23

Evidence:

- `evidence/20260923-120647-type0088-nested-linux`
- `evidence/20260923-122837-type0088-forward-linux`

## Result

Inbound type `0x0088` now has a complete structural decoder and encoder in
`src/isac_protocol/type0088.py`. The implementation round-trips all 24 bodies
from the focused field capture byte-identically. Those bodies range from 29 to
122 bytes after the already-consumed message type, cover both observed values
of the action-correlated equipped flag, and contain zero, three, or four child
rows.

The evidence supports describing `0x0088` as an equipment-state update. Exact
gameplay names for most individual fields remain unproven, so the codec uses
stable neutral names rather than speculative labels.

## Complete parser boundary

The nested parser begins at RVA `0x0c47de0`. Windows unwind metadata describes
only its first region through `0x0c47fac`, although execution continues into
adjacent unwind regions. A fixed runtime code snapshot captured
`0x0c47de0`–`0x0c485e0`. The logical function returns at `0x0c4830e`; bytes
after that point belong to separate functions.

The wrapper at RVA `0x0eb5710` reads:

1. one ZigZag signed 32-bit value;
2. one unsigned variable-length byte, correlated as equipped/active;
3. one compact reference; and
4. the nested item structure below.

The nested item contains 22 fixed fields when its two collection counts and
two trailing fields are included. Together with the three wrapper fields,
this accounts for the previously observed 25 base reads.

```text
type_0088
  signed32
  equipped: varuint8
  owner: compact_reference
  item
    compact_reference × 2
    signed32
    varuint8 × 2
    signed32 × 6
    varuint8
    signed32 × 3
    compact_reference × 2
    packed_flags: varuint8
    child_count: signed32
    child[child_count]
    auxiliary_count: signed32
    auxiliary[auxiliary_count]
    trailing_varuint8
    trailing_signed32
```

Each child has 19 fixed reads. It also contains an optional subitem list:

```text
child
  compact_reference × 2
  signed32
  varuint8 × 2
  signed32 × 6
  varuint8
  signed32 × 3
  compact_reference
  subitem_count: signed32
  subitem[subitem_count]
  varuint8
  packed_flags: varuint8

subitem / auxiliary
  compact_reference
  float32 little-endian
  varuint8
```

All observed child subitem counts and auxiliary counts were zero. Their shapes
come directly from the complete parser code and are exercised with synthetic
round-trip tests, but still need a live nonzero sample for behavioral
validation.

## Primitive encodings

- Signed 32-bit values use unsigned base-128 varints after ZigZag mapping.
- Byte values use unsigned base-128 varints with an eight-bit result bound.
- Float32 values are little-endian. The codec retains their raw bits so NaN
  payloads and signed zero can round-trip exactly.
- Packed flag bytes are retained whole. The client currently expands five low
  bits into separate object fields.

The compact-reference reader at RVA `0x0f7f5f0` behaves as follows:

- without a reference-table object, it reads a raw 16-byte identifier;
- with a table, it reads an unsigned token, using `token >> 1` as the index;
- an existing index copies the table entry, and an odd token consumes an
  additional 16-byte side value;
- an out-of-range index reads a raw 16-byte identifier and appends it to the
  table.

The codec implements that state transition. It also has an explicit
`assume_existing` mode for mid-session captures whose bootstrap table is not
available. That mode preserves tokens and side values but intentionally leaves
their identifiers unresolved.

## Validation

Run the evidence validator without printing payload contents:

```bash
./tools/validate-type0088.py \
  evidence/20260923-120647-type0088-nested-linux/project-isac-dispatch-probe.log
```

The validation result is 24 reconstructed bodies and 24 byte-identical
decode/encode round trips. Unit tests additionally cover both list branches,
the child subitem branch, arbitrary counts, bit-exact float32 handling,
reference-table insertion/reuse, and odd-token side values.

## Remaining boundary

This completes the message's structural codec, not its session semantics. A
future local server must reproduce the bootstrap reference table and the
surrounding session state before a retail client can resolve and accept a
synthetically generated `0x0088` update.
