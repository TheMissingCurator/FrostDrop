# Finding 018: early-control message schemas `0x0002` and `0x0006`

Date: 2026-09-23

Evidence:

- `evidence/20260923-224608-control-types-0002-0006-linux`
- `evidence/20260923-225213-control-decoder-bodies-linux`
- `evidence/20260923-225611-control-schema-code-linux`
- `evidence/20260923-230215-control-nested-schemas-linux`
- `evidence/20260923-230806-control-schema-closure-linux`
- `evidence/20260923-231219-control-final-closure-linux`

## Result

The early server-control types `0x0002` and `0x0006` now have structural
decoders and encoders in `src/isac_protocol/control_messages.py`. They are
registered as server-to-client messages in the central codec registry.

The schemas come from complete runtime snapshots of their generated readers
and nested callees. The control probe intentionally redacts these message
bodies because they may carry account or session metadata. Consequently, the
codecs have comprehensive synthetic branch and boundary tests but have not yet
been byte-for-byte validated against live bodies.

## Type `0x0006`

The reader at RVA `0x2257c10` establishes this grammar:

```text
uint32-varint request_id
uint8-varint  presence
if presence != 0:
  uint32-varint length (< 64)
  byte[length] bytes_0
  control_identity identity
```

`control_identity`, shared with `0x0002`, is:

```text
uint8-varint byte_0
uint8-varint length (<= 61)
byte[length] value
```

The code retains `presence` as an integer because the client branches on
zero/nonzero and does not require the canonical Boolean values zero or one.

## Type `0x0002`

The main reader is rooted at RVA `0x2257cc0` and delegates to `0x651d0`:

```text
uint32-varint request_id

either stop here (short acknowledgement variant)

or:
  control_identity identity
  uint32-varint flags
  if flags & 1:
    uint64-varint length (<= 1024)
    byte[length] embedded_0
  if flags & 2:
    metadata
```

The short variant was observed as a two-byte complete frame in the final
capture. The full variant was observed at 136 and 156 bytes. The embedded
object is retained as opaque bytes: the outer wire boundary is fully known,
while the client parses its legacy inner serialization separately at RVA
`0x63860`.

The optional metadata reader at RVA `0x64800` consumes, in order:

```text
uint32-varint
sint32-zigzag x 2
uint32-varint x 4
uint32-varint x 2, narrowed to bytes by the client
uint8-varint x 9
tagged_value
byte[16] identifier
uint32-varint
uint32-varint length (< 34)
byte[length]
uint32-varint entry_count (<= 3)
entry[entry_count]
```

The two narrowed values are preserved as full wire integers so a decode and
re-encode does not discard high bits that the client itself ignores.

The tagged value at RVA `0x64760` accepts discriminators zero through six:

```text
uint32-varint discriminator
if discriminator != 0:
  byte[16] identifier
if discriminator == 1:
  uint32-varint uint32_1
  uint32-varint uint32_0
if discriminator == 4:
  uint32-varint uint32_0
```

Each metadata entry contains:

```text
control_identity identity
uint32-varint length (< 32)
byte[length] bytes_0
uint32-varint uint32_0
uint8-varint byte_0
uint8-varint byte_1
```

Unknown high flag bits are retained. The encoder verifies that bits zero and
one agree with the presence of their corresponding optional structures.

## Validation

Run the complete suite:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

The control-codec tests cover the short and full `0x0002` variants, every
known tagged-value shape, both optional flag branches, multi-entry metadata,
noncanonical nonzero `0x0006` presence, field limits, malformed counts, and
trailing-byte rejection.
