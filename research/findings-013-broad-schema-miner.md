# Finding 013: broad schema miner validation

Date: 2026-09-23

Evidence: `evidence/20260923-164825-schema-miner-wide-3-linux`

## Capture health

The first successful broad-miner run remained stable through a varied gameplay
session and produced:

- 8,192 bounded `SCHEMA_MESSAGE` records;
- 8,184 complete bodies and eight incomplete bodies;
- 60 distinct inbound message types;
- 9,158 primitive-reader field records;
- 75 captured deserializers; and
- zero message, field, dispatch, or plaintext probe errors.

The 8,192-message bound was reached. Of the field records, 6,019 correlate to
captured message bodies. The remaining 3,139 were recorded after the body cap
and are still useful for aggregate callsite discovery, but cannot contribute
to per-body coverage calculations.

Thirty-four of the 60 types have at least one complete body whose entire byte
range is explained by known primitive readers. Thirty-five types reach at
least 90 percent best-case coverage. This establishes that broad structural
mining can promote multiple schemas from one gameplay run rather than tracing
every type with a dedicated probe.

## Known-codec control

Type `0x0088` appeared 11 times. All 11 bodies had 100 percent field coverage
and round-tripped byte-identically through the previously implemented codec.
This run contained only its simple 31- and 32-byte forms: equipped flag zero,
no child rows, and no auxiliary rows. The independent broad capture therefore
validates the schema ordering and message-body boundary without relying on the
focused evidence used to construct that codec.

## Newly promoted simple schemas

Five stable schemas were implemented with neutral names in
`src/isac_protocol/simple_messages.py` and validated across 129 complete
bodies:

```text
0x0020  compact_reference, varuint8                         8 bodies
0x0024  compact_reference, length-prefixed bytes, u8, u8  57 bodies
0x002d  compact_reference, sint32, float32                 8 bodies
0x0067  compact_reference, vec3f, float32                 45 bodies
0x019d  sint32, compact_reference                         11 bodies
```

Every one of those 129 bodies decodes and re-encodes byte-identically. The
length-prefixed field in `0x0024` is stored as bytes even though observed
values are textual, avoiding an unsupported assumption about character
encoding.

## Next candidate tiers

Type `0x002a` exposed a rare conditional tail and was subsequently promoted
to a branch-aware codec. See `findings-014-type002a-schema.md` for its completed
schema and validation boundary.

Type `0x0023` combines compact references, byte values, a vec3f, a bool, a
signed 64-bit value, and three float32 fields. It was subsequently promoted to
a complete tagged-union codec; see `findings-015-type0023-schema.md`.

Type `0x006c` occurred 179 times and reaches 94.1 percent primitive-hook
coverage. It was subsequently identified as a presence-mask message and all
179 bodies were promoted to an observed-subset codec. See
`findings-016-type006c-schema.md`.

The most frequent types are not automatically the easiest or most useful:

- `0x0012`: 5,777 messages, 25 percent best coverage, many body families;
- `0x000f`: 793 messages, 55.4 percent best coverage; and
- `0x001f`: 76 messages, 72.1 percent best coverage and many lengths.

These need nested-call or branch discovery rather than more samples of the
same top-level primitive group.

## Reproduction

Aggregate ranking without printing body contents:

```bash
./tools/analyze-schema-miner.py \
  evidence/20260923-164825-schema-miner-wide-3-linux/project-isac-dispatch-probe.log
```

Validate the five simple codecs:

```bash
./tools/validate-simple-schemas.py \
  evidence/20260923-164825-schema-miner-wide-3-linux/project-isac-dispatch-probe.log
```

Validate the known `0x0088` control:

```bash
./tools/validate-type0088.py \
  evidence/20260923-164825-schema-miner-wide-3-linux/project-isac-dispatch-probe.log
```

All three tools hide message bytes and reference identifiers in their normal
output.
