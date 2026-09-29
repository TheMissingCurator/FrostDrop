# Finding 014: type `0x002a` conditional schema

Date: 2026-09-23

Evidence: `evidence/20260923-164825-schema-miner-wide-3-linux`

## Result

Type `0x002a` now has a branch-aware neutral codec in
`src/isac_protocol/type002a.py`. All 15 complete bodies in the broad capture
decode and re-encode byte-identically, covering lengths 10, 11, 14, and 23.

The common core is:

```text
compact_reference
compact_reference
sint32 x 6
```

The sixth signed value controls a conditional tail. Every captured body with
value zero ends after the core. The one body with value one contains:

```text
fixed little-endian u32
sint32
sint32
fixed u8
compact_reference
```

The client reads the four-byte and one-byte values without going through the
instrumented primitive helpers. Their sizes, ordering, and byte order are
established by the captured cursor gaps. Their gameplay meaning is not, so
the codec deliberately calls them `fixed_u32_0` and `fixed_u8_0`.

## Evidence strength and boundary

The eight core reads occurred at the same callsites in all 15 messages. Fourteen
bodies had complete primitive coverage. The 23-byte body exercised three more
instrumented calls in the tail; the two direct-read gaps are exactly four and
one bytes. Together these account for its entire body.

The observed discriminator relationship is internally consistent but the
nonzero branch has only one sample. The codec therefore enforces the recovered
wire structure while leaving field semantics neutral. A future capture with
additional nonzero values should test whether every nonzero discriminator uses
the same tail, or whether it is an enum with more branches.

## Reproduction

```bash
./tools/validate-type002a.py \
  evidence/20260923-164825-schema-miner-wide-3-linux/project-isac-dispatch-probe.log
```

Expected summary:

```text
Complete type 0x002a bodies: 15
Byte-identical round trips: 15
Conditional-tail bodies: 1
Lengths: 10:1,11:12,14:1,23:1
```

The validator does not print body contents or reference identifiers.
