# Finding 015: type `0x0023` tagged-union schema

Date: 2026-09-23

Evidence: `evidence/20260923-164825-schema-miner-wide-3-linux`

## Result

Type `0x0023` now has a complete branch-aware neutral codec in
`src/isac_protocol/type0023.py`. All 87 complete captured bodies decode and
re-encode byte-identically.

Static deserializer code at RVA `0x178d250` establishes the branches rather
than requiring them to be guessed from message lengths. The wire grammar is:

```text
compact_reference reference_0
uint8             byte_0
uint8             discriminator

switch discriminator:
  0: stop successfully
  1: compact_reference reference_1
  2: vec3f vector_0
  other: no variant field

if discriminator != 0:
  if byte_0 == 0:
    bool   boolean_0
    sint64 signed_0
  float32 float_0
  float32 float_1
  float32 float_2
```

The `bool` reader uses an unsigned varint and converts zero/nonzero to false or
true. The encoder emits the canonical values zero and one.

## Observed families

```text
byte_0=0 discriminator=0 length=4  bodies=14
byte_0=0 discriminator=1 length=21 bodies=31
byte_0=0 discriminator=2 length=31 bodies=39
byte_0=1 discriminator=0 length=4  bodies=2
byte_0=1 discriminator=1 length=18 bodies=1
```

The apparent six field-trace shapes reported by the broad analyzer were not
six wire variants. Some bodies arrived after per-type or global instrumentation
limits and therefore lacked a subset of field records. Static control flow and
complete bodies reduce them to the five observed selector combinations above.

## What remains unknown

The structure resembles a tagged update capable of carrying either a related
object reference or a 3D vector, followed by three floating-point values and
optional boolean/signed metadata. Those are structural observations, not yet
gameplay semantics. Controlled event correlation is still needed before
naming the message or fields more specifically.

The deserializer also defines behavior for discriminator values above two,
although none occurred in this capture: they omit the variant field but retain
the common tail. The codec implements that static path and tests it with a
synthetic body.

## Reproduction

```bash
./tools/validate-type0023.py \
  evidence/20260923-164825-schema-miner-wide-3-linux/project-isac-dispatch-probe.log
```

The validator reports only aggregate selector and length counts. It does not
print message bodies or reference identifiers.
