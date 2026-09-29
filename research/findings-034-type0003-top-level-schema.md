# Finding 034: type-0x0003 top-level schema

Date: 2026-09-25

## Capture

```text
evidence/20260925-001236-type3-schema-window-linux
```

The capture reached the main menu, observed the expected 835-byte type-`0x0003`
response, and recovered the complete generated reader at RVA `0x22551b0`.
There were no probe errors or capacity limits, and payload recording remained
disabled.

## Ordered reader map

The generated routine verifies that the envelope type at reader offset `0x10`
is `0x0003`, then performs these reads in order:

| Order | Destination offset | Reader RVA | Structural interpretation |
| ---: | ---: | ---: | --- |
| 1 | `0x000` | `0x223daf0` | unsigned 8-bit varint |
| 2 | `0x008` | `0x64cb0` | large bounded subobject |
| 3 | `0x430` | `0x64cb0` | large bounded subobject |
| 4 | `0x858` | `0x64e50` | control identity |
| 5 | `0x898` | `0x217f0` | 32-bit length plus fewer than 64 bytes |
| 6 | `0xe80` | `0x223d530` | Boolean |
| 7 | `0xe81` | `0x223d530` | Boolean |
| 8 | `0xe82` | `0x223d530` | Boolean |
| 9 | `0xd18` | `0x65060` | Boolean bundle plus counted collection |
| 10 | `0x8f0` | `0x64cb0` | large bounded subobject |

The destination offsets are storage layout, not wire order; notably the
`0xd18` bundle is read after the three trailing Booleans and before the final
`0x8f0` subobject.

The identity reader at `0x64e50` is the same structure already used by early
control types:

```text
uint8-varint byte_0
uint8-varint length (<= 61)
byte[length] value
```

The bundle reader at `0x65060` starts with seven Booleans, reads a 32-bit
varint count, and invokes RVA `0x21640` once per entry with an argument of
eight. The repeated `0x64cb0` reader invokes RVA `0x215a0` with a bound of
`0x8000`, then reads a 64-bit varint and converts that value into an internal
time/reference representation. Those two lower-level readers are the only
remaining wire-format ambiguities.

## Next target

RVA `0x215a0` and RVA `0x21640` are only `0xa0` bytes apart. The focused
type-`0x0003` mode now captures one direct 4,096-byte forward window starting
at `0x215a0`, covering both helpers and the already-understood bounded-byte
reader at `0x217f0`. This should be sufficient to finish a structural decoder
and encoder without recording the retail response body.
