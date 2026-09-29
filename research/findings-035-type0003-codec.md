# Finding 035: structural type-0x0003 codec

Date: 2026-09-25

## Capture

```text
evidence/20260925-001956-type3-collection-readers-linux
```

The capture recovered the requested 4,096-byte code window at RVA `0x215a0`
with no probe error or capacity limit. It contains both unresolved collection
readers in full.

## Closed collection formats

RVA `0x215a0` reads a 64-bit varint length, rejects values greater than its
caller-supplied maximum, resizes the destination, and copies exactly that many
bytes. The type-`0x0003` caller supplies `0x8000`, so each repeated large
subobject is:

```text
uint64-varint length (<= 32768)
byte[length] bytes_0
uint64-varint uint64_0
```

The client converts the final integer into an internal time/reference value,
but that conversion does not alter its wire representation.

RVA `0x21640` reads a 32-bit varint length, rejects values greater than or
equal to its supplied maximum, and copies the bytes. The bundle caller supplies
eight, so each entry is:

```text
uint32-varint length (< 8)
byte[length] value
```

The complete type-`0x0003` structural grammar is therefore:

```text
uint8-varint byte_0
timed_blob timed_blob_0
timed_blob timed_blob_1
control_identity identity
uint32-varint bytes_0_length (< 64)
byte[bytes_0_length] bytes_0
bool bool_0
bool bool_1
bool bool_2
bool bundle_bool_0 through bundle_bool_6
uint32-varint bundle_count
bounded_entry[bundle_count] bundle_entries
timed_blob timed_blob_2
```

## Implementation

`src/isac_protocol/control_messages.py` now contains structural decode and
encode models for type `0x0003`. The server-to-client registry includes the
new codec. The local bootstrap profile accepts either the old type-`0x0002`
framing fixture or the retail-correct type-`0x0003` response, and rejects a
profile that configures both.

The synthetic minimal profile in
`docs/bootstrap-profile.type0003-minimal.json` contains only empty/zero values.
It validates the recovered grammar but is explicitly not evidence that those
values satisfy the client's login semantics. Active bridge injection remains
disabled, so the next engineering boundary is guarded inbound injection and
retail-path isolation rather than further schema-code capture.
