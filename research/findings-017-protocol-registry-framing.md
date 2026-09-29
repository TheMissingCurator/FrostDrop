# Finding 017: executable protocol registry and framing layer

Date: 2026-09-23

Evidence: `evidence/20260923-164825-schema-miner-wide-3-linux`

## Result

The recovered message codecs now sit behind a central registry and the
application framing formats are implemented as reusable library code. This is
the first protocol layer intended to be consumed directly by a replacement
backend rather than only by capture-analysis scripts.

`src/isac_protocol/registry.py` registers nine completed server-to-client
message types:

```text
0x0020  0x0023  0x0024  0x002a  0x002d
0x0067  0x006c  0x0088  0x019d
```

Type `0x0088`, which has been validated in both directions, is also registered
client-to-server. Registry keys include direction as well as type ID. This is
required because the capture contains 17- and 18-byte outbound `0x019d` frames,
while the completed inbound `0x019d` schema is only 3 or 4 bytes. Treating a
type ID as globally unique would apply the wrong schema.

The registry validates model types before encoding, supports explicit failure
for unknown direction/type pairs, and can preserve unknown frames as opaque
bodies during partial-protocol replay.

## Directional framing

`src/isac_protocol/framing.py` keeps the two verified wire shapes separate.

Server-to-client application traffic is a stream of frames:

```text
zigzag(nonnegative frame length)
uint16-varint message type
message body
```

Client-to-server traffic groups frames in an outer envelope:

```text
u8 marker
u8 channel
u32-varint envelope body length
  zigzag(nonnegative frame length)
  uint16-varint message type
  message body
  ...
```

Both incremental decoders accept arbitrary transport chunk boundaries,
including a length prefix or body split across chunks. Configurable size limits
reject unreasonable allocations before waiting for their payloads.

## Stateful references and replay

`ProtocolSession` owns independent client-to-server and server-to-client
compact-reference tables. This matters because later frames can encode a
previously introduced 16-byte reference using only a small table token. A test
sends the same reference in two messages and verifies that the second frame is
shorter and resolves to the same value on the receiver.

`MessageReplayDecoder` composes inbound chunk reassembly, registry dispatch,
and the received reference table. Known types become typed message objects;
unknown types remain `OpaqueMessage` values by default. This allows partial
replay tooling to retain ordering and unknown traffic without claiming those
schemas are understood.

## Evidence validation

The framing validator processed the successful plaintext records from the
broad capture:

```text
outbound envelopes                 512
outbound nested frames             584
inbound frames                      21
byte-identical outbound round trips 512
byte-identical inbound round trips   21
registry-decoded outbound frames      0
opaque outbound frames              584
```

It then concatenated each direction and replayed it through deliberately
irregular chunk sizes. The incremental results exactly matched record-by-record
decoding with zero buffered bytes left over.

Six outbound frames use ID `0x019d`, but correctly remain opaque because only
the server-to-client schema for that ID is known. Framing still preserves all
584 outbound frames byte-for-byte.

The source log contains one probe-reported invalid inbound-frame event from
before the successful bounded records. It is retained and reported by the
validator but is not represented as a `PLAINTEXT_IN` record, so it cannot be
round-trip tested.

## Reproduction

```bash
./tools/validate-protocol-framing.py \
  evidence/20260923-164825-schema-miner-wide-3-linux/project-isac-plaintext-probe.log
```

## Remaining boundary

This layer begins at decrypted application bytes. It does not implement the
36/8/3-byte connection preface, mutual TLS, allocation service, authentication,
or the pre-world bootstrap conversation. The next research target is an early
connection/bootstrap capture that uses these framing primitives to inventory
the messages required before world entry.
