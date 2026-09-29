# Finding 030: channel-0 login response is type 0x0003

Date: 2026-09-24

## Capture

```text
evidence/20260924-231459-bridge-reader-correlation-fixed-linux
```

The corrected correlation run completed without bridge errors, drops, or
capacity limits. The local backend again parsed the multiplexed bootstrap
conversation through `control_ready`.

## Corrected delivery decoding

The retail delivery wrapper receives a pointer to a chunk-chain reference.
After applying the missing dereference, its lengths matched the previously
validated delivery probe and its complete frame prefixes decoded normally.

The initial channel-0 conversation was:

```text
client channel 0: type 0x0002 request
retail reader 1: four-byte setup/control delivery
retail reader 1: type 0x0003, declared frame length 835
```

Therefore the local bootstrap state machine's configured type-`0x0002`
response is not the retail login response. The observed request and response
types differ: `0x0002` requests login/bootstrap and `0x0003` carries its retail
response.

The channel-10 control exchange was:

```text
client channel 10: types 0x0000, 0x0005
retail reader 11: four-byte setup/control delivery
retail reader 11: type 0x0001, declared frame length 2
retail reader 11: type 0x0006, declared frame length 309
```

This confirms reader 11 for the channel-10 `0x0005`/`0x0006` exchange.

## Reader topology

The early reader allocation order broadly follows the multiplexed bootstrap
channels: reader 1 serves channel 0, while reader 11 serves channel 10. Other
readers receive the channel-specific setup families (`0x0001`, `0x0002`, and
`0x0008`). The selected outbound transport has no direct or shared readable
pointer field with these readers within the bounded `0x400`/`0x600` scans.

## Consequence

Active injection remains disabled. Before a valid login test, Project ISAC
must recover the type-`0x0003` response schema and change the backend's initial
response factory from `0x0002` to `0x0003`. A targeted bootstrap handoff/code
probe is the next step. Reader discovery for a serverless run remains a
separate requirement after the response schema is established.

The first targeted run was capture
`20260924-232435-bootstrap-type3-code-linux`. It armed without errors, but
produced no type-`0x0003` path. The breakpoint at `0x0009a845` fired only after
RVA `0x223ebb0` had copied the source into a temporary decode context, by which
time the source cursor was no longer a reliable view of the target frame.

Disassembly of the previously captured common reader helper identifies the
correct earlier boundary at RVA `0x0009a7c0`. At entry, `RCX` is the live
reader and `reader+0x70` is its source, before the context copy at `0x0009a840`.
`ISAC_BOOTSTRAP_TYPE3_PROBE=1` now places its persistent breakpoint at this
entry, filters path capture exclusively to type `0x0003`, and records only
framing/call-stack/code metadata. The unwind should identify the
login-specific dispatcher above the shared reader wrapper.

Capture `20260924-233153-bootstrap-type3-reader-entry-linux` armed that entry
without errors but again produced no target path. Its timing isolated a second
issue: the outbound login request occurred at tick `34566471`, while the
worker that processes the initial response did not enter a hooked Winsock call
until tick `34566812`. Hardware breakpoints are per-thread, so that newly
created worker could execute the reader helper before being armed. The probe
now refreshes all process threads 12 times at 25-millisecond intervals after
selecting the outbound login stream, covering the observed response window
without applying a software patch.
