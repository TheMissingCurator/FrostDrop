# Finding 028: loopback bridge observe stage

Date: 2026-09-24

The forwarding DLL now contains an explicitly opt-in application-plaintext
loopback bridge. This first stage validates routing and object lifetime without
mutating the retail client's inbound stream.

## Boundaries

With `ISAC_LOCAL_BACKEND_BRIDGE=1`, the bridge uses hardware execute
breakpoints for:

- inbound transport delivery at RVA `0x00084bd0`;
- outbound serialized-writer handoff at RVA `0x000d6bbf`; and
- reader registration at RVA `0x000af360`.

It records reader candidates during registration. A real transport delivery
confirms the exact primary reader as `secondary_interface-0x08` and retains
the source stored at primary-reader offset `+0x70`. Neither pointer value nor
application payload is written to a log.

## Loopback routing

The bridge connects only to `127.0.0.1`, port `55000` by default. The port can
be changed with `ISAC_LOCAL_BACKEND_PORT`; the host is intentionally not
configurable.

Because the client owns multiple plaintext writers, the bridge waits for the
first structurally valid marker-`0x03` envelope containing type `0x0002` and
pins that writer. Records from other writers are ignored. Selected records are
copied into a bounded 32-slot queue, preserving their order, and a worker
forwards them to the plaintext bootstrap runner.

Received loopback bytes are currently logged only as bounded length metadata:

```text
LOCAL_BRIDGE_RX ... detail=sequence=N,length=N,injection=disabled
```

They are deliberately not injected yet. The live Ubisoft network path remains
unchanged, making this stage suitable for a connected validation run.

## Success criteria

A successful run should contain:

1. `LOCAL_BRIDGE_READY` and `LOCAL_BRIDGE_CONNECTED`;
2. `LOCAL_BRIDGE_STREAM_SELECTED`;
3. at least one `LOCAL_BRIDGE_READER_READY` after a retail delivery; and
4. `LOCAL_BRIDGE_RX` when the local profile emits a response.

Once all four are confirmed, the next revision can feed received bytes through
the validated lock/append/notify/unlock sequence behind a separate injection
flag.

## Validation result

Evidence:

```text
evidence/20260924-225959-local-bridge-observe-linux
```

Two game processes opened loopback connections. The short-lived first process
never selected a writer. Process 1228 selected the first valid type-`0x0002`
writer and forwarded a complete multiplexed bootstrap conversation. The local
backend parsed channels 0 through 15, advanced through `login_accepted` to
`control_ready`, and emitted both configured responses. The bridge received
the three-byte synthetic `0x0002` frame and four-byte synthetic `0x0006` frame.
There were no bridge errors, queue drops, or probe errors.

Every transport-delivery reader exposed the expected source vtable RVA
`0x034863d8`. However, the transport-delivery stream changed reader identity
54 times during the run. A delivery proves that a reader/source pair is valid,
but it does not by itself prove that the pair belongs to the pinned outbound
bootstrap writer. Consequently, active injection must not simply use the most
recent reader.

The next bridge probe must retain the transport object in `RCX` at the selected
outbound boundary and correlate it with an inbound reader, using anonymous
object IDs and pointer-field offset comparisons rather than logging addresses
or payloads. Only after that association is unambiguous should response
injection be enabled.
