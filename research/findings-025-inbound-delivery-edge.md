# Finding 025: the inbound delivery edge is a buffer-and-length call

Date: 2026-09-24

## Capture

```text
evidence/20260924-174726-registration-handles-linux
```

The registration-handle capture completed without probe errors or capacity
limits.

## Registration handles

The three candidate values classified as follows:

- `transport-reference`: object with vtable RVA `0x0291dab0`;
- `registration-input`: not a polymorphic object; and
- `resolved-context`: object with the already-classified collection vtable
  RVA `0x02910bf8`.

Vtable `0x0291dab0` has the same three constructor/destructor references as the
primary reader vtable. Reader constructor RVA `0x0002f790` writes the primary
vtable at object offset `+0x00` and `0x0291dab0` at offset `+0x08`. The
transport reference is therefore the reader's secondary interface, not a
separate transport allocation.

## Delivery wrapper

Secondary-interface slot 3 resolves to RVA `0x00084bd0`. It accepts a
refcounted chunk chain through `RDX` and, under the reader lock, walks it using:

```text
chunk byte length  = dword [chunk+0x0c]
chunk bytes        =       chunk+0x10
next chunk         = qword [chunk+0x3f8]
```

For every chunk it loads the persistent source object from primary reader
offset `+0x70` (secondary-interface offset `+0x68`) and calls source vtable
slot `+0x30` with:

```text
RCX = persistent source object
RDX = chunk bytes
R8D = chunk byte length
```

Source vtable slot `+0x30` is RVA `0x223f180`, a direct jump to RVA
`0x223d140`. This is the first recovered boundary with an unambiguous
`(source, bytes, length)` signature between transport-owned receive chunks and
the persistent inbound source.

## Next validation

The next metadata-only probe places execute breakpoints at both
`0x00084bd0` and `0x223d140`. It records bounded chunk counts, total lengths,
direct-call lengths, readable-window status, and module-relative caller stacks.
It also captures the complete unwind-bounded functions for both RVAs. No
buffer address or byte content is logged.

Matching wrapper totals to direct-call lengths and confirming the expected
caller RVA will establish whether `0x223d140` can serve as the synthetic-frame
injection boundary for a local backend bridge.
