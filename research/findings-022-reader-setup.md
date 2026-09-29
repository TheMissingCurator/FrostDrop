# Finding 022: reader setup converges on one shared routine

Date: 2026-09-24

## Capture

```text
evidence/20260924-171812-reader-setup-code-linux
```

All five requested unwind regions and forward windows were captured without a
probe error or capacity limit.

## Persistent source object

The source-object constructor at RVA `0x02237e90` is only 63 bytes. It installs
vtable RVA `0x034863d8`, initializes the object's base/refcount state, and
zeroes fields `+0x40`, `+0x48`, `+0x50`, `+0x60`, `+0x70`, and `+0x78`. It does
not receive transport bytes or register a callback.

This confirms the object stored at `reader+0x70` is a persistent, initially
empty cursor/source object. Its `+0x48` backing-block pointer and `+0x50` cursor
are populated later.

## Setup convergence

Reader setup A at RVA `0x005fb10` performs connection/endpoint selection. It
enumerates candidate objects, follows the selected object's nested interface,
and prepares a handle before making its final setup call. Reader setup B at RVA
`0x005fed0` skips that selection work and uses the supplied handle directly.

Both paths converge on RVA `0x000af360` with the reader object in `RCX` and
their resolved transport/channel inputs in the remaining arguments. This is
the narrowest shared routine known before normal inbound parsing begins.

## Next capture

The next code-only probe combines:

1. the complete unwind region and a 1,024-byte forward window for `0x000af360`;
2. the live source-object vtable and its first 16 method RVAs; and
3. bounded code windows around every in-image method in both reader and source
   vtables.

The result should show whether `0x000af360` registers a decrypted-data callback
directly or delegates to one of the persistent source object's methods. Payload
bytes and heap addresses remain disabled.
