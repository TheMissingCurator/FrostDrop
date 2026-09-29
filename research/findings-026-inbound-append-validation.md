# Finding 026: direct source append is the validated injection primitive

Date: 2026-09-24

## Capture

```text
evidence/20260924-175532-delivery-boundary-linux
```

Both metadata streams reached their intentional 128-event bounds. No probe
error occurred. Every direct-call buffer passed the bounded readability check,
and all 128 wrapper chains were structurally complete.

## Runtime correlation

The transport wrapper produced 128 observations:

- 100 chains had one chunk;
- 23 had two chunks;
- three had three chunks; and
- two had five chunks.

The direct append breakpoint filled earlier because RVA `0x223d140` is a
generic engine primitive used by several source/writer objects. Within the
overlap, six wrapper events have an unambiguous same-tick direct call whose
first caller is RVA `0x00084c22`. In every case the wrapper total equals the
direct append length. Confirmed lengths include 4, 138, 158, and 837 bytes.

The call at `0x00084c1f` returns to `0x00084c22`, so the dynamic stacks match
the static wrapper disassembly exactly.

## Append behavior

RVA `0x223d140` has the effective signature:

```text
uint32 append(source *source, const byte *data, uint32 length)
```

It:

1. acquires the source's internal lock at `source+0x08`;
2. obtains or allocates refcounted chunks with 1,000-byte payload capacity;
3. copies the supplied bytes across as many chunks as required;
4. maintains head and tail references at `source+0x48` and `source+0x78`;
5. adds the input length to the total at `source+0x70`;
6. releases the internal lock; and
7. returns the input length.

This routine performs the byte ownership/copy itself, so a local bridge does
not need to reproduce the transport's chunk allocation or linked-list ABI.

## Required bridge context

The primitive is not globally unique to inbound traffic. A bridge must retain
the exact persistent source from `reader+0x70`. It must also mirror the outer
wrapper sequence:

```text
lock reader secondary-interface state at primary reader +0x18
append to the retained source
notify reader state at primary reader +0x68
unlock
```

The next code-only capture recovers complete bounded functions for the lock,
notify, and unlock helpers at RVAs `0x0000b7e0`, `0x0001e0a0`, and
`0x0000c6c0`. Those calling conventions are the last internal ABI detail needed
before implementing an explicitly opt-in loopback transport bridge.
