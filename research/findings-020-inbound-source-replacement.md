# Finding 020: the source backing-pointer watch was downstream of transport

Date: 2026-09-24

## Capture

The retargeted inbound-source capture is:

```text
evidence/20260924-164710-inbound-buffer-producer-linux
```

It armed an eight-byte per-thread write watch on the selected source object's
backing-buffer pointer at offset `+0x48`. The capture reached its 64-event cap
without logging object addresses or payload bytes.

## Result

Every write stopped at RVA `0x0223cd58`, inside the same generic refcounted
pointer-assignment helper (`0x0223ccc9` through `0x0223cda4`). Immediate callers
varied with the decoded field and message family. The first two bootstrap hits
returned through RVA `0x0002156d`; later world hits predominantly returned
through the schema paths below RVA `0x01795686` and related helpers.

Disassembly of the bootstrap caller beginning at RVA `0x00021500` shows a
bounded byte-field reader: it obtains a field length, validates that length
against the caller's maximum, obtains source bytes through reader virtual
methods, and copies/assigns the resulting field. The later call stacks contain
the already verified schema boundary at RVA `0x00f8448c`. Therefore the watched
field changes during deserialization/cursor management; it is not where the
private TLS transport publishes a new plaintext record.

## Reader replacement hypothesis disproved

Capture `evidence/20260924-170106-inbound-source-replacement-linux-linux`
resolved the method invoked at RVA `0x0009a851` to RVA `0x00078db0`. Its entire
function compares `reader+0x90` with state `2`, writes the equality result to
`AL`, and returns. The per-thread watch on `reader+0x70` armed successfully but
recorded zero writes through world entry, combat, and a loot drop. The method
is a finished/closed check, not a queue pop or source replacement operation.

## Revised target: reader construction/setup

The current source at `reader+0x70` is already populated before the first
verified handoff and appears invariant for that reader instance. The next
probe therefore works backward from the concrete reader vtable rather than
guessing another field method.

The `ISAC_INBOUND_SOURCE_PROBE` mode now additionally:

1. records up to eight distinct reader vtable RVAs and their first 16 method
   RVAs;
2. scans committed executable image pages for RIP-relative references to that
   exact vtable;
3. records up to 32 constructor/setup candidate RVAs; and
4. captures bounded code around each candidate.

This preserves the code-only, redacted scope while locating the code that
initially creates the reader and assigns its source, before the first parser
handoff makes a field watchpoint possible.
