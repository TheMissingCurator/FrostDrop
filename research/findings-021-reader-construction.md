# Finding 021: reader construction and source ownership

Date: 2026-09-24

## Capture

```text
evidence/20260924-171103-inbound-reader-vtable-xrefs-linux
```

The capture recorded one concrete reader vtable at RVA `0x0291da38`. Its first
16 slots resolve to:

```text
0x0d3980 0x0d3920 0x0e67a0 0x006c0f0
0x0dbc70 0x058df0 0x0611a0 0x078db0
0x078de0 0x078df0 0x06a9d0 0x062850
0x069980 0x049f70 0x356dad8 0x04450c
```

The executable-page scan found exactly three RIP-relative references to the
vtable, at RVAs `0x002f7cf`, `0x002f93f`, and `0x003b598`. No probe errors or
capacity limits occurred.

## Constructors

The references at `0x002f7cf` and `0x002f93f` belong to constructor variants
beginning at RVAs `0x002f790` and `0x002f900`. Both constructors:

1. install the reader vtable;
2. initialize fields `+0x50` through `+0x90`;
3. allocate `0x80` bytes through RVA `0x00002c90`;
4. initialize that allocation through RVA `0x02237e90`;
5. store the returned object at `reader+0x70`; and
6. call setup routine `0x005fb10` or `0x005fed0`.

This explains why the previous `reader+0x70` watch recorded no writes: the
field owns a persistent source/cursor object created during reader construction,
before the first inbound handoff exposes the reader.

The reference at RVA `0x003b598` belongs to the destructor beginning at
`0x003b580`. It transitions state `reader+0x90` to `2` and invokes the source
object's first virtual method with argument `1` before releasing the remaining
reader-owned objects.

## Next boundary

The transport-facing setup is now bounded to five code regions:

- source-object constructor `0x02237e90`;
- reader constructors `0x002f790` and `0x002f900`;
- reader setup routines `0x005fb10` and `0x005fed0`.

The next code-only capture snapshots their complete unwind regions plus
1,024-byte forward windows. The goal is to identify where the persistent source
object is registered with the decrypted transport and which callback appends or
selects its backing blocks. Object addresses and payload bytes remain disabled.
