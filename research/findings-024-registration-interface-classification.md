# Finding 024: registration subobjects are collection adapters

Date: 2026-09-24

## Capture

```text
evidence/20260924-173101-registration-interface-linux
```

The registration-return capture completed without probe errors or capacity
limits. Constructor RVA `0x00034450` creates a `0x98`-byte object with embedded
polymorphic subobjects at offsets `+0x18` and `+0x50`. Their vtable RVAs are
`0x02910bf8` and `0x02915588`.

## Classification

Both embedded subobjects have the same collection-oriented method pattern:

- two accessors return the subobject's stored data pointer;
- one accessor returns its count or capacity field;
- one method tests whether the collection is nonempty;
- one method reserves or grows its backing store; and
- one method returns a newly grown indexed element.

The constructor confirms that interpretation. It initializes four element
slots at `+0x18` and five at `+0x50`, then invokes the same copy/helper routine
for each subobject. These fields carry registration inputs, but they are not a
direct `(buffer, length)` transport callback.

The broad 16-slot inventory also reached RVA `0x000e0f00` after vtable
`0x02915588`. That routine accesses fields near `this+0x918`, which cannot
belong to this `0x98`-byte allocation. It is therefore outside the useful
interface boundary (or otherwise not callable for this subobject) and must not
be treated as the registration delivery method.

## Remaining delivery candidates

The registration routine still exposes three external values that were not
classified by this capture:

1. the reference passed in `RDX`, attached to registration object offset
   `+0x00` immediately after construction;
2. the original `R9` registration input, copied into the `+0x50` collection;
   and
3. the resolved context stored at registration object offset `+0x90`.

The next redacted capture inventories these three values as potential objects.
For each it records only its role, whether it is a valid in-image polymorphic
object, its module-relative vtable RVA, bounded method windows, and bounded
vtable references. It does not record object addresses, field contents, or
transport payloads.
