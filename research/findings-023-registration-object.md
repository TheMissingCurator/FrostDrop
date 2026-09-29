# Finding 023: shared setup creates a transport registration object

Date: 2026-09-24

## Capture

```text
evidence/20260924-172320-reader-register-source-vtable-linux
```

The capture recovered the shared reader-registration routine and both live
reader/source vtables without errors or capacity limits.

## Source vtable

The persistent source object uses vtable RVA `0x034863d8`. Its nine populated
slots are:

```text
0x22387c0 0x223b3f0 0x223b2e0
0x223d520 0x223da00 0x223c770
0x223f180 0x223fb00 0x223aa90
```

The captured methods are predominantly ownership and primitive decode
operations. Slot 8 (`0x223aa90`) returns a retained reference to `source+0x48`.
Slots 3 through 7 belong to the shared primitive-reader family already seen in
schema recovery. The persistent source is therefore the decode cursor API, not
itself the transport callback.

## Registration routine

RVA `0x000af360` validates reader state and allocates a monotonically increasing
registration ID. It then:

1. allocates `0x98` bytes;
2. calls constructor RVA `0x00034450` with the ID and resolved setup inputs;
3. attaches the resolved transport/reference object to the constructor result;
   and
4. inserts that result into the reader-owned table at `reader+0x570` through
   the table's virtual insertion method.

The constructor return site is RVA `0x000af439`. The new `0x98`-byte object is
the first concrete object on this path whose purpose is registration rather
than stream decoding, making its embedded interfaces the strongest current
candidate for the decrypted-data delivery callback.

## Next capture

The next redacted probe places an execute breakpoint at `0x000af439`. On its
first hit it scans pointer-sized fields within the `0x98`-byte object for valid
in-image vtables, recording only:

- each interface's object-relative offset;
- its module-relative vtable RVA;
- bounded vtable references; and
- bounded code windows for its methods.

It also captures constructor `0x00034450` directly. No object address, field
contents, transport data, or gameplay payload is logged.
