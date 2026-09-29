# Finding 029: transport-to-reader correlation probe

Date: 2026-09-24

The observe-only loopback bridge now correlates its selected outbound
bootstrap transport with inbound reader objects without recording addresses or
message bodies.

## Added metadata

At the outbound writer boundary, `RCX` contains the transport object and `RDX`
contains the serialized writer. When the first valid type-`0x0002` envelope
selects a writer, the probe now retains both objects.

Each inbound call to RVA `0x00084bd0` receives a stable anonymous reader ID.
The probe walks the bounded receive-chunk chain to record:

- total delivery length;
- chunk count;
- the first length-prefixed frame's type ID, when its prefix is complete; and
- its declared frame length.

Only the few prefix bytes needed for the two varints are inspected. They are
not written to disk.

For every newly observed reader, the probe performs bounded pointer-field
comparisons between the reader and selected transport. `LOCAL_BRIDGE_RELATION`
reports only object-relative offsets for:

- a reader field equal to the transport;
- a transport field equal to the reader, its secondary interface, or source;
  and
- shared readable heap pointers stored in both objects.

The local response path now reports its decoded first type and declared frame
length as well. This permits direct alignment of local `0x0002`/`0x0006`
responses with retail deliveries of the same type while keeping all bodies
redacted.

## Decision rule

A reader is safe for the next injection experiment only if the run produces a
stable structural relationship to the selected transport, or an otherwise
unambiguous repeated type/reader mapping supported by both bootstrap response
families. The probe does not inject or suppress any traffic.

## First-run correction

Evidence `20260924-230909-bridge-reader-correlation-linux` confirmed both local
response types and assigned 28 stable reader IDs, but all delivery lengths were
incorrectly zero. The wrapper's `RDX` argument points to a reference containing
the first chunk; the correlation implementation initially treated `RDX` as the
chunk itself. The established delivery probe already used the required one
pointer dereference. The correlation path now does the same.

The bounded direct/shared-field comparison found no relationship between the
selected transport and any of the 28 readers. Timing alone placed reader 1
immediately after the local `0x0002` response and reader 11 immediately after
the local `0x0006` response, but that is not sufficient for injection. A short
corrected run will validate the corresponding retail frame types.
