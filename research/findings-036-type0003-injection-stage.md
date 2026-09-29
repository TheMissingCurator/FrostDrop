# Finding 036: guarded type-0x0003 injection stage

Date: 2026-09-25

## Purpose

The loopback bridge can now perform the first bounded application-plaintext
mutation experiment. This is an explicit mode selected by
`ISAC_LOCAL_BACKEND_INJECT=1`; ordinary bridge runs remain observe-only.

## Guards

The implementation:

1. requires `ISAC_LOCAL_BACKEND_BRIDGE=1`;
2. rejects simultaneous `ISAC_BOOTSTRAP_TYPE3_PROBE=1` because the modes need
   different DR0 targets;
3. accepts only one complete, standalone type-`0x0003` frame from loopback;
4. waits for a verified transport delivery on anonymous reader ID 1, the
   channel-0 reader established by Finding 030;
5. verifies source vtable RVA `0x034863d8`, the live `reader+0x70` source
   pointer, and that state `reader+0x90` is not the closed value two;
6. calls the recovered outer lock, source append, reader notification, and
   outer unlock helpers in their retail order; and
7. records only type, length, reader ID, append count, and status.

TCP response bytes are reassembled into complete length-prefixed frames before
selection. Non-type-`0x0003` responses, including the current type-`0x0006`
fixture, remain observe-only. Payload bytes and object addresses are never
logged.

## Scope of the first run

The retail transport remains enabled because its first channel-0 delivery is
used to prove the target reader. The experiment can therefore receive a later
duplicate retail type-`0x0003`, and the minimal local profile carries only
synthetic empty values. The first run is a mutation-boundary validation, not
yet an offline login claim. Boundary success requires
`LOCAL_BRIDGE_INJECTION_READER_READY` followed by `LOCAL_BRIDGE_INJECTED` with
`status=notified`. Because DR0 is assigned to transport delivery in this mode,
the type-`0x0003` decoder breakpoint cannot be active simultaneously; client
acceptance is inferred from the resulting menu/error and request sequence.
