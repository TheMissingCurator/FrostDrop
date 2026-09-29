# Finding 043: complete timed world-bootstrap corpus captured

Date: 2026-09-25

## Capture

```text
evidence/20260925-012804-world-bootstrap-private-linux
```

The `ISACWBS1` writer started on reader 12's complete type-`0x0002` sync frame
and closed itself on the first complete type-`0x0012`. The ordinary log reports
status `complete`; no stream parse error occurred.

The private file is mode `0600`, 78,925 bytes total, and contains 464 timed
spans holding 71,469 application-stream bytes. The inspector reconstructed 730
complete frames across 53 type IDs with zero buffered remainder. The first
type-`0x0012` was frame 729 at 18,786 milliseconds and had a 51-byte body. The
same final span contained one subsequent empty type-`0x0102` frame.

The pre-gate corpus contains 728 frames and 69,221 body bytes. Its first
substantial records were type `0x014d` with an 11,872-byte body and type
`0x0007` with an 11,179-byte body. The repeated pre-gate controls were 373
empty type-`0x0102` frames and 18 one-byte type-`0x0100` frames.

## Comparison and consequence

The sequence shape matches the earlier metadata-only run, but world entry took
18.8 rather than 15.9 seconds and the two large initial frame lengths changed
slightly. This supports treating the artifact as a session-specific causal
replay corpus, not a durable synthesized world state.

The next implementation can load this private format in the local backend,
emit the spans at their recorded relative times after the matching Continue
request, inject them into the selected world reader, and suppress the
corresponding retail reader only once local replay has begun. The last-span
post-gate type-`0x0102` can remain in the first replay because it was delivered
atomically with the completed gate frame.
