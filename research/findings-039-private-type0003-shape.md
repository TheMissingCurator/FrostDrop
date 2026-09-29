# Finding 039: private retail type-0x0003 capture decodes completely

Date: 2026-09-25

## Capture

```text
evidence/20260925-005822-type3-private-profile-linux
```

The observe-only probe captured exactly one complete reader-1 retail login
frame. The normal evidence bundle contains no payload copy. The private file
is 837 bytes, mode `0600`, and structurally decodes to type `0x0003` with an
834-byte body.

## Redacted field shape

The response contains three substantial opaque timed blobs: 240 bytes with
value 8,640; 240 bytes with value 604,800; and 272 bytes with value 8,640. It
also contains a discriminator-2 identity with 36 bytes, a separate 9-byte
field, top-level flags `0,1,1`, bundle flags `1,1,1,1,0,0,1`, and two bundle
entries of three and four bytes. Only lengths, integers, Boolean values, and
SHA-256 fingerprints were printed; captured bytes remain private.

The large opaque fields and lifetime-like integers are consistent with
account/session tickets rather than a simple display-name profile. This is an
inference, not yet a semantic identification.

## Replay artifact

The inspector created `private/type0003-retail-profile.json` with mode `0600`
inside a mode-`0700` ignored directory. The bootstrap loader accepted it as a
valid type-`0x0003` response. The next causal experiment injects this exact
response while suppressing the reader-1/reader-2 retail type-`0x0003`
deliveries. Success proves byte-exact replay at this handler; later captures
and controlled field comparisons are still required for durable synthesis.
