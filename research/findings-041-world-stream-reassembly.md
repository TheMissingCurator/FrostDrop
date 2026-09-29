# Finding 041: the post-Continue world stream is now framed reliably

Date: 2026-09-25

## Capture

```text
evidence/20260925-011716-world-bootstrap-linux
```

The local 837-byte type-`0x0003` profile was injected on reader 1 and the
corresponding retail response was suppressed. Continue then produced the same
740-byte channel-0 envelope seen in the prior timeline. The private capture
decodes as one type-`0x0000` frame with a 733-byte body.

The request selected reader 12, 66 milliseconds after the outbound match. The
reader delivered five setup bytes and then one complete type-`0x0002` frame;
the new parser synchronized at that frame and remained synchronized for the
entire bounded trace. No `WORLD_STREAM_PARSE_ERROR` occurred.

## Bootstrap sequence

The first type-`0x0012` world-state frame was sequence 671, 15,902 milliseconds
after the Continue request. Before it, the parser observed 670 frames, 54
distinct type IDs, and 70,827 declared frame bytes. Of those frames, 315 were
empty type `0x0102` and 15 were one-byte type `0x0100`; 340 frames remained
after excluding those two recurring control types.

The first substantial responses were:

```text
sequence 1   type 0x0002  body 17 bytes
sequence 14  type 0x014d  body 11,890 bytes
sequence 15  type 0x0007  body 11,423 bytes
sequence 16  type 0x00dd  body 3 bytes
```

A larger bootstrap burst began near sequence 338 immediately before world
activation. The first type-`0x0012` had a 51-byte body. The metadata logger
reached its 4,096-frame display limit after the world activated but continued
parsing, and it reported no framing error.

## Consequence

Chunk-prefix false positives are eliminated: the project now has a trustworthy
ordered world-session type/length timeline. The next causal experiment should
privately capture the bounded raw reader-12 stream with per-delivery timing
from the initial type-`0x0002` synchronization point through the first complete
type-`0x0012` frame. That approximately 70-KiB pre-gate corpus can seed a
timed local replay. Retail reader-12 suppression should be added only alongside
that replay so failure means the local corpus was insufficient, rather than
merely absent.
