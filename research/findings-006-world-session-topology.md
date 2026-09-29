# Finding 006: world-session connection topology

Date: 2026-09-22

Evidence: `evidence/20260921-235620-backend-world-connected-linux`

## Successful path

The capture covered a normal launch, character selection, world entry, and
roughly 30 seconds of movement. The full game process started at approximately
23:56:52 and remained healthy through the end of the capture at 23:58:15.

Two Uplay functions appeared that were absent from the earlier menu-only run:

- `UPLAY_USER_SetGameSession` at monotonic tick 34471228
- `UPLAY_WIN_RefreshActions` at monotonic tick 34488754

`UPLAY_USER_SetGameSession` is useful as a high-resolution marker for the
gameplay-session transition. It does not itself prove which network endpoint
implements that session.

## Dedicated endpoint sequence

| Approximate event | Endpoint | Lifetime observed |
| --- | --- | --- |
| Initial game-service connection | `35.240.79.80:55000` | 23:57:02–23:58:15 |
| Regional/service fan-out | five hosts on port `55002` | 23:57:02–23:57:04 |
| Session-transition exchange | `34.78.249.25:51000` | less than one polling interval at 23:57:27 |
| Selected persistent endpoint | `34.44.132.255:55000` | 23:57:29–23:58:15 |

The five short-lived port 55002 targets included `34.44.132.255`. About 25
seconds later, that same address was selected for a persistent port 55000
connection immediately following the game-session marker.

## Working model

The evidence supports this provisional division of roles:

1. `35.240.79.80:55000` — bootstrap, login, or session-control service.
2. Port `55002` fan-out — regional availability or latency probes.
3. Port `51000` — short allocation, ticket, or handoff exchange.
4. `34.44.132.255:55000` — selected gameplay/world service.

This is an inference from connection timing and reuse of the selected probe
address, not yet a protocol-level identification.

## Next experiment

Capture only TCP ports 51000, 55000, and 55002 from launch through world entry.
This avoids unrelated web/account traffic while revealing:

- whether the protocol is plaintext, TLS, DTLS-like, or a custom framed stream;
- initial client/server message sizes and ordering;
- whether the two persistent 55000 connections share a handshake format;
- whether the 55002 probe payload is identical across candidate hosts;
- whether the 51000 response supplies the chosen world endpoint.

Packet contents may contain opaque session material and must remain local to
the research workspace. Analysis should report structure and hashes rather
than publishing live tokens.
