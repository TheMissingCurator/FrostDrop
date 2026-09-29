# Finding 044: first timed local world replay stage implemented

Date: 2026-09-25

## Backend

The local backend now loads and validates a private `ISACWBS1` artifact. It
requires monotonic timestamps, exactly one synchronization span, exactly one
completed-gate span, an initial type-`0x0002`, a complete frame stream, and at
least one type-`0x0012`. The large channel-0 type-`0x0000` request selects the
world replay without hard-coding private request bytes.

The server writes an immediate loopback-only `ISACRPL1` arm marker and emits
each captured span at its request-relative millisecond offset. It uses
`TCP_NODELAY` and continues reading client envelopes while the timed replay
runs. Logs contain counts and types only.

## Game bridge

`ISAC_WORLD_BOOTSTRAP_REPLAY=1` is separately gated and conflicts with private
capture mode. After the arm marker, the bridge retains one small reader setup
delivery and suppresses subsequent retail deliveries on the selected world
reader. The exact supported-build return site is checked before every skip.

Loopback bytes are reassembled into complete length-prefixed frames. Each
frame is appended to the retained world source using the verified outer lock,
source append, reader notification, and unlock helpers. The local stream also
feeds the persistent metadata parser. Injection and suppression records expose
only type IDs, lengths, sequence numbers, and status.

## Experiment boundary

This first replay remains connected because the retail transport's initial
setup delivery is used to discover reader 12. Success would prove local
sufficiency only through the captured first type-`0x0012`; the corpus contains
no ongoing simulation after that point. The next boundary after a successful
run is creating the world reader/source association without a retail delivery,
followed by replacing session-specific captured values with locally generated
state.
