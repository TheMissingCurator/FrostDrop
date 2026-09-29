# Finding 055: disconnected startup stops before the login writer

Date: 2026-09-25

## Evidence

```text
evidence/20260925-123456-offline-local-full-replay-linux
```

The corrected standalone-Uplay integration run had the expected wrapper,
standalone loader, loopback backend, and disconnected physical interfaces.
The loopback bridge established its TCP connection, but the backend received
no bytes. The dispatch log contained no `LOCAL_BRIDGE_STREAM_SELECTED`,
`LOCAL_BRIDGE_TX`, `LOCAL_BRIDGE_RX`, reader-ready, or injection event.

This places the failure before profile decoding. The private type-`0x0003`
profile and world replay were never delivered to Division. In earlier
connected experiments, a genuine transport first caused the client to emit
its type-`0x0002` login request; the bridge selected that writer, and the first
small retail delivery subsequently established reader 1. Both prerequisites
are absent in the disconnected run.

## New diagnostic

`ISAC_TRANSPORT_STARTUP_PROBE=1` adds one metadata-only startup pass. It
classifies `connect`, `getaddrinfo`, and `GetAddrInfoW` calls without recording
endpoint addresses or resolver strings. Known Division names are represented
only as `tctd-pc` or `tctd-pc-echo`; other names are `localhost`, `numeric`, or
`other`. Connect targets are represented only by address family, port, and
scope (`loopback`, `private`, `link-local`, or `remote`). Return codes, Winsock
errors, and bounded game-relative caller RVAs are retained.

The four hardware execute breakpoints are reassigned to reader setup A, reader
setup B, reader registration, and the outbound plaintext writer. Because those
registers overlap the mutation path, transport diagnostic mode explicitly
disables login injection, retail isolation, and world replay. The loopback
bridge remains observe-only so a real type-`0x0002` request can still reach the
local backend if the writer appears.

The dedicated wrapper and runner are:

```text
tools/steam-transport-probe-wrapper.sh
tools/run-offline-transport-probe.sh
```

The hook smoke test validates both system Wine 11 and the analyzed Proton Wine
prologue variants. `tools/test-transport-startup-probe.sh` and the ordinary
standalone-Uplay smoke test both pass.
