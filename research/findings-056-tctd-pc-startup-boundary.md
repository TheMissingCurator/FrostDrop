# Finding 056: disconnected startup is blocked at tctd-pc:27015

Date: 2026-09-25

## Evidence

```text
evidence/20260925-125555-offline-transport-startup-linux
```

The standalone Uplay shim supplied the local ticket, account ID, and display
name. Immediately afterward, Division made 216 resolver attempts for the
classified `tctd-pc` host on service `27015`. Every attempt failed with Winsock
error `11002` (`WSAHOST_NOT_FOUND`). No reader setup, reader registration,
outbound plaintext-writer, local stream-selection, or type-`0x0002` event
followed.

This places the immediate disconnected-startup boundary before profile login
and before the port-55000 plaintext bridge. Earlier connected Winsock evidence
shows the same name resolving and receiving a nonblocking TCP connection, but
the packet-capture filter in that experiment did not include port 27015. The
current corpus therefore does not establish whether that service is TLS,
HTTP, or a custom protocol.

## Targeted diagnostic

`ISAC_TCTD_PC_LOOPBACK=1`, used together with the transport-startup probe,
rewrites only the exact pair `tctd-pc.ubisoft.com:27015` to
`127.0.0.1:27015`. It obtains the replacement result through Wine's original
`getaddrinfo` trampoline, so the returned allocation remains compatible with
the application's normal `freeaddrinfo` call. All other names and services
pass through unchanged.

`tools/run-tctd-pc-listener.py` is a silent TCP listener. It records whether
the client sends the first bytes, classifies the protocol family, and retains
a bounded private copy of the client flight. It does not emulate a response.
The dedicated wrapper and runner are:

```text
tools/steam-tctd-pc-probe-wrapper.sh
tools/run-offline-tctd-pc-probe.sh
```

The Wine resolver smoke test verifies a valid IPv4 loopback result and safe
freeing. A separate listener smoke test correctly classified a real TLS
ClientHello and preserved its bounded client flight.
