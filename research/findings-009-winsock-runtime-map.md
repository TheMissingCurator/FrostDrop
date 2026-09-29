# Finding 009: Winsock runtime map

Date: 2026-09-22

Evidence: `evidence/20260922-004029-winsock-trace-connected-linux`

The capture combined the dedicated-port PCAP with Wine's `winsock` trace. The
full game process was Windows PID `0x04dc` (decimal 1244). Analysis used
`tools/analyze-winsock-trace.py` so launcher traffic and unrelated game
connections were excluded from the dedicated socket summary.

## Service names and sequence

The Winsock trace revealed names that were not available from the PCAP:

- `tctd-pc.ubisoft.com:27015` is resolved during initial startup;
- `tctd-pc-echo.ubisoft.com:51000` is resolved before each short mutual-TLS
  exchange;
- the port-55000 and port-55002 addresses are then used directly without a
  corresponding DNS lookup in the game process.

This supports the allocation model: the named port-51000 service returns or
helps establish the direct addresses used by the control, probe, and world
connections.

## Dedicated socket ownership

All dedicated sockets were created and connected by game thread `0x06c0`.
Observed handles in this run were:

| Purpose | Endpoint | Socket |
| --- | --- | --- |
| Initial allocation | `34.78.249.25:51000` | `0xf5c` |
| Initial control | `34.77.3.24:55000` | `0xf5c` (handle reused) |
| Five service probes | five direct IPs on port 55002 | `0x119c`–`0x11ac` |
| World allocation | `34.78.249.25:51000` | `0x1884` |
| World simulation candidate | `34.44.132.255:55000` | `0x1890` |

The `connect failed, status 0xc00000a3` messages in Wine's trace are not
terminal failures. The game deliberately uses nonblocking sockets, and the
PCAP shows each connection completing afterward.

## World-socket threading

The world candidate, socket `0x1890`, was traced for 58.7 seconds. Wine logged
8,743 receive attempts and 825 send attempts. The high number of receive calls
relative to PCAP packets is caused by nonblocking polling and does not describe
wire packet counts.

The main game thread (`0x04e0`) performed most receive polling. A pool of 15
worker threads (`0x0518` through `0x0550`) also serviced the socket and made
most send attempts. This is the first direct identification of the runtime
threads responsible for the world protocol.

The lower-rate control socket was also mostly polled by the main thread, with
occasional work from the same worker pool. This suggests a shared internal
network transport rather than separate Windows networking libraries.

## Next boundary

Winsock sees already-encrypted TLS records, so intercepting its buffers will
not reveal application messages. A narrowly filtered Wine relay trace was
tested against an isolated 64-bit Winsock program using the host's Wine 11.17
build. Wine loaded the `RelayInclude=ws2_32.*` filter but emitted no relay
records for Winsock exports. That route should not be repeated against the
game unless Proton's behavior is first shown to differ.

The next useful experiment therefore needs a targeted debugger or runtime
stack probe on the identified send/receive boundary. It should record only
return addresses or unique backtraces for sockets whose peer port is 55000;
payload capture at Winsock would add no value. The objective is to locate the
runtime-unpacked game routines immediately above the private TLS layer.
