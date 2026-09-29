# Combined latency and main-channel setup

Date: 2026-09-26

## What changed our interpretation

`evidence/20260926-012807-offline-tctd-encrypted-backend-linux` shows the
55001 constructor requesting **556**, not the candidate main protocol 2056.
The client closes immediately after the old pre-TLS greeting, without sending
client bytes. The previous directory pointed both service kinds at that port.
This is a service/protocol mismatch, not evidence of a new certificate failure.

Five historical port-55002 flows in
`evidence/20260922-000956-backend-protocol-connected-linux/backend-ports.pcap`
establish the plain-TCP 556 exchange:

1. Server sends control type 3/version 556: `07 03 ac 04`.
2. Server sends application type 0/interval 200: `06 00 c8 01`.
3. Client sends type 1/sequence 0, 1, 2; server echoes each with type 2.
4. Client sends type 3 with five unsigned integers (count and timing data).

There is no preface or TLS on these flows. Static callers at 0x2fd51 and
0xe5a3f, initial consumer 0xbcb50, ping sender 0xb5eb0, pong consumer 0xbc9b0
and summary serializer 0x225ce30 agree with that exchange. The summary's
last timing field is not fully named; the server preserves it without claiming
more specific semantics.

## Main protocol setup from static code

Runtime text SHA-256:
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

- Main constructor 0x2f756 supplies 2056. This still needs current-game
  confirmation on the separated main endpoint.
- Initial root application type 7 is server-first. Parser 0x2258af0 reads a
  Boolean, optionally followed by a policy table. Consumer 0xb6920 clears the
  waiting flag at owner+0x53a. Register function 0xaf360 cannot proceed while
  that flag is set. Send false (`04 07 00`) to omit the optional table; true
  with zero entries enables an empty allowlist and blocks registrations.
- Client root type 0: uint32 request ID, two length-prefixed byte strings
  shorter than 64 bytes. Serializer 0x225ced0, caller 0xb6340. Successive
  writer calls finalize separate outer frames, not repeated records in one.
- Server root type 1: uint32 request ID, uint32 assigned channel ID, Boolean
  success. Reader 0x2258d10 and consumer 0xb72c0 correlate pending requests.
  Reader registrations become entries in owner+0x540; write registrations take
  another callback path. Their application pairing is still unknown.
- Root type 3 carries channel ID, byte count and inner framed bytes; writer
  0xd6b29 and reader/dispatcher 0x98160. Inner framing is per channel.
- Client root type 2 closes an assigned channel (0x225cde0).
- Client root type 8 contains an opaque bounded blob and uint64 lifetime
  (0x225cd90 -> 0xe0200). Receiving it is **not** proof of authentication.
- Client empty type 9 heartbeat (0x225ce20) receives server empty type 10
  (reader 0x22584f0). Type 11 has empty and uint32 diagnostic forms.

These are candidate responses derived from client code, not yet a successful
game login. Types 5/6 and application service bindings remain unresolved.

## One combined run

`tools/run-offline-tctd-channels.sh GAME_DIRECTORY COMPATDATA_DIRECTORY`
selects `tctd-channels`. It starts existing certificate bootstrap and directory
services, then both new listeners before capture:

- 55001: preface/TLS, candidate version 2056, initial settings, correlated
  channel acknowledgments, heartbeat replies, private inner-message capture.
- 55002: known plain-TCP version-556 latency responder, including all three
  ping/pong pairs and final timing summary.

The directory now assigns kind 0 to 55001 and kind 1 to 55002 in this mode.
**That kind-to-service mapping remains a hypothesis** based on static consumer
collections, not an observed successful split. The read-only constructor
checkpoint covers both ports to test it in the same run. The synthetic
directory revision changes to avoid reusing the previous combined routing.
Older runner modes retain their existing routes and transport-only behavior.

Steam launch options remain:

```text
"/path/to/ProjectISAC/tools/steam-tctd-echo-wrapper.sh" %command%
```

Keep networking off. Hostname rewriting is not a firewall. All new listeners
bind loopback and contain no upstream forwarding, but that alone does not
prove isolation of the entire game process. Press Enter to begin capture
before launching, then finish at the first stable error/menu and exit the game.

Public listener logs contain only stages, types, counts and channel/request
numbers. Names, identity blobs, plaintext and TLS keys remain in the private
0700 per-run directory, with files mode 0600. Main capture retains the previous
256-KiB input limit, 90-second session and 20-second idle limits; registrations
are limited to 64. Latency sessions have a 4-KiB/10-second limit. Combined
listeners share the 64-session/eight-worker limit. Malformed or unsupported
messages close the affected connection, preserving captured input.

No profile/world response is enabled here. The old bootstrap/replay messages
cannot safely be attached until registered reader/write service names and
their inner requests identify the correct bindings. This run attempts all
known setup gates together and captures that next layer if reached; it does
not promise a world load.

## Verification

173 Python tests pass, including synthetic CA-trusted TLS settings/registration/
heartbeat exchanges, plain-TCP latency completion, fragmented per-channel
frames, malformed input, privacy permissions, duplicate registrations, limits,
both actual CLI listeners starting together, and signal-driven clean shutdown.
These checks validate our implementation, not the retail client's acceptance.
The Wine allocation/checkpoint smoke test and full-loader transport startup
smoke test also pass, including the additional port-55002 constructor case.
