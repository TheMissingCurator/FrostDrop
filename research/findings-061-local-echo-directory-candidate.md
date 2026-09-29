# Port-51000 local TLS and candidate directory

Date: 2026-09-26

## Evidence and uncertainty

The offline `20260926-005401-offline-tctd-certificate-bootstrap-linux` capture
establishes local TLS, sends our 559-byte CA in its 568-byte bootstrap response,
then reaches `tctd-pc-echo:51000`. Its DNS resolution fails repeatedly with 11002
while disconnected. This was progress beyond the previous silent listener,
not successful offline login.

Reinspection of `20260922-000956-backend-protocol-connected-linux/backend-ports.pcap`
shows both port-51000 streams begin directly with TLS. Each client sends a
139-byte ClientHello flight and a 138-byte second flight; neither sends any
application-data record. The client's Certificate message has a THREE-byte
body `00 00 00`: the certificate list is empty. Earlier descriptions in
findings 007/009 calling this mutual TLS are therefore incorrect. The server
requests a certificate but accepts an empty list.

Each server sends one 319-byte encrypted application record. For the observed
TLS 1.2 AES-GCM suite, removing the 8-byte explicit nonce and 16-byte tag gives
295 application-plaintext bytes. Those bytes are NOT decrypted in this capture.
The service must send first; waiting for an application login request would
not reproduce the recorded ordering.

## Static candidate, not a promoted schema

The runtime code supplies a plausible directory reader at 0x2258520, called
at 0xb98f9. It reads:

1. 32 raw bytes (opaque identifier; consumer compares against its prior value).
2. An unsigned count and that many length-prefixed strings, each shorter than
   64 bytes.
3. An unsigned entry count. Each entry contains a host-table index, unsigned
   port-like value, another unsigned value, and a discriminator below 2.

0xb9a22 consumes the first value as a 16-bit port; 0xb9a4e divides the entries
into two collections according to the discriminator. The other value's meaning
is unknown. The related transport constructor call at 0xe5718 passes protocol
version 0x624 (1572). There is not yet live evidence tying this candidate reader
and version to the port-51000 connection. This mode explicitly tests that link.

`src/isac_protocol/service_directory.py` implements the candidate encoding and
strict local bounds. It uses the previously understood control-flag framing,
control type 3/version 1572, then application type 0. The test response has a
stable synthetic identifier, one loopback host, and two entries of different
kinds targeting port 55001. The extra unsigned field is provisionally zero.
The resulting response is 62 bytes, not a replay of the 295-byte retail data.

## Implementation

`tctd-echo` is separate from `tctd-bootstrap`. It runs both the functioning
port-27015 certificate bootstrap and a new port-51000 direct-TLS listener.
The latter uses a P-256 leaf signed by our persistent bootstrap CA, not another
verification override. Keys/captures stay private (0700 directories, 0600
files); no private keys or client payloads are printed in public logs.

The new Steam wrapper clears inherited ISAC flags and redirects only the exact
echo hostname plus port 51000, in both ANSI and Unicode resolver hooks. Other
hosts/ports are untouched. Keep the network disabled: this is not a firewall.

Three signature-checked, read-only hardware checkpoints share the run with the
existing port-27015 acceptance mechanism (DR0 remains reserved):

- DR1, 0x22412c0: log the requested version when the constructor port is 51000.
- DR2, 0xb98fe: log AL after the candidate parser, filtered to a port-51000
  transport belonging to the consumer.
- DR3, 0xb9ad8: report the consumer reaching its completion path, with the
  same port filter. This is not by itself proof of changed endpoint state.

No instruction bytes are patched at these checkpoints. Unreadable pointers
are ignored; log events are bounded; exception resume flags and last-error
state are preserved. Slot conflicts and instruction-signature mismatches stop
checkpoint installation. Neither a server send nor a Python round-trip counts
as game-side schema confirmation.

## One-run interpretation

Use `tools/run-offline-tctd-echo.sh GAME_DIRECTORY COMPATDATA_DIRECTORY` and
`tools/steam-tctd-echo-wrapper.sh` as the Steam wrapper, with networking off.
The runner starts all listeners before capture and includes ports 27015,
51000, 55001 and 55002 in the packet filter. It does not print launch-option
reminders. The current plaintext adapter still listens on 55000; the candidate
never advertises that port as a retail encrypted service.

Look in `tctd-echo-listener.log` and `tctd-echo-checkpoints.txt`:

- DNS redirected, TLS fails: investigate the CA/leaf trust path, not schema.
- TLS succeeds, expected protocol differs: correct candidate version/mapping.
- Expected protocol matches, parser returns zero: reject the schema hypothesis.
- Parser succeeds and loopback 55001 is attempted: directory delivery advanced
  to the next service; implement its encrypted transport next.
- Checkpoint absent: do not call it a parser failure; validate the candidate
  code-path mapping/installation first.

Port 55001 is intentionally unserved and must be free before the run. A
connection refusal there is an expected next boundary, not a playable backend.
No gameplay, profile/world injection or live-server fallback is enabled.

Validation: 152 Python tests pass, including two direct-TLS exchanges with a
distinct echo leaf trusted through the local bootstrap CA, codec bounds and
truncation tests, identity persistence, and wrapper flag hygiene. Wine smoke
tests pass for ANSI/Unicode resolver routing and synthetic checkpoint
contexts (signature mismatch, successful/failed parser events, port filtering,
unreadable owner pointers, DR0 preservation, slot conflicts, resume flags and
last-error preservation). Modified shell scripts pass `bash -n`.
Built local DLL SHA-256:
`7a768fa3c9c8ed88c47968642bba30d8239ededd13e2e345466cb08e40eb9cb2`.
