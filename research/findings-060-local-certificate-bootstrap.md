# Local certificate bootstrap service

Date: 2026-09-26

## What the capture actually contains

Capture `20260926-004037-connected-tctd-allocation-linux` and private artifact
`tctd-allocation-f88UPpmq/records.bin` contain 668 decrypted bytes, a successful
message descriptor, 659 parsed bytes, and an identical 659-byte handoff.
OpenSSL identifies that blob as a self-issued P-256 X.509 CA certificate,
not an endpoint allocation list. Certificate SHA-256:
`a6d23ee5f0e53e2a9e9e00f5c873e9c4bcb342550127262565179ec47861b5af`.

The exact nine-byte prefix is `07 03 af 02 ac 0a 00 93 05`:

- `07`: three-byte transport control frame, low bit set.
- `03 af 02`: control type 3, unsigned version 303.
- `ac 0a`: 662-byte application frame, low bit clear.
- `00 93 05`: application type 0, 659-byte length-prefixed certificate.

Static cross-check: 0x223bbd0 shifts the length right one; 0x2239fc0 retains
the low-bit control flag; 0x2248663 requires control type 3 and checks its
version against the constructor's 303. The certificate parser at 0x2258d90
limits the blob to 10000 bytes. The handoff at 0xbb4df reaches 0x223b570 and
0x223b6d0, which decode the certificate, obtain its public key and add it to
a certificate store. This corrects the earlier allocation-list hypothesis.

## Implemented stage

`certificate_bootstrap.py` encodes this exchange with calculated lengths.
`run-tctd-pc-tls-probe.py --serve-certificate` sends it immediately after the
TLS handshake. The new `tctd-bootstrap` integration mode uses a persistent,
newly generated Project ISAC P-256 CA identity. Both TLS and the application
certificate use this identity; no captured Ubisoft certificate or private key
is used. Captured 36/8-byte transport prefaces are still reused.

The wrapper enables the existing loopback-only TLS acceptance mechanism and
clears inherited capture flags. The game DLL does not change for this stage.
The listener logs certificate length/hash and explicitly marks client
acceptance unconfirmed. Sending the response is not evidence of installation
in the game's certificate store.

## Test procedure and limits

Use `tools/run-offline-tctd-bootstrap.sh GAME_DIRECTORY COMPATDATA_DIRECTORY`
with the `steam-tctd-bootstrap-wrapper.sh` Steam launch wrapper. Disable the
network for the game run: only tctd-pc port 27015 is redirected, and later
remote connections are not blocked by this wrapper. The runner starts the
services, prompts to begin capture, then prompts for the game launch. Stop at
the first stable error and close the game before ending capture.

Look for TLS establishment followed by `TCTD_PC_CERTIFICATE_SENT`, then
compare startup connection ordering against the connected baseline. The
baseline proceeds to port 51000 and 55002. An attempted next connection is
progress, not proof that every intermediate return value succeeded.

Later encrypted service transports are NOT implemented here. The existing
port-55000 plaintext adapter is not their wire-compatible replacement, and
this mode deliberately does not combine diagnostic breakpoints with profile
or world injection. A loading error remains possible and expected. Full
login, character selection, world state and persistent gameplay still need
the subsequent services.

Tests cover exact observed framing with synthetic payloads, variable lengths,
truncation/malformed input, and a real local TLS exchange using a new identity
trusted explicitly by the test client. Game acceptance requires the next run.

Validation completed: all 145 Python tests pass with local socket access;
modified shell scripts pass `bash -n`. The private 668-byte response round-trips
byte-for-byte, and its decoded certificate equals both the parsed and handoff
records. The installed game DLL matches the current build (SHA-256
`b1d9f573b23f11aa7459588b3cb6c7da48f9506ab985e193bc895956b6778277`),
so this service-only change needs no DLL reinstall.
