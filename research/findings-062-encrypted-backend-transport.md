# Local port-55001 backend transport

Date: 2026-09-26

## What the last game capture established

`evidence/20260926-011229-offline-tctd-echo-directory-linux` records:

- Local certificate bootstrap on 27015 and direct TLS on 51000 succeed.
- The 51000 constructor requests protocol 1572.
- The directory parser returns 1 and its consumer reaches completion.
- The client then attempts loopback port 55001, which had no listener.

This validates the synthetic directory for this path, not every possible
directory field or offline login. In particular, the extra unsigned entry
value remains unexplained. There is no evidence it is the protocol version.

## Transport evidence and remaining hypotheses

The two historical port-55000 flows in
`evidence/20260922-000956-backend-protocol-connected-linux/backend-ports.pcap`
both start with a 36-byte server greeting beginning `46 01 02 20`, then an
8-byte client greeting beginning `0e 01 00 04`, server `04 00 01`, and TLS.
Their client greeting suffixes are `00000000` and `02000000`; the certificate
service's suffix is `08000000`. The new endpoint checks size/header, preserves
the suffix privately and does not require it to equal the certificate-service
template. It reuses that service's 36-byte greeting template. Its suitability
for the current game connection still needs verification.

Static runtime text (SHA-256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`) shows a
transport-constructor call at RVA 0x2f756 with R9D=0x808 (2056). This is our
candidate backend protocol version, not yet observed on the current 55001
connection. The existing read-only constructor checkpoint now logs 55001 as
well as 51000, so the same run can check it. No additional certificate-trust
override or debug-register slot was added.

The old bridge captures a different layer from the TLS wire:

- RVA 0xd6b29 constructs a root message; 0xd6b33 sets type 3; subsequent
  writes serialize channel, length and opaque inner message bytes.
- Root inbound dispatcher 0x9a000 routes type 3 to 0x98160, which reads a
  channel and length and delivers the bytes to a registered reader.
- Other root types have separate handlers. For example root type 1 reaches
  0xb72c0; root type 8 is constructed on the outbound path at 0xb78a0.
  Their complete setup schemas/semantics are not established here.

Therefore outbound channel numbers must not be assumed to identify inbound
readers, and the old login responses cannot simply be written to TLS. The
`ISACRPL1` command is private bridge machinery, never a retail wire message.
World captures are inner reader spans, not complete outer transport exchanges.

## Implementation and boundaries

`tools/run-offline-tctd-backend.sh` selects the combined `tctd-backend` mode:
27015 certificate bootstrap, 51000 directory, and 55001 preface/TLS/version
endpoint all start before capture. The existing plaintext bridge on 55000
remains separate. The Steam wrapper stays `steam-tctd-echo-wrapper.sh`.

55001 binds only 127.0.0.1, uses the existing localhost leaf signed by the local
bootstrap CA, and sends control type 3/version 2056. It has no remote upstream
connection and no login/world response handler yet. The runner still requires
networking to be disabled: exact hostname rewrites are not general isolation.

`src/isac_protocol/transport.py` decodes the outer length/control flag,
message type and opaque body incrementally, preserving control vs application
type 3. The latter's channel/length pair is decoded only when structurally
valid. Inner message schemas are not guessed. Existing inner-frame codecs
are unchanged.

`tctd-backend-listener.log` contains staged metadata, not payloads. Plaintext,
client greetings and TLS keys go into the existing private per-run directory
(0700 directory, 0600 files). Capture is bounded to 256 KiB per connection,
64 accepted sessions, 8 concurrent workers, 90 seconds per session and a
20-second idle timeout. Metadata is limited to 512 frames per connection.
Malformed framing ends the connection but preserves the received bytes.
Shutdown stops active post-handshake readers before copying private artifacts.

Interpret the next run in order:

1. Constructor checkpoint: is 55001's requested version actually 2056?
2. Listener: did greeting and TLS complete using the local CA?
3. Root frames: did the client send transport controls or application messages?
4. Use private root bytes to establish setup/channel registration before
   connecting the existing bootstrap state machine to this transport.

`VERSION_SENT` is not proof of acceptance. `root-frames-received` is not a
login or world-load success. Another loading error remains possible and is
not a reason to reconnect to Ubisoft during this test.

## Verification

160 Python tests pass, including actual synthetic TLS with the generated CA,
different greeting suffixes, fragmented/coalesced framing, malformed/oversize
input, capture privacy, byte limits and clean shutdown. Wine synthetic tests
cover the expanded constructor checkpoint, signature rejection, existing
directory checkpoints and preservation of DR0/last-error/resume state.
These tests do not substitute for a game capture.
