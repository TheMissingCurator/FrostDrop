# Local bootstrap backend

The first local-backend component is implemented in
`src/isac_backend/bootstrap.py`. It operates on decrypted application bytes
and deliberately contains no captured account identifiers, tokens, or session
payloads.

## Implemented boundary

For each connection, the backend:

1. incrementally reassembles client-to-server envelopes;
2. requires marker `0x03` and an initial envelope containing type `0x0002`;
3. emits a configured, typed, length-prefixed login response (`0x0003` for
   the recovered retail path, or the older `0x0002` framing fixture);
4. observes intermediate unknown frames without inventing responses;
5. treats a later channel-`0x0a` envelope containing type `0x0005` as the
   observed selector for a configured `0x0006` response; and
6. decodes the request's leading unsigned varint and writes it into the
   `0x0006` response's request-ID field.

The final association is now supported by the correlation capture: the
channel-`0x0a` `0x0005` request carried leading value zero and the `0x0006`
response 489 milliseconds later carried the same value. A later channel-`0x09`
type `0x0005` used a different value and belongs to the world-session path, so
the channel is part of the bootstrap selector.

## Plaintext loopback runner

The development runner listens only on loopback by default:

```bash
python3 tools/run-bootstrap-server.py \
  --profile docs/bootstrap-profile.example.json
```

The example values are synthetic and exist only to test framing. Validate a
private profile without opening a socket:

```bash
python3 tools/run-bootstrap-server.py \
  --profile bootstrap-profile.local.json \
  --check-profile
```

Profile values are encoded message bodies, excluding the type ID and outer
length prefix:

```json
{
  "control_request_channel": 10,
  "correlate_control_response": true,
  "type0003_body_hex": "...",
  "type0006_body_hex": "..."
}
```

Only one of `type0002_body_hex` and `type0003_body_hex` may be configured.
The former remains available for older framing tests; it is not the retail
login-response type. A structurally valid all-empty type-`0x0003` experiment
is provided in `docs/bootstrap-profile.type0003-minimal.json`. Its field
values are synthetic and are not yet proven acceptable to the game.

With correlation enabled (the default), the request ID encoded in
`type0006_body_hex` is a template value and is replaced for each matching
request. Set `correlate_control_response` to `false` only for protocol tests
that intentionally require a fixed value.

`bootstrap-profile.local.json` is ignored by source control. The runner logs
only phases, channels, and message type IDs; it never prints body bytes.

## Not yet a direct game endpoint

The retail client cannot connect directly to this runner yet. The known gap
before this application layer includes endpoint redirection, the observed
connection prefaces, and the encrypted transport/mutual-TLS boundary. The
client request schemas for types `0x0000`, `0x0001`, and most of `0x0002` and
`0x0005` remain opaque. The bootstrap `0x0005` correlation field is now
decoded, but valid semantic values for the two configured responses still need
to be established.

The bootstrap profile is now partially a response factory rather than a wholly
static test fixture. The remaining direct-game work is controlled inbound
injection, retail-path isolation, and a semantically valid local login profile.

## Observe-only game bridge

The first transport-adapter stage is now available in the forwarding DLL. It
connects only to loopback and activates when it sees the first outbound
plaintext writer carrying a valid type-`0x0002` bootstrap envelope. After that
activation, it forwards every structurally valid Division envelope to this
runner in order; writer-object identity is not a stream or session boundary.
It receives local responses but does not inject them into the game yet. The
retail network path is not suppressed or modified in observe-only mode.

Start the synthetic runner before launching the game:

```bash
python3 tools/run-bootstrap-server.py \
  --profile docs/bootstrap-profile.example.json
```

Use these Steam launch options:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 %command%
```

The bridge defaults to `127.0.0.1:55000`. A different loopback port can be
selected with `ISAC_LOCAL_BACKEND_PORT=PORT`; the host cannot be changed.

Inspect `project-isac-dispatch-probe.log` for `LOCAL_BRIDGE_` records. A
complete validation has `READY`, `CONNECTED`, `STREAM_SELECTED`, at least one
`READER_READY` after a retail inbound delivery, and `RX` after the synthetic
backend emits a response. Payload bytes and object addresses are not logged.

The first validation completed the full local state machine and returned both
synthetic frames to the bridge. It also showed that many valid reader/source
pairs share the delivery wrapper. A `READER_READY` record therefore validates
the pair but does not yet associate it with the pinned bootstrap writer. The
bridge remains receive-observe-only until that transport-to-reader association
is established.

The current correlation revision assigns stable anonymous reader IDs and adds
`LOCAL_BRIDGE_DELIVERY` records containing only total length, chunk count,
first frame type, and declared frame length. `LOCAL_BRIDGE_RELATION` compares
bounded pointer fields with the selected outbound transport and reports only
matching object-relative offsets. Local `RX` records likewise include only the
decoded first type and declared length. The launch options and capture workflow
are unchanged.

The corrected capture established that channel 0 does not answer its client
type-`0x0002` request with server type `0x0002`. Retail instead delivered a
type-`0x0003` frame on reader 1. Channel 10 was unambiguous: its type-`0x0005`
request led to server type `0x0006` on reader 11. The example profile's
type-`0x0002` response remains a framing fixture and must not be treated as a
game-compatible login response. The next protocol target is the inbound
type-`0x0003` schema.

## Focused type-0x0003 decoder-path probe

Set the following Steam launch options for the next main-menu capture:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_BOOTSTRAP_TYPE3_PROBE=1 %command%
```

This mode observes the shared virtual-reader helper at RVA `0x0009a7c0`, before
the source is copied into a temporary decode context. At this entry the reader
and its unconsumed frame cursor are both still available. The probe filters to
type `0x0003` and records only framing metadata, the anonymous reader method
RVA, normalized caller RVAs, and bounded executable-code windows. The response
body is never written to disk. Because this helper consumes the bridge's
delivery breakpoint, `LOCAL_BRIDGE_DELIVERY` correlation is intentionally
unavailable for the run; outbound forwarding and local-response observation
remain enabled.

The login decoder may run on a worker created after the DLL's initial
breakpoint pass. Once the first outbound type-`0x0002` envelope selects the
login stream, this mode therefore performs 12 bounded thread-refresh passes at
25-millisecond intervals. Each pass only installs the same verified hardware
execute breakpoints; it does not patch game code.

Reaching the main menu and waiting several seconds is sufficient. A useful run
contains `BOOTSTRAP_TYPE3_PROBE_READY` followed by a `CONTROL_PATH` record with
`type_id=0x0003`. No gameplay is needed.

The successful reader-entry capture identified the login-specific dispatcher
at RVA `0x00099490`. Its first Windows unwind region is only 53 bytes and ends
before the type switch. The probe therefore also captures a direct 4,096-byte
forward code window from that dispatcher during startup. This remains a
code-only capture; the response body stays disabled.

That window resolved type `0x0003` to its dedicated handler at RVA
`0x000b8160`. The same mode now captures a second 4,096-byte forward code
window from that handler. A main-menu-only run is sufficient; the objective is
to identify the handler's generated schema reader and field helpers, not to
collect gameplay traffic.

The handler window resolved its generated schema reader at RVA `0x022551b0`.
The mode now captures that reader as a third direct 4,096-byte forward window.
The next main-menu run should provide the first ordered type-`0x0003` field
map; response payload bytes remain disabled.

That schema window exposed the complete top-level read order and reduced the
remaining ambiguity to collection readers at RVAs `0x00215a0` and `0x0021640`.
Because both fit in the same range, the mode now captures a fourth 4,096-byte
forward window starting at `0x00215a0`. One further main-menu-only run should
close both helpers and make a structural type-`0x0003` codec implementable.

That final window closed both formats. Type `0x0003` now has a structural
decoder/encoder registered in `isac_protocol`, and the bootstrap runner can
emit it from a `type0003_body_hex` profile. No additional code-only schema
capture is currently required. The next boundary is the separately gated
inbound injection path; the existing bridge still logs local responses with
`injection=disabled` and leaves the retail stream untouched.

## First guarded type-0x0003 injection

The bridge now has a separate, explicitly opt-in injection mode. It is never
enabled by `ISAC_LOCAL_BACKEND_BRIDGE=1` alone. Start the synthetic minimal
profile in one terminal:

```bash
python3 tools/run-bootstrap-server.py \
  --profile docs/bootstrap-profile.type0003-minimal.json
```

For the first connected experiment, use these Steam launch options:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_LOCAL_BACKEND_INJECT=1 %command%
```

Do not combine `ISAC_LOCAL_BACKEND_INJECT=1` with
`ISAC_BOOTSTRAP_TYPE3_PROBE=1`; they need different use of the first hardware
breakpoint, and the DLL rejects that combination.

The injection mode accepts only one complete locally returned type-`0x0003`
frame. It waits up to five seconds for a real transport delivery on the
previously mapped channel-0 reader (anonymous reader ID 1), verifies the
persistent source vtable and that the reader is not closed, then invokes the
captured lock/append/notify/unlock sequence. Other response types remain
observe-only, response bodies are not logged, and a second type-`0x0003` is
not injected. Twelve bounded thread-refresh passes are made immediately after
the outbound login request so a newly created transport worker also receives
the delivery breakpoint.

This first experiment deliberately leaves the retail path enabled so the
reader can be established from a genuine delivery. It may therefore cause a
duplicate retail login response after the local one, and the synthetic empty
field values may be rejected. Stop at the first stable error, menu, or crash.
A successful append/notification boundary is proven by both of:

```text
LOCAL_BRIDGE_INJECTION_READER_READY
LOCAL_BRIDGE_INJECTED ... type=0x0003 ... status=notified
```

The injection mode cannot simultaneously place DR0 on the type-`0x0003`
decoder, so client acceptance is judged from the resulting stable menu/error
and any subsequent request sequence. The next stage after that proof is
offline reader discovery and retail-response suppression; neither is silently
enabled by this initial mutation test.

## Type-0x0003 retail-isolation experiment

The first injection capture proved that the local 23-byte frame was appended
and the reader was notified. It also showed the genuine 837-byte type-`0x0003`
reply arriving 188 milliseconds later, followed by the corresponding reply on
the second login reader ten seconds later. Reaching the world in that run does
not by itself prove that the client accepted the local frame.

The next opt-in experiment adds:

```text
ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1
```

It is valid only with both bridge and injection mode enabled. After a
successful local append/notification, it suppresses complete standalone
retail type-`0x0003` deliveries on anonymous readers 1 and 2. The four-byte
reader setup deliveries and every other message type remain untouched. Before
skipping a delivery, the probe also verifies the exact retail caller return
site recovered for the supported executable; a mismatch leaves the delivery
enabled and records an isolation error.

Run the same minimal profile, then use these Steam launch options:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_LOCAL_BACKEND_INJECT=1 ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1 %command%
```

Stop at the first stable menu, error, or crash rather than continuing into a
long gameplay session. A valid causal run must contain:

```text
LOCAL_BRIDGE_INJECTED ... type=0x0003 ... status=notified
LOCAL_BRIDGE_RETAIL_TYPE3_SUPPRESSED ... reader_id=1
```

A second suppression for reader 2 is expected if the channel-1 login attempt
occurs. If the client reaches the menu/world without either retail login
reply, the local type-`0x0003` is causally sufficient for this stage. If it
stalls or reports an error, the next distinction is between required nonzero
profile fields and a required second local reply.

The isolation run stalled at account login after suppressing the first two
retail replies. Starting again created channel 2 / reader 3, whose unsuppressed
retail type-`0x0003` allowed bootstrap to continue. This establishes that the
minimal zero-valued response does not supply the account/session semantics the
client requires.

## Private retail type-0x0003 profile capture

The next probe is an explicit one-frame payload exception. It is enabled only
with an observe-only loopback bridge:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_LOCAL_BACKEND_CAPTURE_TYPE3=1 %command%
```

Do not combine it with injection, isolation, or the focused type-`0x0003`
decoder probe. It copies the first complete retail login frame on reader 1 to:

```text
project-isac-type0003-private.bin
```

The file is created once and is never copied by
`tools/capture-startup-linux.sh`. The ordinary logs still contain only
framing metadata. The capture can contain account identifiers or short-lived
session material; do not commit or share it. The probe refuses to overwrite an
existing private capture.

Inspect field lengths, flags, integers, and truncated SHA-256 fingerprints
without printing the captured byte values:

```bash
python3 tools/inspect-type0003-profile.py \
  "/path/to/game/project-isac-type0003-private.bin"
```

For a bounded replay experiment, the same tool can create a mode-`0600` local
server profile and refuses to overwrite the requested path:

```bash
python3 tools/inspect-type0003-profile.py \
  "/path/to/game/project-isac-type0003-private.bin" \
  --write-profile private/type0003-retail-profile.json
```

Replaying the exact response is diagnostic, not the final offline-account
design: any ticket-like field may expire. Comparing private summaries across
two clean retail logins will identify stable profile fields versus per-session
values before the backend starts synthesizing its own local identity.

The first private capture decoded successfully as an 834-byte body inside a
complete 837-byte frame. Its redacted shape is:

```text
byte_0: 0
timed_blob_0: 240 bytes, uint64=8640
timed_blob_1: 240 bytes, uint64=604800
identity: discriminator=2, 36 bytes
bytes_0: 9 bytes
bools: 0,1,1
bundle_bools: 1,1,1,1,0,0,1
bundle_entries: lengths 3 and 4
timed_blob_2: 272 bytes, uint64=8640
```

The private replay profile is stored under the ignored, mode-`0700`
`private/` directory, and the profile itself is mode `0600`. Validate it
without displaying its payload:

```bash
python3 tools/run-bootstrap-server.py \
  --profile private/type0003-retail-profile.json \
  --check-profile
```

The next connected experiment reuses the established injection/isolation
mode with that private profile. It tests only whether a byte-exact legitimate
type-`0x0003` replay satisfies the login handler while the corresponding
retail replies are suppressed; it is not yet an offline or durable-account
claim.

The replay experiment reached the character/main menu without a retail
type-`0x0003` reply. Pressing Continue then emitted a separate large channel-0
type-`0x0000` request and created a new inbound reader about 100 milliseconds
later. This is the world-session handoff, not a second account-login request.

## Post-Continue world-bootstrap probe

The next opt-in stage captures that one outbound request privately and then
records a correctly reassembled message-type timeline for the first reader
created after it. It does not suppress the retail world session or inject
world data yet.

Start the local bootstrap server with the private login replay profile:

```bash
python3 tools/run-bootstrap-server.py \
  --profile private/type0003-retail-profile.json
```

Use these Steam launch options:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_LOCAL_BACKEND_INJECT=1 ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1 ISAC_WORLD_BOOTSTRAP_PROBE=1 %command%
```

The probe selects the first post-login channel-0 envelope containing one
type-`0x0000` frame between 512 and 2,048 bytes. It creates, but never
overwrites:

```text
project-isac-world-request-private.bin
```

The capture helper restricts that file to mode `0600` and records only its
presence in the evidence summary. It never copies, hashes, sizes, or prints
the file. Move any prior capture to a private archive before another run.

After the request, the probe selects the first newly created transport reader.
It ignores the reader's setup bytes, synchronizes on its first complete
type-`0x0002` frame, and incrementally parses subsequent frames across
arbitrary transport-delivery boundaries. `WORLD_STREAM_FRAME` records contain
only reader ID, sequence, type ID, declared length, type-varint length, and
body length. No inbound body bytes are logged.

A useful run reaches Continue and remains in the world until the first
type-`0x0012` frame or a stable loading failure. It should contain:

```text
WORLD_REQUEST_CAPTURED ... channel=0x00,type=0x0000
WORLD_STREAM_READER_SELECTED
WORLD_STREAM_SYNCED ... sync_type=0x0002
WORLD_STREAM_FRAME ... type_id=0x0012
```

Inspect the private request's framing and fingerprints without printing its
body:

```bash
python3 tools/inspect-world-request.py \
  "/path/to/game/project-isac-world-request-private.bin"
```

This capture separates the next two implementation tasks: decode the
Continue request's schema, and identify the minimum ordered server frame set
needed to leave loading. Retail world-response suppression is intentionally
deferred until a local replacement exists, avoiding a guaranteed loading
deadlock.

## Private timed world-bootstrap capture

The metadata run stayed synchronized through 4,096 logged frames and placed
the first type-`0x0012` at sequence 671, 15.9 seconds after Continue. Enable
the separately gated payload capture for the next connected run by adding:

```text
ISAC_WORLD_BOOTSTRAP_CAPTURE=1
```

The complete Steam launch options are:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_LOCAL_BACKEND_INJECT=1 ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1 ISAC_WORLD_BOOTSTRAP_PROBE=1 ISAC_WORLD_BOOTSTRAP_CAPTURE=1 %command%
```

After stream synchronization, this mode creates:

```text
project-isac-world-bootstrap-private.bin
```

The `ISACWBS1` file contains relative millisecond timestamps, delivery-span
flags, and raw reader-12 bytes. Capture begins with the complete type-`0x0002`
sync frame and stops only after the first complete type-`0x0012` frame. It is
bounded to 2 MiB and 8,192 span records and refuses to overwrite an existing
file. The capture helper applies mode `0600` and never copies, hashes, sizes,
or prints it in ordinary evidence.

Because this artifact can contain account, character, and world-session data,
keep it private. Inspect only structure, timing, frame counts, lengths, and
fingerprints with:

```bash
python3 tools/inspect-world-bootstrap.py \
  "/path/to/game/project-isac-world-bootstrap-private.bin"
```

A complete run contains `WORLD_SNAPSHOT_CAPTURE_STARTED` followed by:

```text
WORLD_SNAPSHOT_CAPTURED ... status=complete ... reason=first-complete-type-0x0012
```

Once validated, the same timed corpus can be used to implement the first
connected local replay experiment. World-reader suppression remains disabled
in this capture stage.

## First timed local world replay

The local runner can now validate and replay a private `ISACWBS1` corpus. The
loopback bridge uses a 16-byte `ISACRPL1` control marker to arm the DLL before
the first timed span; this marker exists only between Project ISAC components
and is never injected into the game.

Start the server with both private artifacts:

```bash
python3 tools/run-bootstrap-server.py \
  --profile private/type0003-retail-profile.json \
  --world-replay \
  "/path/to/game/project-isac-world-bootstrap-private.bin"
```

Use these Steam launch options, replacing capture mode with replay mode:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_LOCAL_BACKEND_INJECT=1 ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1 ISAC_WORLD_BOOTSTRAP_PROBE=1 ISAC_WORLD_BOOTSTRAP_REPLAY=1 %command%
```

When the backend recognizes the large channel-0 type-`0x0000` Continue
request, it sends the arm marker immediately and then emits the private spans
at their recorded request-relative times. The DLL retains the first small
retail reader-setup delivery, selects that exact reader/source pair, and
suppresses later retail reader-12 deliveries after the arm marker. Complete
local frames are appended and notified through the verified inbound helper
sequence. Locally injected frames are also passed through the persistent
metadata parser, so its type timeline describes the replay rather than the
suppressed retail stream.

Replay isolation is bidirectional. The initial selected world request is
allowed to reach retail because its small setup delivery currently supplies
the reader/source association. Once the loopback `ISACRPL1` arm marker is
received, every later structurally valid Division envelope at the serializer
handoff is copied to the local backend and the verified call at RVA
`0x00d6bbf` that would hand it to a retail transport is skipped. The writer
argument at this call site is stack-local and changes across producer threads,
so writer-pointer filtering is explicitly not used. The call's result is unused
at this site, so the client-side producer continues without requiring synthetic
Winsock completion behavior.

`WORLD_REPLAY_OUTBOUND_ISOLATION_STARTED` confirms the first skip;
`WORLD_REPLAY_OUTBOUND_SUPPRESSED` provides bounded progress records. Any
`WORLD_REPLAY_OUTBOUND_ISOLATION_ERROR` invalidates the run. Post-arm calls
that still reach the port-55000 Winsock path are recorded as
`WORLD_REPLAY_RETAIL_WIRE_SEND` with socket ID and length only. Those audit
records can include data already queued by the retained request or transport
control traffic, but persistent application-sized sends require investigation
before gameplay testing continues.

This is still a connected causal experiment: a genuine initial reader setup
is currently required to discover the world reader. Later application
gameplay envelopes are locally redirected, but the underlying retail
transport remains connected for this setup dependency. It does not claim durable
offline play, and the captured world payload may contain expired or
session-specific fields.

Stop at world entry, a stable loading failure, or a crash. Useful evidence
contains:

```text
WORLD_REPLAY_ARMED
WORLD_REPLAY_SETUP_RETAINED
WORLD_REPLAY_RETAIL_SUPPRESSED
WORLD_REPLAY_INJECTED ... sequence=1,type_id=0x0002
WORLD_REPLAY_GATE_INJECTED ... type_id=0x0012
```

If the client enters the world while the retail reader remains suppressed,
the captured local corpus is causally sufficient through the first world
gate. If it fails, the ordering of these records distinguishes reader setup,
replay timing, append failure, and payload rejection.

## Post-gate continuation and labeled gameplay capture

The first local replay reached an interactive but incomplete Post Office. It
provided inventory and stash state, but the Base of Operations presentation,
exit, and fast travel were incomplete. To test whether later authoritative
progression and world-phase messages fill that gap, add:

```text
ISAC_WORLD_CONTINUATION_CAPTURE=1
```

Continuation mode requires `ISAC_WORLD_BOOTSTRAP_CAPTURE=1`. It keeps the
same private `ISACWBS1` format and first-`0x0012` gate marker, but continues
recording the selected world reader until clean game shutdown or a safety cap
of 16 MiB/65,536 delivery spans. Payload-free bootstrap metadata is raised to
32,768 records so longer gameplay transitions retain outbound type and
channel evidence. The probe still refuses to overwrite an existing private
capture.

Use these Steam launch options for a connected continuation capture:

```text
ISAC_STACK_PROBE=1 ISAC_LOCAL_BACKEND_BRIDGE=1 ISAC_LOCAL_BACKEND_INJECT=1 ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1 ISAC_WORLD_BOOTSTRAP_PROBE=1 ISAC_WORLD_BOOTSTRAP_CAPTURE=1 ISAC_WORLD_CONTINUATION_CAPTURE=1 %command%
```

The Linux capture helper can record payload-free action boundaries in the
evidence directory:

```bash
ISAC_ACTION_MARKERS=1 ./tools/capture-startup-linux.sh \
  world-continuation \
  "/path/to/Tom Clancy's The Division" \
  "/path/to/steamapps/compatdata/365590"
```

Enter labels after stable observations, or bracket an action with matching
`begin_NAME` and `end_NAME` labels. Useful labels include `hub_stable`,
`begin_ammo_box`/`end_ammo_box`, `begin_region`/`end_region`, and
`begin_fast_travel`/`end_fast_travel`. Exit the game cleanly before submitting
an empty label so the private stream is flushed and closed.

Correlate the selected-reader inbound stream with payload-free outbound
metadata afterward:

```bash
python3 tools/analyze-world-continuation.py \
  "/path/to/project-isac-world-bootstrap-private.bin" \
  evidence/TIMESTAMP-world-continuation-linux/action-markers.tsv \
  evidence/TIMESTAMP-world-continuation-linux/project-isac-plaintext-probe.log
```

For a region window, a new outbound type/channel burst followed by distinct
inbound types supports a server-backed region-state request. No corresponding
network change supports client-only asset or presentation streaming. Fast
travel may also reveal a new reader; the ordinary dispatch log remains
enabled so that case is visible even though the private payload capture stays
restricted to the selected world reader.

Create a replay-safe slice at a named marker with:

```bash
python3 tools/slice-world-bootstrap.py \
  private/world-continuation-actions.bin \
  evidence/TIMESTAMP-world-continuation-linux/action-markers.tsv \
  hub_stable \
  private/world-bootstrap-hub-stable.bin
```

The slicer chooses the last complete frame boundary at or before the marker,
preserves timestamps and flags, refuses to overwrite its output, writes mode
`0600`, and validates the result through the backend's `WorldReplay` loader.
It reports any gap between the requested marker and the selected safe
boundary without printing captured bytes.
