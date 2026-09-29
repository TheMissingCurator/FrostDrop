# Standalone local Uplay compatibility shim

The first standalone compatibility DLL is built at
`dist/uplay_local/uplay_r1_loader64.dll`. It exports the same 89 names and
ordinals as the analyzed retail loader but does not load or forward to Ubisoft
Connect's `uplay_r1_loader64_isac_original.dll`.

This is an early compatibility stage, not a finished launcher. It implements
the startup contracts established by the bounded ABI and caller-code captures:

- `UPLAY_Start` accepts the observed product ID and reports success;
- local account ID, display name, and ticket getters return project-owned
  strings;
- ownership and connection checks report true while client-facing offline mode
  remains false, matching the state Division expects before backend login;
- update, social initialization, presence, game-session, and action-refresh
  calls return their observed success forms; and
- unsupported saves, store, overlay, and asynchronous social operations return
  zero instead of fabricating undocumented output structures.

The deterministic development identity is:

```text
Account ID: 49534143-0000-4000-8000-000000000001
Name:       ProjectISAC
Ticket:     project-isac-local-ticket-v1
```

These are Project ISAC values, not Ubisoft credentials. Per-profile identity
files and locally signed tickets come after this startup boundary is validated.

The existing Winsock/local-backend bridge is linked into the standalone DLL,
so the established `ISAC_LOCAL_BACKEND_*` and world-replay modes remain
available. Probe-only ABI forwarding is intentionally absent.

## Build and test

```bash
./tools/build-uplay-local.sh
./tools/test-uplay-local.sh
```

The Wine smoke test loads the DLL without any retail forwarding target,
validates all 89 name/ordinal exports, exercises the implemented startup
surface, and confirms unsupported features fail closed.

## Reversible installation

Close Division and Ubisoft Connect first, then check status:

```bash
./tools/manage-uplay-local.sh status "/path/to/The Division"
```

Install the standalone shim:

```bash
./tools/manage-uplay-local.sh install "/path/to/The Division"
```

Restore the verified retail loader:

```bash
./tools/manage-uplay-local.sh restore "/path/to/The Division"
```

The manager requires the analyzed retail backup hash and never deletes the
backup. The local call log contains export names and timing metadata only; it
does not record arguments, identity strings, tickets, or payloads.

## First game validation

The first run should test only whether the game process reaches its own startup
path without launching or contacting Ubisoft Connect. Do not enable ABI-probe
mode; the standalone DLL has no retail target to observe. Capture the run with
`tools/capture-startup-linux.sh`; it will include only newly appended records
from `project-isac-uplay-local.log` and any explicitly enabled bridge logs.

## Combined offline backend and gameplay-replay test

After standalone launch succeeds, the complete integration runner starts the
local bootstrap server, validates the private login profile and replay corpus,
runs the normal evidence capture, and copies the backend transcript into the
same evidence directory:

```bash
./tools/run-offline-integration.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Its default `full` replay contains 51,280 complete inbound frames over roughly
5.5 minutes, including world bootstrap, the stable hub state, and the captured
gameplay/action period. `hub` and `gate` may be passed as a third argument for
shorter diagnostic runs. The runner does not change Steam's configuration or
network state. It prints a single `steam-offline-wrapper.sh %command%` launch
option, waits for confirmation that it was saved, and requires the standalone
DLL to already be installed. The wrapper exports the bridge/replay environment
directly into Proton, avoiding mistakes in the long individual-variable form.

## Offline transport-startup diagnostic

If a disconnected integration run reaches ROMEO before the local backend sees
the initial type-`0x0002` request, run the bounded transport diagnostic:

```bash
./tools/run-offline-transport-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

The runner prints a separate `steam-transport-probe-wrapper.sh %command%`
launch option. Keep physical interfaces disconnected and stop after ROMEO or
the first stable menu. This diagnostic intentionally disables profile and
world injection because it assigns the four hardware breakpoints to:

- reader setup A at RVA `0x005fb10`;
- reader setup B at RVA `0x005fed0`;
- the outbound plaintext writer at RVA `0x000d6bbf`; and
- reader registration at RVA `0x000af360`.

It additionally observes the Wine `connect`, `getaddrinfo`, and `GetAddrInfoW`
boundaries. Resolver names are reduced to known service classes, socket
addresses are reduced to scope and port, and only return/error values plus
game-relative caller RVAs are retained. No IP address, ticket, protocol body,
or packet payload is written to the logs.

Useful events are:

```text
TRANSPORT_RESOLVE
TRANSPORT_CONNECT
TRANSPORT_STARTUP_MILESTONE
LOCAL_BRIDGE_STREAM_SELECTED
```

The isolated hook test is:

```bash
./tools/test-transport-startup-probe.sh
```

## Initial tctd-pc loopback diagnostic

The disconnected transport capture established that startup repeatedly stops
at `tctd-pc.ubisoft.com:27015`. The next diagnostic rewrites only that exact
host-and-service pair to `127.0.0.1:27015`; every other resolver request is
left unchanged:

```bash
./tools/run-offline-tctd-pc-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use the printed `steam-tctd-pc-probe-wrapper.sh %command%` launch option and
keep physical interfaces disconnected. A silent loopback listener accepts the
connection but deliberately sends no bytes. Its evidence log establishes
whether the client speaks first and classifies the first client data as TLS,
HTTP, printable text, or custom binary.

The listener stores at most 64 KiB of each client-first flight under the
project's `private/` directory with mode `0600`. The ordinary evidence
directory receives only protocol classification, byte counts, the first eight
framing bytes, and a SHA-256 digest. This keeps a potentially ticket-bearing
message out of the normal evidence corpus while retaining it for local
protocol analysis.

The loopback result establishes that port 27015 is server-first. Capture the
missing initial server flight with one narrowly filtered connected run:

```bash
./tools/run-connected-tctd-pc-capture.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

The runner refuses to proceed unless the installed loader exactly matches the
built standalone shim. This ensures Division has only the deterministic
Project ISAC ticket, account ID, and name; the real Ubisoft credential is not
available to the game process. The packet filter is exactly `tcp port 27015`.
No gameplay is required: stop after the first stable menu/error or about 20
seconds of loading.

The raw PCAP remains private. Payload-free flow metadata is written beside it,
while the reassembled first server and client flights are placed under
`private/` with mode `0600` for the subsequent local replay experiment.

## Local tctd-pc preface and TLS probe

The connected capture established a 36-byte server greeting, an 8-byte client
reply, a 3-byte server transition, and then TLS 1.2. Run the first local
termination experiment with:

```bash
./tools/run-offline-tctd-pc-tls-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Set Steam to the wrapper for the selected probe mode and keep physical network
interfaces disconnected. The runner starts the existing local
bootstrap server, redirects only `tctd-pc.ubisoft.com:27015` to loopback,
replays the captured server greeting, validates the client's 8-byte reply,
sends the captured transition marker, and offers a local TLS 1.2 server using
the observed ECDSA/P-256 cipher profile.

The probe intentionally sends no application data after TLS. This separates
three outcomes cleanly:

- no 8-byte reply means the replayed server greeting is not sufficient;
- a TLS alert or disconnect means local certificate acceptance is the next
  boundary;
- `TCTD_PC_TLS_ESTABLISHED` means the local process owns the decrypted
  allocation channel and the next task is reconstructing its first response.

The generated local certificate, TLS key log, client preface, and any decrypted
client application bytes remain under `private/` with restrictive modes. The
ordinary evidence directory contains the listener log, port-27015 packet
capture, and payload-free metadata analysis.

## Port-27015 certificate-read probe

The first local TLS run reached the client certificate-validation boundary: the
game sent a ClientHello, received the complete local server handshake, and then
closed without sending its client handshake flight. Trace the local
certificate's path through the runtime with:

```bash
./tools/run-offline-tctd-pc-cert-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

This mode uses the same disconnected preface/TLS server but additionally scans
successful port-27015 receives for the standard EC P-256 SubjectPublicKeyInfo
structure. On the first match it places an eight-byte hardware read/write watch
over the public-key region. Up to 64 watch hits retain only the faulting
in-game instruction RVA and unwound game caller RVAs. Certificate bytes,
addresses, server names, and account data are not logged.

The runner writes `tctd-cert-analysis.txt` beside the ordinary capture. A
successful stage contains `TCTD_CERT_WATCH_ARMED` followed by one or more
`TCTD_CERT_READ` events. Those RVAs identify the private TLS parser and the
caller path leading toward the trust decision.

## Port-27015 validation-decision probe

After the certificate-read probe identifies stable TLS-parser return sites,
capture their runtime code and result propagation with:

```bash
./tools/run-offline-tctd-pc-validation-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-validation-probe-wrapper.sh` as the Steam launch
wrapper for this mode. When the EC P-256 certificate arrives, the probe saves
eight bounded code windows, then advances a single hardware slot from the
certificate data watch through five return checkpoints. Each checkpoint
records the scalar return class, low 32 bits, condition flags, and game-module
caller RVAs. It does not log certificate or application payloads.

The runner writes `tctd-validation-analysis.txt`. The useful success markers
are `TCTD_VALIDATION_CODE_CAPTURED` plus one or more
`TCTD_VALIDATION_CHECKPOINT` events. Repeated scalar states across connection
attempts should expose where the locally generated certificate becomes a
rejection result.

## Loopback-only port-27015 acceptance test

The runtime dump identified the certificate verifier return at `0x206573b`.
The 20260925-200430 capture confirmed that overriding a rejected return there
establishes TLS with the local server. The earlier `0xbb4cd` completion-byte
experiment has been replaced:

```bash
./tools/run-offline-tctd-pc-local-accept.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-local-accept-wrapper.sh` as the Steam launch wrapper.
This mode arms only after finding the expected EC certificate on a socket whose
peer is loopback port 27015. At `0x206573b`, after checking the instruction
signature, it changes a non-positive verifier return to one if verification
is enabled. Each hit disables the breakpoint; another matching certificate
receive may re-arm it, up to 256 attempts. It does not alter validation for
remote peers. This remains experimental receive-triggered thread scoping.

The runner writes `tctd-local-accept-analysis.txt`. Success requires
`TCTD_LOCAL_ACCEPT_APPLIED` followed by `TCTD_PC_TLS_ESTABLISHED`. Any first
decrypted client application bytes are retained only in the restrictive
private capture directory and represented by length and digest in ordinary
evidence.

## Combined connected allocation capture

Use `tools/run-connected-tctd-allocation.sh GAME_DIRECTORY COMPATDATA_DIRECTORY`
with Steam launch options `"/absolute/project/tools/steam-tctd-allocation-wrapper.sh" %command%`.
Keep the network enabled, start the runner, press Enter to begin capture,
then launch through Steam when instructed. Stop at the first stable menu/error
or after about 20–30 seconds of loading; exit the game before ending capture.

The installed standalone shim is hash-checked by the runner. The wrapper clears
inherited probe flags and observes the live allocation service with the shim's
development identity. It does not enable the local certificate override, DNS
redirect, profile injection, or world replay. The existing plaintext backend
is started for transport observation.

Four hardware execution checkpoints run together:

- `0x224817b`: decrypted TLS queue bytes passed to the transport parser,
  restricted to a socket whose peer port is 27015;
- `0xf11d8`: the allocation message descriptor and status;
- `0xf1251`: successful parser output, or a metadata-only failure;
- `0xbb4df`: the parsed allocation handed to the next backend component.

All checkpoint instructions must match the saved runtime code signatures.
The private `tctd-allocation-*/records.bin` file records sequence, thread,
timestamp, object, site, result and payload; limits are 128 events, 64 KiB per
record and 1 MiB total payload. Its directory/file permissions are 0700/0600.
The evidence summary contains sizes, hashes and stage outcomes only. No
uninitialized output capacity is dumped. The capture is evidence for schema
reconstruction, not yet an implemented allocation response or gameplay server.

## Port-27015 validator-body code capture

To reproduce the bounded function capture that helped reject the original
setter hypothesis, use:

```bash
./tools/run-offline-tctd-pc-validator-code.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-validator-code-wrapper.sh` as the Steam launch
wrapper. This mode performs no mutation and installs no additional execution
breakpoint. When the expected certificate arrives from loopback port 27015,
it uses runtime unwind metadata for the function containing RVA `0xf12b1` and
captures that complete function in up to eight contiguous 512-byte windows.
The captured routine is a cleanup funclet, not a legitimate success setter.

The runner validates and reconstructs those windows as
`tctd-validator-function.bin`, with bounds and setter offset summarized in
`tctd-validator-analysis.txt`.

## Port-27015 validation-state lifecycle probe

Trace the byte observed at the failed TLS decision without modifying it:

```bash
./tools/run-offline-tctd-pc-state-watch.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-state-watch-wrapper.sh` as the Steam launch wrapper.
After the expected loopback certificate arrives, the probe stops once at RVA
`0xbb4cd` to obtain the state address. That same hardware slot is then changed
to a one-byte write watch. Up to 64 subsequent writes record only the resulting
zero/nonzero classification, post-write game RVA, caller RVAs, and bounded
runtime code windows. The probe never changes the watched state.

The runner writes `tctd-state-watch-analysis.txt`. A useful capture contains
`TCTD_STATE_WATCH_TARGET` followed by one or more `TCTD_STATE_WRITE` events.

The first lifecycle run observed no writes during certificate retries. Its
only later hit was an eight-byte pointer write after the memory had entered a
teardown/reuse path. Consequently this probe is retained for reproducibility,
not as the current discovery path.

## Port-27015 decision-owner lifecycle probe

Trace the object that owns the pointer consumed at `0xbb4cd` with:

```bash
./tools/run-offline-tctd-pc-owner-watch.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-owner-watch-wrapper.sh` as the Steam launch wrapper.
After each expected loopback certificate arrives, DR0 is armed once at
`0xbb4cd` and removed as soon as that decision is observed. This one-shot
design avoids Wine repeatedly trapping on a persistent execution breakpoint.
At every decision, the probe classifies the owner in RBX and verifies that
`[RBX+0x40]` matches the state pointer in RCX. DR1 then watches the aligned
eight-byte owner field between attempts, while DR2 follows the first byte of
its current target. Pointer-field and state writes record only
same/replaced/null or zero/nonzero classifications, game RVAs, caller RVAs,
and bounded code windows. Runtime addresses and payloads are not logged, and
the probe never changes game memory.

The runner writes `tctd-owner-watch-analysis.txt`. Useful captures contain
`TCTD_OWNER_DECISION` plus either `TCTD_OWNER_FIELD_WRITE` or
`TCTD_OWNER_STATE_WRITE`. Their corresponding code-window labels are
`tctd-owner-field-NN` and `tctd-owner-state-NN`.

## Connected port-27015 owner baseline

Compare the same lifecycle against Ubisoft's live TLS service with:

```bash
./tools/run-connected-tctd-pc-owner-baseline.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-owner-baseline-wrapper.sh` as the Steam launch
wrapper and enable the network for this run. This mode does not set
`ISAC_TCTD_PC_LOOPBACK`, rewrite DNS, start a port-27015 listener, change game
memory, or modify traffic. The standalone local Uplay shim and local profile
backend remain active, so Ubisoft Connect credentials are not forwarded into
the game process. The probe observes only the remote port-27015 certificate
and the same bounded owner/state classifications used by the offline probe.

The resulting capture is labelled `connected-tctd-pc-owner-baseline` and
includes `tctd-owner-watch-analysis.txt` plus encrypted port-27015 metadata.
Stop at the first stable menu or loading result; gameplay is unnecessary.

## Connected port-27015 validation baseline

Compare the five staged certificate-validation checkpoints against Ubisoft's
live TLS service with:

```bash
./tools/run-connected-tctd-pc-validation-baseline.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-validation-baseline-wrapper.sh` as the Steam launch
wrapper and enable the network for this run. Like the owner baseline, this
mode neither sets `ISAC_TCTD_PC_LOOPBACK` nor starts a local port-27015
listener. It observes the official certificate and records the same bounded
key-read, TLS-return, caller, and final validation-result checkpoints as the
offline validation probe. It does not change game memory or network traffic.
Because the official certificate takes a different leaf-level key-processing
path, the remote mode arms the first shared return checkpoint from the first
in-game certificate read. The five recorded checkpoint addresses remain the
same as the offline probe.

The resulting capture is labelled `connected-tctd-pc-validation-baseline` and
contains `tctd-validation-analysis.txt` for a direct comparison with the local
certificate trace. Stop at the first stable menu or loading result; gameplay
is unnecessary.

## Port-27015 asynchronous completion-path probe

Trace the certificate worker's entry, completion setter, and shared return
against the local TLS endpoint with:

```bash
./tools/run-offline-tctd-pc-completion-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-completion-probe-wrapper.sh` as the Steam launch
wrapper. The probe arms three execution-only hardware breakpoints after the
expected loopback certificate arrives: worker entry at RVA `0xf0e60`, the
instruction at `0xf12b1` (observed immediately afterward at `0xf12b4`), and
the shared return at `0xf1324`. The breakpoints remain active after the shared
return because completion is asynchronous, and are removed after the setter
is confirmed. The probe records bounded register classifications, the state byte's
zero/nonzero classification, and caller RVAs. It does not change the state,
code, or traffic.

The same run captures the contiguous runtime code region from `0xf0e60`
through `0xf1337` in three bounded windows. The runner reconstructs it as
`tctd-completion-region.bin` and summarizes the run in
`tctd-completion-analysis.txt`.

For the corresponding live-service baseline, enable the network, use
`tools/steam-tctd-pc-completion-baseline-wrapper.sh`, and run:

```bash
./tools/run-connected-tctd-pc-completion-baseline.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

The connected mode does not rewrite DNS, start a local port-27015 listener,
modify traffic, or change game memory. Stop either run at the first stable
menu or loading result; gameplay is unnecessary.

## Port-27015 certificate completion branch probe

Classify the four internal gates identified from the completion-path code with:

```bash
./tools/run-offline-tctd-pc-branch-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-branch-probe-wrapper.sh` as the Steam launch wrapper.
Four execution-only hardware breakpoints record the operation-readiness result
at RVA `0xf11af`, status-readiness result at `0xf11d0`, exact 16-bit TLS status
at `0xf11d8`, and final-helper result at `0xf1251`. A nonzero TLS status or any
final-helper result completes the probe. Values are bounded scalar status
fields; certificate payloads, keys, and traffic contents are not recorded.

For the official comparison, enable the network, use
`tools/steam-tctd-pc-branch-baseline-wrapper.sh`, and run:

```bash
./tools/run-connected-tctd-pc-branch-baseline.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Both runners write `tctd-branch-analysis.txt`. The connected mode observes the
live port-27015 service without DNS rewriting or traffic modification; the
offline mode uses only the local TLS listener.

## Port-27015 certificate-processing chain probe

The completion-gate comparison shows that the rejected local handshake never
produces a readable high-level TLS status. Trace the earlier certificate path
with:

```bash
./tools/run-offline-tctd-pc-chain-probe.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-chain-probe-wrapper.sh` as the Steam launch wrapper.
After the expected EC P-256 key is read at RVA `0x21fea19`, one hardware slot
advances through the six observed return addresses at `0x2016925`,
`0x20167db`, `0x223b8d5`, `0x2248085`, `0x224ca7c`, and `0xf131c`. Each
checkpoint records only scalar return state, condition flags, and caller RVAs.
Six bounded code windows make the return values interpretable without retaining
certificate or application payloads.

For the official comparison, enable the network, use
`tools/steam-tctd-pc-chain-baseline-wrapper.sh`, and run:

```bash
./tools/run-connected-tctd-pc-chain-baseline.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Both runners write `tctd-chain-analysis.txt`. The first return checkpoint that
differs between the official and local runs identifies the smallest validator
or parser function to inspect next. Neither mode changes game memory or TLS
traffic.

The first comparison found `0x037a` for the official flight and `0x0382` for
the local flight at the three inner returns. Those values equal the respective
890-byte and 898-byte receive lengths, so they are successful byte counts, not
trust errors. The surrounding wrappers therefore are not the rejection point.

## Dynamically selected TLS parser code capture

Resolve and capture the vtable-selected parser beneath those wrappers with:

```bash
./tools/run-offline-tctd-pc-parser-code.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-parser-code-wrapper.sh` as the Steam launch wrapper
and disconnect the network. After the expected certificate key passes through
the receive-copy path, the probe stops at RVA `0x20167d8`, reads only the
in-game function pointer in vtable slot `+0x10`, and captures that function's
runtime bounds in at most twelve 512-byte windows. It records no certificate,
key, or application bytes and makes no memory or traffic changes.

The runner validates and reconstructs the capture as
`tctd-parser-function.bin`, with its selected RVA and bounds summarized in
`tctd-parser-analysis.txt`.

## Copy-following certificate-flow probe

Trace the selected certificate key through internal copies and all later
consumers in one bounded run with:

```bash
./tools/run-offline-tctd-pc-cert-flow.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Use `tools/steam-tctd-pc-cert-flow-wrapper.sh` as the Steam launch wrapper and
disconnect the network. The probe moves one eight-byte hardware watchpoint from
the verified `memcpy` source to its corresponding destination. It records up to
256 copy/consumer events and captures one bounded code window for each of at
most twelve distinct in-game consumer functions. It also captures one bounded
window around each shared, official-success, and local-cleanup function found
in the first local/official comparison, allowing that complete decision path to
be analyzed from one local run. Certificate bytes, absolute addresses, and
application payloads are not logged, and the probe does not modify game
decisions or network traffic.

For the official comparison, enable the network, use
`tools/steam-tctd-pc-cert-flow-baseline-wrapper.sh`, and run:

```bash
./tools/run-connected-tctd-pc-cert-flow-baseline.sh \
  "/path/to/The Division" \
  "/path/to/compatdata/365590"
```

Both modes produce `tctd-cert-flow-analysis.txt`. Compare the ordered follow
hops, consumer RVAs, caller chains, and captured consumer code to locate the
first local/official divergence without adding a separate probe for every
candidate function.
