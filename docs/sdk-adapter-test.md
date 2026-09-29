# Isolated SDK adapter and transport integration

For the separate **online retail forwarding-probe baseline**, see
[retail-forward-probe.md](retail-forward-probe.md). That probe forwards to the
original retail DLL with no debugger, backend or namespaces. Restore its
on-disk forwarding DLL before using custom mode. Do not mix
its launch option or network instructions with the isolated mode below.

This opt-in mode runs a real local SDK backend and the native service adapter.
It is ready for an **experimental tutorial test**, not a completed gameplay
backend. The older template patch, certificate/handoff probes and
world replay stay disabled. The optional `transport` mode adds a separate Linux
hardware breakpoint that admits only the exact local bootstrap certificate.

Keep desktop networking **on**. Game and backend share a private loopback-only
network. Direct external IPv4/IPv6 is blocked, including destinations reached
through SDK redirects/proxy settings. A fixed local Steam IPC relay remains so
Steam can start the game; Steam itself may be online. This is not an air gap or
a guarantee against arbitrary host IPC brokers. No host interfaces/firewall
rules are changed. Close Division and its prefix's Wine processes first.

## Preferred: restored retail installation, selected through Steam

Close Division and Ubisoft Connect (including this prefix's Wine processes).
Verify the installed game files in Steam. Verification restores Steam-managed
files, but may leave extra ISAC backup/log files and does not reset the Proton
prefix or Ubisoft Connect configuration. Do not delete the prefix as part of
this procedure. The launcher checks the retail loader's known SHA-256 before
admitting this new workflow.

The pre-verification checkpoint is private and outside the game installation:
`private/checkpoints/pre-verify-20260927-frZnoKrn/`. It contains a source archive,
the three installed loader DLLs, both project-built DLLs and a verified hash
manifest. Existing captures remain in `evidence/`. Do not publish these DLLs or
private capture material.

For **normal online retail play**, either clear Steam launch options or use the
explicit baseline-checking option:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" retail -- %command%
```

For the **isolated custom startup test**, use:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" custom -- %command%
```

No separate backend terminal or Enter prompt is needed. Steam supplies the
installation and compatdata paths. The launcher starts the existing private
network, waits for all local listeners, then launches the existing debugger
and Proton command. On completion it saves the capture and stops the listeners.
Keep desktop networking on. There is no fallback to retail or host networking
if custom-mode setup fails.

### Opt-in tutorial world-startup experiment

This is a **capture-derived startup test**, not a completed gameplay backend.
The private tutorial template has been prepared at
`private/tutorial-startup.isacwst`. Use this Steam launch option:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" custom --world-startup -- %command%
```

Keep desktop networking on: the same existing private loopback-only isolation
still applies. No DLL rebuild/install, database reset, extra server terminal,
or Enter prompt is needed. Close the previous game/launcher first. Removing
`--world-startup` returns to the existing connection-acceptance-only mode.
Normal retail mode is unchanged; the new flag is refused with `retail`.

If coming directly from the **retail tutorial capture**, restore its forwarding
DLL before launching custom mode (close Division and Ubisoft Connect first):

```sh
bash tools/manage-uplay-probe.sh restore \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-tutorial
```

Changing Steam launch options alone does not restore the on-disk loader. The
2026-09-27 08:25 attempts stopped at this baseline check, before a capture,
backend or game was started; they were not crashes caused by the world snapshot.
The verified original loader was subsequently restored and the loader/template
preflight passed. No save, profile database or capture was removed.

The launcher validates and freezes a private copy of the template before
starting listeners. Missing/invalid templates fail closed, with no retail
fallback. It sends generated connection acceptance, a batch flush, a fresh
reference dictionary, a typed 0x0007 snapshot, the observed two-integer
0x00dd message and another batch flush. A separate private continuation
template now supplies the bounded retail first-gate burst only after an
authenticated 0x0009 request naming the selected local character.
After a matching 147-byte 0x000c submission, a second private artifact now
sends the 48 missed reference-dictionary updates and a bounded 500 ms retail
response window once. This is a best-effort test of the observed "Authorising
Agent" stall, not a decoded character-creation protocol or world simulation.
Known retail character/name/account and item-instance identifiers are replaced
locally; asset references, spawn pose, stats and unresolved defaults remain
capture-derived. Session-like substitutions and account-field meaning are
experimental assumptions, not completed semantic decoding.

### Separate first-tutorial-activation test

To test whether the initial movement/shooting tutorial *starts*, keep
`--world-startup` and add `--tutorial-start` to the Steam launch option:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" custom --world-startup --tutorial-start -- %command%
```

The custom mode's per-process external-IP isolation still applies; desktop
networking can stay on. No game-file modification or DLL rebuild is needed.
By default `--tutorial-start` uses the dedicated persistent tutorial profile
database. Add `--fresh-tutorial-profile` for a new capture-private character
without changing that saved tutorial character.
The extra flag sends one capture-derived `0x00e6` five-row activation after
the authenticated `0x000c` appearance submission. It does **not** advance
objectives, spawn AI, save mission progress, or establish a playable tutorial.
Removing only `--tutorial-start` restores the previous world-startup mode for
an A/B comparison. The flag is refused without `--world-startup` or in retail
mode.

### One-shot first-objective display test

To test whether the first objective **appears** after the mission shell, use a
fresh capture-private character and add `--first-objective-test`:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" custom --world-startup --tutorial-start --fresh-tutorial-profile --first-objective-test -- %command%
```

This adds one separate receive batch after the five-row activation: a locally
reindexed `0x014d` reference, a 145-byte row-1-active `0x00e6`, and `0x0102`.
It is a display-sufficiency test, **not** a retail trigger or mission engine:
there is no timer, later objective completion, AI, or reward. Check for
`TCTD_FIRST_OBJECTIVE_TEST_READY` and `TCTD_FIRST_OBJECTIVE_SEND` in the
newest backend log. Note whether an objective text/marker appears, whether
movement/shooting works, and any error. Removing only
`--first-objective-test` is the A/B control using the same other launch flags.

### Gated take-cover completion test

To test the first objective's completion and the next objective's display,
use this separate opt-in Steam launch option:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" custom --world-startup --tutorial-start --fresh-tutorial-profile --first-objective-test --cover-completion-test -- %command%
```

Select the tutorial mission if necessary, then take cover at the first
objective. Only an authenticated `0x0014` report for the local character,
the observed cover object, matching entry-state fields and cover vicinity
can trigger a one-shot batch: a local dictionary entry, row-1-complete /
row-2-active `0x00e6`, and `0x0102`. The backend logs
`TCTD_COVER_COMPLETION_TEST_READY` and, if the gate matches,
`TCTD_COVER_COMPLETION_SEND`. This is an experimental first transition only:
there is no later objective progression, mission reward or persisted mission
state. Removing `--cover-completion-test` leaves the previous display test.
Desktop networking may stay on; the game's external IP traffic remains
isolated in custom mode.

### Experimental shooting and weapon-switch stages

This adds bounded, one-shot shooting, weapon-switch, and activity-close
transitions after the cover test:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" custom --world-startup --tutorial-start --fresh-tutorial-profile --first-objective-test --cover-completion-test --stage-progression-test --weapon-gate-test -- %command%
```

To test the first retail `0x015a` frame after the safe-house activity starts,
add `--dialogue-015a-test` before `--`. This is a separate opt-in experiment:
it sends one pinned, capture-private 35-byte candidate approximately 250 ms
after the existing four-row activity start, followed by a batch flush. The
known-good tutorial close and activity start remain unchanged. `0x015a` has
not been identified as a dialogue command. The first live run sent it and
the client immediately closed its world connection with DELTA C-0-1302.
Do not use this flag for normal gameplay tests; it is retained only for
controlled protocol diagnosis. See finding 145 before repeating it.

Reselect the tutorial mission if its first objective does not appear, take
cover, fire at least three rounds at the tutorial target, then switch weapons.
The experimental `0x006a` gate requires the observed same-weapon `31,30,29`
counter sequence for the local character, allowing the observed variable
one-to-four subitems per message; it then sends the retail-shaped
`(0,4,4,1,0)` `0x00e6` and a flush. In this mode, a validated cover report
also receives a compact-reference `0x0014` echo built from the local report
before its
objective update. An owner-bound `0x0088` with the observed switch fields
sends two equipment updates rebound to the local startup items, followed by
a dictionary update, `(0,4,4,4,1)` `0x00e6`, and a flush.
After the validated secondary shot, the backend sends a final five-row
`0x00e6`. About one second later, it sends the previously successful
44-byte activity-close `0x00e6` and flush. About four seconds after that,
it sends a new two-reference dictionary, four-row `0x00e6` activity for the
candidate next safe-house objective, and flush. Look for
`TCTD_STAGE_PROGRESSION_SEND`, `TCTD_TUTORIAL_CLOSE_SEND`, and
`TCTD_NEXT_ACTIVITY_SEND` in the newest `tctd-backend.log`.
With `--weapon-gate-test`, the existing debugger stop also records
`ISAC_ACTION_GATE_OBSERVED` counts for running, sprinting, cover-to-cover,
cover, exit-cover, firing, and reload. After Agent Activation closes, a later weapon-switch
gate check on the same owner may clear an exactly-one running count once;
look for `ISAC_RUNNING_GATE_OVERRIDE applied=1`. Tap the weapon-switch key
once after mission completion to trigger that check, then try sprint, vault,
and cover-to-cover. No other movement count is changed. This is an opt-in
memory-only diagnostic, not a decoded backend fix or a vault-gate trace. To
investigate a post-reload firing pause, tap weapon-switch while the pause is
occurring so the existing debugger stop samples the firing/reload counts.

These correlations do **not** establish that `0x006a` proves target hits or
that `0x0088` is a universal stage-completion signal. Ordinary fire/switch
traffic may satisfy them. The next activity is capture-derived and has not
yet been verified in a live local client. The additional retail close
companions (`0x014d`, `0x0064`, `0x01ae`) are disabled in this test because
the client disconnected when they were added. This does not handle the
safe-house PC interaction, unlock the four side missions,
send rewards, or persist mission state. Removing only
`--stage-progression-test` retains the previous cover-only behavior.
The server also checkpoints up to 64 post-agent `0x0014` cover candidates in
`transport-private/` and logs their gate result. These files are private and
may include character IDs; they survive a run that exits before the full raw
stream can be written. Inbound retail `0x006a` messages are still omitted:
their reference and hit-data lineage is not decoded enough for safe rebinding.

On a first character-creation run, check the newest
`evidence/*-sdk-adapter-linux/tctd-backend.log` for
`TCTD_TUTORIAL_ACTIVATION_READY` and
`stage=instance-agent-profile-finalized-tutorial-activated`. In-game, note
whether a movement/shooting objective appears, whether sprint and weapon
switching remain gated, and any error code. If no matching `0x000c` arrives,
the activation is not sent. A completed profile selected on a later launch
does not yet rehydrate tutorial state; that is a separate gap.

Look in the newest `*-sdk-adapter-linux/tctd-backend.log` for
`TCTD_WORLD_EXPERIMENT_READY` and
`instance-experimental-startup-batch-sent response=0x0002,0x0102,0x014d,0x0007,0x00dd,0x0102`.
The next milestone is `TCTD_WORLD_CONTINUATION_READY`, followed by
`instance-experimental-first-gate-sent` after the client sends 0x0009.
If the client submits a matching local character, expect
`TCTD_AGENT_REQUEST ... artifact=saved` and
`instance-agent-profile-finalized` after 0x000c (or
`instance-agent-profile-finalized-tutorial-activated` with the extra flag).
The request body is
saved privately before dispatch, even if the process later hangs. These prove
server delivery, **not client acceptance or a playable world**.
In this opt-in world-startup mode, the backend no longer disconnects the
session after 90 seconds or when a raw capture fills. The 20-second idle
timeout and per-message decode bounds still apply; each saved stream is
limited to its first 4 MiB. The readiness log reports `session_limit=none`.
Subsequent distinct unsupported message types are logged as
`TCTD_WORLD_UNIMPLEMENTED`, without payloads or identities.

If the run stops before the intro, creation diagnostics now print
`TCTD_PROFILE_CREATE_REQUEST` with `flag_5`/`flag_4`, and
`TCTD_PROFILE_FAILURE` with the failing operation, allowlisted reason and
numeric storage error codes. The bounded creation request is saved privately
before handling it, without relying on graceful shutdown. These diagnostics
do not broaden creation policy or change responses. See
[finding 123](../research/findings-123-profile-create-rejection-diagnostics.md).

The follow-up run proved that the local client can request `flag_5=0,
flag_4=0`, whereas the initial retail creation had `1,0`. The backend now
admits both observed normal pairs, preserves the first flag in the local
entry and supports archiving either unfinished variant. The first flag's
full upstream meaning remains provisional; `flag_4=1` and conflicting active
modes remain unsupported. This does **not** change the world-startup batch.
No new launch option, DLL build, profile reset or deletion is needed. See
[finding 124](../research/findings-124-second-observed-create-variant.md).

For this tutorial test, allow loading to progress through character creation,
then exit at the first stable result/error; if unchanged for roughly a minute,
exit and retain the capture. The response window is only 500 ms, not ongoing
AI, mission, movement, inventory or state simulation.
Do not expect mission progress or gameplay changes to persist. The burst is
partly opaque: known character/account/name occurrences are rebound, but
unclassified fields remain capture-derived. Only the two observed
length-prefixed display-name fields are rewritten for a different local name;
unexpected name locations or shapes fail closed.

To prepare the template on a setup where it does not yet exist:

```sh
python3 tools/prepare-world-startup.py \
  evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin \
  private/tutorial-startup.isacwst
python3 tools/prepare-world-continuation.py \
  evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin \
  private/tutorial-first-gate.isacwct
python3 tools/prepare-world-agent.py \
  evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin \
  private/tutorial-agent.isacaut
```

Preparation creates an owner-only file and refuses to overwrite existing
files. This artifact still contains unclassified capture data: keep it private.
See [finding 122](../research/findings-122-experimental-world-startup.md).

### Earlier profile/discovery milestones (default mode)

The local profile experiment now supports the client's type-3 unfinished-profile
cleanup with a type-4 success reply after a committed archive. On its first
cleanup request, the existing unfinished character moves out of the active
list into `archived_unfinished_characters` in the same private
`private/local-profiles/characters.sqlite3` database; its exact entry is retained
for recovery. No database wipe or customized-profile flag patch is needed.
Schema migration preserves the existing active character until the game
requests deletion. Restart the custom run to load the new Python handler;
no DLL build/install or launch-option change is needed. Look for
`profile-unfinished-character-archived response=0x0004`, then the next client
requests. Tutorial/world loading remains unimplemented. See
[findings 113](../research/findings-113-unfinished-profile-cleanup.md).

The backend also answers the observed `server_list` connect and normal
starting-zone join, returning a locally owned instance route and expiring
character-bound bearer. This fixes the previously unanswered discovery
messages, **not complete world loading or a confirmed DELTA C-2-229 fix**.
Restart custom mode; no DLL rebuild or new launch options are needed. Look for
`server-list-auth-policy-reply-sent response=0x0001` and
`server-list-local-instance-reply-sent response=0x0006`. If the client reaches
the new route, `instance-connect-reply-sent-world-pending response=0x0002`
now marks a generated game-connection acceptance. It is not a world-ready
response: generated world state remains unimplemented. The acknowledgment
passed isolated backend integration tests, but has not yet been tested in
the game. See [finding 120](../research/findings-120-generated-connect-and-complete-startup-shape.md).
For the original discovery implementation, see
[findings 114](../research/findings-114-local-server-discovery.md).

The subsequent retail handshake capture confirmed that the instance bearer is
the **second** timed-token slot, between auth blobs 0 and 2. Instance admission
now validates that slot; the previous first-slot check rejected the real
client's request. Tests reject swapped/forged/empty instance tokens and retain
parent expiry/revocation checks. This is an admission fix only: no game-server
connect reply or world state is sent. See
[findings 116](../research/findings-116-retail-instance-token-slot.md).
If returning from the handshake probe, restore the original loader using
[the restore command](retail-handshake-capture.md#inspect-and-restore), then
select the custom launch option above. No DLL rebuild or database reset is
needed; restart custom mode to load the corrected Python backend.

Custom mode freezes a copy of the built adapter in that capture, then mounts
it read-only over `uplay_r1_loader64.dll` **only in the launched process's mount
view**. The on-disk loader remains retail throughout, including after a crash.
The debugger attests the DLL's hash through the actual game's filesystem view,
in addition to the existing isolation and routing checks. Rebuilds during a
capture are refused. This changes launch orchestration, not the server responses,
registration gate, or service-name producer. The default is the existing
`transport-name-lineage` trace; another existing profile can be selected before
the command separator, e.g. `custom --trace transport-channel -- %command%`.

The wrapper now defers Steam's `LD_*` and `PYTHON*` settings **before starting
Python**, not only before GDB. They are carried as inert, name-checked
`ISAC_GAME_ENV_*` variables through namespace and listener setup. Retail mode
restores them for its original Steam command; custom mode restores them only
at GDB's inferior-command boundary. All Python helpers, listeners and the
system debugger run without Steam's loader/Python overrides. Exact values,
including empty strings, whitespace and literal shell characters, are retained
without evaluation or public logging. This is not removal of the Steam overlay
from the game itself. The legacy SDK wrapper uses the same early preparation.

The 2026-09-27 00:47 custom attempt failed before producing a capture: the
`_auto-inside` Python process (host PID 158884) crashed in the Steam overlay's
constructor, with `gameoverlayrenderer.so` followed by dynamic-loader frames.
Namespace and Steam-IPC readiness did not mean the backend was running.
The leftover launcher remained tracked until Steam stopped the launch.
Regression tests now model a preload constructor that rejects Python startup,
then exercise clean Python/namespace/listener setup and exact game-environment
restoration through real GDB. Retail game acceptance still needs another run;
this repair does not change server responses or the service-name bootstrap.

Build the adapter once if `dist/uplay_sdk_adapter/uplay_r1_loader64.dll` is
missing; **do not install it into the game folder** for this workflow:

```sh
bash tools/build-uplay-local.sh --sdk-adapter
```

Switch modes only after the previous game/prefix processes exit. They share the
existing Proton prefix; this is a DLL/network baseline, not a pristine separate
prefix. Synthetic tests check mount persistence in the installed Steam runtime;
a real retail/custom game launch is still required to confirm this workflow on
the current installation. It does not fix the remaining service-name bootstrap
failure or establish world-loading support.

## Legacy: installed adapter and separate capture terminal

This preceding workflow requires replacing the loader on disk. Keep it only
for comparison; it is not used by `steam-isac-mode.sh`.

### Build/install

```sh
bash tools/build-uplay-local.sh --sdk-adapter
python3 tools/manage-sdk-adapter.py install \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division"
```

The preceding local shim is retained as
`uplay_r1_loader64_isac_before_adapter.dll`. The original retail backup is not
touched. Without the new mode's explicit flag, this build retains the older local
shim behavior. The existing capture runner also accepts this known compatible
build. There is no automatic host-network fallback from the new mode.

### Run

In the project terminal:

```sh
python3 tools/sdk_adapter_test.py run \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  "/path/to/SteamLibrary/steamapps/compatdata/365590" \
  transport
```

Wait for `SDK adapter test ready` and the local backend listening message. Leave
this terminal running. No Enter is needed before launching the game.

Set Steam launch options to:

```text
"/path/to/ProjectISAC/tools/steam-sdk-adapter-wrapper.sh" %command%
```

Launch through Steam. Stop at the first stable menu/error; no gameplay is needed.
Exit the game, then press Enter in the capture terminal. Do not combine these
options with the old SDK protection/handoff wrappers or another debugger.

The wrapper starts system GDB without Steam's `LD_*` or `PYTHON*` overrides,
then restores those exact values for the Proton command only. This prevents
Steam's bundled libcurl/overlay libraries from breaking the debugger itself.
This launcher-only change needs no DLL rebuild or reinstall.

Omit `transport` (or use `sdk`) to repeat the successful SDK-only baseline.
Combined mode also starts the certificate service on 27015, directory on 51000,
main-channel transport on 55001 and latency on 55002, in the same isolated
network. A read-only, game-only `/etc/hosts` overlay routes the two known
bootstrap names to loopback; the outer NSS overlay uses `hosts: files`.
Steam may replace NSS inside its runtime: the guard accepts only `files`,
`files dns`, or `files myhostname dns`, with no action overrides. The pinned
hosts file resolves the two bootstrap names before fallback; direct DNS/IP
fallback remains inside the isolated network. Resolve/mDNS/WINS/NIS NSS routes
are rejected. Host files, global trust, and game binaries are untouched.
All services must be ready before the launch prompt; partial starts are cleaned up.

Mount setup finishes before GDB starts: tracing the extra wrapper together with
Steam's runtime triggers a crash in the installed GDB. At adapter/certificate
stops, GDB checks its current network namespace against the validated session,
the supervisor's PID/UID/start time, loopback-only network negative controls,
the game's matching network namespace, its exact hosts-file hash, and its
approved NSS hosts policy. Unrelated passwd/group entries or comments do not
need to match our outer overlay byte-for-byte.
This avoids needing ptrace access to the ancestor's namespace links; failures
of the required checks still stop the run. Namespace joining retains its
original open-handle validation. Restart the capture after launcher updates.

## What counts as progress

Capture output is under `evidence/<timestamp>-sdk-adapter-linux/`:

- `sdk-adapter-debugger.log`: `ISAC_ADAPTER_DEBUGGER_READY` proves the debugger
  admitted the isolated process and created its hardware breakpoint;
  `ISAC_ADAPTER_INSTALLED ... before-publication=1` proves the owner slot changed
  at the checked initialization event. Breakpoint insertion can still fail when
  the process resumes; such failure terminates the traced run, not falls back.
- `project-isac-uplay-local.log`: bootstrap build/initialization checks, including
  `SDK_ADAPTER_ARMED` or a named `SDK_ADAPTER_ERROR`.
- `sdk-services.log`: actual local session/configuration requests. Installation
  alone is not proof that those requests succeeded.
- `steam-365590.log`: Proton output, if Proton produced it.
- `integration.json`: isolation identity, binary hash and scope for this run.

In `transport` mode also inspect:

- `ISAC_TRANSPORT_READY` and `ISAC_TRANSPORT_CERTIFICATE pinned=1 applied=1`
  in the debugger log: the extra hardware breakpoint is armed and the exact
  local certificate was admitted. Other certificates retain normal verification.
- `ISAC_TRANSPORT_ROUTING hosts=pinned nss=...` identifies the approved runtime
  lookup policy without logging arbitrary configuration contents.
- `tctd-certificate.log`: TLS and application certificate delivery.
- `tctd-directory.log`: local directory response delivery.
- `tctd-backend.log`: latency completion, main TLS, channel registrations and
  inner message types. It explicitly distinguishes setup from login/world support.
- `transport-private/`: bounded private plaintext and TLS key logs; do not publish.

An early `live-code-anchor-mismatch` or `too-late-sdk-root-already-exists` is a
refusal, not a successful redirect. Do not disable those checks. A later ROMEO
error also does not erase earlier installation/HTTP evidence; keep all logs.

## Local type-5 service advertisements (2026-09-27)

The custom transport bundle now enables `--service-advertisements` on the
main backend. After protocol version 2056 and the existing policy settings it
sends 24 type-5 records with the captured retail service-type order and
multiplicity. Each has a stable **local** instance name and `process_guid`;
retail IDs/captures are not read at runtime. The existing default
`transport-name-lineage` trace checks whether these reach the registry and
the prepared name without patching the registration gate.

Use the custom Steam option above, with desktop networking on. If the online
retail probe is still installed, close the game and Ubisoft Connect and restore
the original loader first (no Steam re-verification or prefix reset needed):

```sh
./tools/manage-uplay-probe.sh restore "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division"
```

No adapter rebuild or separate server terminal is needed for this Python-only
backend change. Success is **not** the server merely printing
`TCTD_BACKEND_ADVERTISEMENTS_SENT ... count=24`: look for a nonempty registry,
a nonempty prepared gate name, then an actual registration request/reply and
subsequent inner messages. Stop at a stable menu/error and quit. A loading
screen is still possible: advertisements do not implement the named services.
The auth target binding is now confirmed by the next capture; the experimental
reply below is available. Character/profile/world services remain unimplemented
in this encrypted transport path. No old world replay is attached. See
findings-106/108 for evidence and limitations.

For a manual control run, omit `--service-advertisements` from the backend
command to retain the preceding settings-only behavior. It is invalid without
`--channel-setup` and does not apply to protocol 556 or the endpoint directory.

## Experimental local auth reply

Custom mode now also enables `--experimental-auth`. A registration must name
`auth` and target one of our advertised auth instance IDs. The first inner
type-2 request is checked against the observed local shape: a 75-byte SDK
ticket plus an opaque 14-byte tail. Other shapes stay unsupported. The backend
validates that ticket against the issuing SDK process through the fixed
loopback `/isac/internal/validate-ticket` endpoint. Expired, revoked, foreign
or forged tickets and an unavailable validator receive no speculative reply.

After validation, the server sends inner type 3 on that same registered
channel. Identity/name come from the local SDK profile (`ProjectISAC`), never
retail account data. This is a **shape-valid experiment**, not proven login:
the three opaque blobs are newly generated, explicitly local placeholders;
their interpretation by the client remains unknown. Lifetime candidates are
capped by SDK session expiry, observed flags are retained, and unknown bundle
entries are omitted. None of this supplies saved characters, gear or a world.

`stage=auth-experimental-reply-sent response=0x0003` proves the local response
was sent. `client_session_acceptance=unconfirmed` remains until independent
game evidence establishes advancement. Duplicate requests do not mint another
reply, conflicting requests are refused, and channel close retires its auth
state. Later unknown messages remain privately captured/observe-only. There
is no fallback to captured retail tickets or live Ubisoft services.

Use the same custom Steam option, desktop networking on, and no extra backend
terminal/DLL build. Stop at the first stable menu/error and quit. Omit
`--experimental-auth` in a manual backend command for the advertisement-only
control case. The HTTP SDK contract remains otherwise unchanged; in-memory
sessions expire after three hours and are lost when the local SDK exits.

Combined mode connects the known startup services, **not yet the old world replay**.
Port-55000 bridge framing/channel selectors are not interchangeable with the
encrypted port-55001 channel protocol. Live registrations and requests must
establish the application bindings before attaching profile/world responses.
A loading error is still possible; retain the logs rather than assuming the
successful SDK path regressed. Synthetic integration tests do not establish
retail acceptance of the new certificate pin or complete game login.

## Local character creation and persistence (2026-09-27)

The isolated custom bundle now also enables `--experimental-profiles`. This
adds a handler only for the registered `profile_client` service, not a generic
response to every type-1 request. It validates the session token issued by local
auth and answers the unfiltered list request with a matching-ID type-2 reply.
The auth reply itself is unchanged. See
[finding 109](../research/findings-109-profile-list-bootstrap.md) for the static
reader/producer evidence and [finding 111](../research/findings-111-local-character-creation.md)
for the retail-backed list/create and character-blob codecs.

Initially the reply reports zero characters. A normal type-5 creation request
now persists a fresh local character and receives a matching-ID type-6 success
reply; subsequent lists return that character. Lists use observed metadata
1800 and static string `default_start_zone`. The 161-byte initial blob is
generated from decoded defaults, not copied from a retail account.

Data lives in `private/local-profiles/characters.sqlite3`, separate from captures
and expiring SDK sessions. Back up this directory with the backend stopped;
do not delete it as capture cleanup. Manual servers can choose `--profile-store`.
One unfinished character per local account is supported; retries/reconnects
reuse it. Customization finalization, deletion, inventory, world handoff and
playable sessions are **not** implemented. The character remains correctly
marked uncustomized. Other services can still block loading.

Keep the same custom Steam launch option and desktop networking on. No DLL
rebuild/install and no separate server terminal are required. Stop at the first
stable menu/error, then quit normally. Look for
`profile-local-token-bound` followed by
`profile-empty-list-reply-sent response=0x0002`, then
`profile-character-created response=0x0006` and
`profile-character-list-reply-sent response=0x0002`; these markers prove processing
and transmission, **not** client acceptance. The capture retains unknown
requests privately for the next comparison. The retail launch path is unchanged.

For a manual auth-only control run, omit `--experimental-profiles`; do not omit
auth while leaving profiles enabled. Service tokens survive auth-channel close
but expire with the server-side lifetime or SDK revocation and do not cross
backend connections.

### Character-selection token experiment

The normal profile-client type-7 request now receives a matching-ID type-8
reply for an owned unfinished local character. Its status **2** is the
statically verified success branch, not creation's status 0. The reply uses
`default_start_zone`, empty instance name, both optional session flags false,
and a fresh local bearer capped at 15 minutes and parent-login expiry.
It does not copy retail credentials or claim to reproduce their opaque format.
See [finding 112](../research/findings-112-local-profile-token-handoff.md).

Use the same custom option, networking on, no DLL rebuild. The last saved
character is retained, so creation may not repeat. Look for
`service=profile_client ... stage=profile-character-token-reply-sent response=0x0008`.
Subsequent inner-message logs identify only known service categories; unknown
names stay redacted and unknown requests remain privately captured/observe-only.
World/group admission, tutorial state and customization finalization remain
unimplemented. Reaching another loading screen is not proof that they work.

## Restore the preceding local shim

With Division closed:

```sh
python3 tools/manage-sdk-adapter.py restore \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division"
```

Use the old launch options again for the old modes. The verified predecessor
backup is retained after restoration. Nothing is deleted.
