# Follow channel selection and preparation in one isolated run

Date: 2026-09-26

## Evidence motivating the trace

Capture `evidence/20260926-232422-908576-sdk-adapter-linux` establishes:

- Local session-create and configuration requests both returned HTTP 200.
- Services state reached 7; services and auth ticket predicates became present.
- Auth state changed 4 -> 0 -> 1; the auth client and pending ticket-login
  request became present, but its channel remained absent.
- Manager state was 2. Auth requested selector kind 0 and numeric channel
  parameter 4097 (0x1001). That parameter is not established as a wire opcode.
- All 60 paired channel-helper results were false with a null output. The
  observer retired normally at its event limit: 61 entries, 60 results, one
  pending pair. The final unmatched entry is not evidence of a crash.
- The main listener exchanged four decoded heartbeats and replies, with no
  inner frames. Login/world remain explicitly unimplemented there.

The prior startup capture separately established main version 2056 acceptance
and successful settings consumption. A heartbeat connection's existence does
not establish that channel selection or logical service preparation succeeds.

## Static distinction: two different failures give false/null

State 2 in helper `0x5c290` calls selector `0x9c3e0` at `0x5c350`.
If its returned endpoint entry is null, the helper records an error and returns
false without constructing a channel. If selection succeeds, it allocates and
constructs a channel through `0x2f790`, publishes that object to the output,
then checks it through vtable+0x38. A rejected object is released through
vtable+0x30 and the output is cleared before the same false return. The last
handoff trace alone cannot distinguish these branches.

The selector iterates manager+0xc8 entries, compares entry+0x5c to the requested
kind, calls predicate `0x58c20`, and rejects candidates when AL is true. An
eligible entry with non-null +0x60 is reused immediately. Eligible entries
without that connection are accumulated and one is selected for construction.
The trace records the predicate result, not an unproven semantic label such as
"blacklist." An entry's presence or connection pointer alone is not readiness.

Channel construction retains the selected entry's +0x60 linked owner at
channel+0x58. It calls `0x5fb10`; failure sets channel+0x90 state 2 and +0x94
error 1. That helper requires a present, non-rejected owner+0x50 transport,
prepares a service name, and calls `0x14c20`. Static code verifies that this
predicate returns true for an empty string. An empty name returns failure
before registration `0xaf360`. A nonempty name enters registration; its
settings/policy gates and actual return are separate observations.

## New opt-in mode and checkpoints

`sdk_adapter_test.py run GAME PREFIX transport-channel` uses the same local
services, transport listeners, kernel network isolation, SDK adapter and Steam
wrapper. It stores mode=transport, backend_trace=true, profile=channel. Existing
modes are unchanged. No DLL reinstall, executable patch or constructor hook
is added. The new diagnostic observer performs only memory/register reads.

One hardware slot stays at the fixed outer tail `0x5c523`. The other follows
the actual branch of one paired call at a time:

| Checkpoint RVA | Observation |
| --- | --- |
| 0x5c337 | Manager state, selector kind, numeric parameter; begin pair |
| 0x9c443 | Total selector entry count before filtering |
| 0x9c461 | Candidate kind match/mismatch |
| 0x9c48c | Rejection predicate and existing connection presence |
| 0x9c518 | Continue iteration or finish selection |
| 0x5c355 | Selector result, selected kind/port, linked owner presence |
| 0x5fbae | Owner transport presence/state/version/error, settings/policy flags |
| 0x5fbc1 | Transport validity-check result |
| 0x5fe48 | Empty-service-name predicate result |
| 0xaf36d | Registration reached; settings/policy/transport snapshot |
| 0x5fe75 | Registration return result |
| 0x5c3de | Channel rejection predicate and object state/error before release |
| 0x5c523 | Actual BL helper result and output presence; finish pair |

There are only two diagnostic hardware slots, four including the existing
certificate and adapter breakpoints. Every checkpoint signature is verified
before arming. Five auxiliary prologue/predicate signatures attest stack
adjustments and the empty-string interpretation against runtime text hash
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

Pairing uses the GDB thread and exact stack depth relative to the outer helper:
selector sites -0xc0, preparation sites -0x370, registration gate -0x3d0,
outer sites zero. Owner/manager checks guard the first nested observations.
Other thread/frame hits do not advance the rotating slot. A paired permanent
tail resets it even if an intermediate site never fired. Interleaved calls
are not exhaustively traced; ignored and unpaired hits are counted in END.
State-1/other-manager paths get an outer result, not a reconstructed state-2
selection/preparation path. No guessed return address or inferior call is used.

One CHANNEL_ROUTE line combines each changed complete decision. Identical
retries for the same manager/kind/parameter do not fill the event budget;
attempt/result counts still increase. Unknown/unreadable fields remain -1.
Prepared-name emptiness comes from the already-computed AL result: no service
name, ticket, host string or message payload is read or logged. Pointer values
remain private; public manager identifiers are allocation-address based and
can be reused across lifetimes. Limits remain 4096 diagnostic stops, 128 public
events and 90 seconds checked on stops. END with a pending pair or missing END
limits negative conclusions. Retirement affects only the diagnostic slots.

## What existing evidence can and cannot replace

The attested static code and existing captures are enough to build this trace
and explain these branches. A new isolated game run is needed to identify
which branch actually fires against our backend. A fresh Ubisoft-server
capture is not required to perform that test, and reconnecting the experimental
client is not part of this workflow.

This does not reconstruct a complete backend. Dynamic service metadata and
successful registration/login/world message values still need evidence or
independently validated reconstruction. Historical gameplay captures may help
with their own layers, but do not establish this new transport's startup
contract. If this trace exposes missing service-name preparation, follow its
metadata producers and serialized configuration before inventing a value or
forcing a constructor result. If registration is reached, use its result and
the actual wire frames to choose the next server-side work.

## Verification and capture instructions

Unit tests cover selection-empty, kind mismatch, filter rejection, reuse/new
selection, absent/rejected transport, empty name, registration gate/return,
success and rejection, unknown memory, cross-thread/frame protection, signature
refusal, changed-decision suppression, missing-site recovery and limits.
A real GDB fixture uses the exact nested stack depths and all four hardware
slots alongside the existing adapter/certificate hooks. It observes selector
failure, ten identical name rejections, then successful registration: three
changed route lines, twelve paired calls, fixture results unchanged. The old
startup/handoff and isolated-service fixtures also pass.

Verification: all 79 SDK tests passed with real debugger and isolated-service
integration enabled. All 18 checkpoint/prologue/predicate signatures match
the attested runtime text.

For the game: start transport-channel, wait for ready, launch with the unchanged
Steam SDK-wrapper option, stay at loading about 30 seconds or stop at an error,
exit the game, then press Enter in the runner. Desktop networking can stay on;
the game and backend remain in their isolated loopback namespace. No gameplay
or menu entry is required. No live-game result for this new profile is claimed
until that capture is reviewed.
