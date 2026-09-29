# Settings accepted; follow frontend-to-channel creation

Date: 2026-09-26

## What the latest game capture actually establishes

`evidence/20260926-231204-885281-sdk-adapter-linux` contains:

- VERSION expected=2056, received=2056, accepted=1.
- POLL type=7, waiting_settings=1, policy_enabled=0, stored_error=0.
- SETTINGS consumer_result=1, waiting_before=1, waiting_settings=0.
- Four main-connection heartbeats followed by one on a second connection;
  each is decoded and replied to. No registration/identity/inner messages.
- No REGISTRATION marker in the recorded debugger interval.
- ERROR expected_version=1572, code=1, name=unmapped. It is a directory
  transport error, not evidence of a main-2056 transport failure. Pointer-based
  object IDs can be reused across object lifetimes; the version field is the
  relevant disambiguator, not the repeated numeric transport ID alone.

This confirms version and settings acceptance rather than merely structural
compatibility. It does not prove whole-launch absence of registration: the
debugger log ends without END/FINISHED, so completeness is limited. No server
settings or transport-response change is justified by this evidence.

## New opt-in handoff mode

`sdk_adapter_test.py run GAME PREFIX transport-handoff` retains the existing
SDK/certificate/directory/main/latency listeners and isolation. The local
record stores mode=transport, backend_trace=true, backend_trace_profile=handoff.
The existing Steam wrapper reads that record. No DLL install/build or Steam
launch-option change is needed. Existing sdk, transport and transport-trace
modes retain their previous selection and checkpoint behavior.

Two read-only diagnostic hardware slots operate **from launch**, alongside the
existing certificate and adapter publication breakpoints. There are never more
than four hardware slots, and no executable bytes or game results are patched.
The old native Windows thread-sweep observer is not re-enabled. GDB handles the
same isolated launch and new-thread coverage as the working adapter driver.

## Observed paths and exact checkpoint contracts

All RVAs/signatures are checked against runtime text SHA-256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

Slot A, frontend `0x185daf0`, runs before the ticket-copy suppression branch.
RSI is the frontend, frontend+0x60 the services object, +0x68 the auth object.
Auth+0x1128 holds its auth client; client+0 is the backend manager. Recorded
fields reuse the layouts established in findings 066/067:

- Numeric services+0x220 and auth+0x1124 states.
- Boolean nonempty predicates for services+0x330, services ticket +0x228,
  auth ticket +0xf50, and auth+0xea0 (not otherwise semantically named).
- Byte flags auth+0x10/+0xfa8/+0x1120 and frontend+0x29a8/+0x29aa.
- Pointer-presence predicates for auth client, pending ticket login at
  client+0x28, and channel at client+8; numeric manager+0x38 state.

No virtual getter is called. Only direct getter implementations with verified
signatures at `0x12920`, `0x12940`, `0x12960`, `0x12980` are recognized, using
their +0x48/+0x408/+0x88/+0x808 storage pointers and one byte for a nonempty
predicate. Unsupported layouts/unreadable/null storage produce -1, never a
fabricated false. Public logs contain only predicates, no ticket contents.

Slot B, channel state gate `0x5c337`, records RBP manager+0x38 state, R15D
selector kind, R12D numeric channel parameter, and remembers R14's output
location privately. Auth polling calls this helper with selector 0 and parameter
0x1001 at `0x90c29` (findings 066). State 2 reaches selector `0x9c3e0`;
state 1 takes a different route; other states return without that selection.

The slot then rotates to fixed function tail `0x5c523`, before releasing the
local guard. BL is the helper's result, which is copied to EAX at `0x5c538`.
It records the output pointer's presence and, if readable, channel+0x90 state,
channel+0x94 error, and channel+0x58 linked-owner presence. The constructor
`0x2f790` stores +0x58 from its linked owner, zeroes +0x90, then on failure of
`0x5fb10` writes state 2/error 1 at `0x2f8c0`. A returned object and helper
success therefore do not prove registration or authentication succeeded.
Channel+8 is a secondary vtable, **not** a connection pointer; it is not used
as a readiness signal. These are fixed observation sites, not per-constructor
hooks, and no constructor outcome is overridden.

Entry/result pairing uses GDB thread ID and the fixed function stack position,
with the saved selector/parameter retained even if registers change inside
the helper. An unmatched result logs paired=0 and leaves the result breakpoint
armed for the original call. While waiting for that result, other concurrent
channel entries are not traced; this is bounded observation, not an exhaustive
call trace. The slot returns to the entry checkpoint only on the paired result.

## Interpretation, bounds and verification

FRONTEND/CHANNEL/CHANNEL_RESULT markers share `ISAC_BACKEND_TRACE_` and the
same SDK debugger log. Frontend unchanged snapshots are suppressed. Limits
remain 4096 diagnostic stops, 128 public events, 32 private object identifiers
and 90 seconds checked on stops. They retire only diagnostic breakpoints.
The END summary counts frontend observations and channel calls/results/pending
pairs. Missing END still limits negative conclusions. Pointer identifiers do
not encode account identity or guarantee a unique allocation lifetime.

Examples of useful distinctions:

- No services/auth ticket or a suppression flag identifies an upstream handoff
  candidate; before-sync snapshots may temporarily differ normally.
- Ticket present and pending request but no channel calls: inspect auth polling
  and its retry/state gate next, rather than altering main settings.
- A channel call with manager state other than 2 explains lack of that selector
  branch, but not the upstream reason for the manager state.
- Output absent or state/error 2/1 identifies channel creation/registration
  preparation as a lead. It does not mean a server login response was rejected.
- Successful output with no wire registration: follow `0x5fb10`'s parameter/
  name preparation and its callers to registration `0xaf360` next. Its two
  direct caller sites are `0x5fe70` and `0x5ff27`; before the first, a predicate
  at `0x5fe43` can reject preparation without ever entering registration.

Tests cover safe/unknown predicates, all getter layouts, signature refusal,
state changes/deduplication, two-slot rotation, thread/stack pairing, selector
preservation, output fields and retirement. A real GDB fixture exercises the
handoff profile concurrently with the certificate/publication hooks, asserts
register/results unchanged and checks that secret fixture text is not logged.
The earlier startup-trace fixture and isolated-service fixture remain enabled.

Verification result: all 67 SDK tests passed with both real GDB profiles and
isolated-service integration enabled. All 12 startup/handoff/getter instruction
signatures match the attested static image. No live-game handoff result is
claimed until the next capture.

For the next game run: wait for ready, launch with the unchanged SDK wrapper,
stay at loading for about 30 seconds or stop at an error, exit the game, then
press Enter in the runner. Desktop networking can stay enabled. No gameplay
or successful menu entry is required to collect these initialization decisions.
