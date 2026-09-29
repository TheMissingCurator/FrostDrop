# Read-only client-side startup decision trace

Date: 2026-09-26

## Why the previous capture cannot finish this diagnosis

`evidence/20260926-225604-810676-sdk-adapter-linux` establishes successful
local SDK HTTP, certificate and directory TLS, protocol-556 latency, and
main-backend TLS. Connection 2 sends four compressed empty type-9 heartbeats;
connection 3 sends one. All five decode and receive type-10 replies. There
are no channel registrations, identity declarations or inner login messages.

The saved server root streams contain version 2056, settings type 7/false,
then empty type-10 replies. Static checks found no missing settings fields:
`0x2258af0` reads a Boolean through `0x223d530`; false branches directly to
success at `0x2258cbd`. The dispatcher jump table at `0x9a258` routes type 7
to `0x9a0e6` / consumer `0xb6920`, and type 10 to `0x9a0f5` /
`0x22584f0`, which requires no fields. The version comparator `0x223f100`
accepts equal expected/received 2056. The saved root streams decode cleanly,
and reconstructed compressed blocks independently decode with native LZ4.
These structural checks do not prove what the running client consumed.

Consumer `0xb6920` requires successful parsing and owner+0x53a still set.
It copies the policy Boolean to +0x53b and clears +0x53a at `0xb69ea`.
Registration `0xaf360` returns false immediately at `0xaf37f` while +0x53a
is nonzero. Policy filtering then depends on +0x53b. The remaining issue
is whether these branches execute, not an established missing world reply.

## Opt-in trace mode

Run `sdk_adapter_test.py run GAME PREFIX transport-trace`. The active record
still uses transport mode, with `backend_trace: true`. The existing isolated
launch wrapper reads this attested local record; ordinary `sdk` and
`transport` runs do not arm diagnostic breakpoints. No DLL rebuild/install
or Steam launch-option change is needed. Local server responses are unchanged.

`tools/sdk_backend_trace.py` uses two diagnostic hardware slots, alongside
the existing publication and certificate slots. It rotates sites rather
than exceeding x86's four slots. Every candidate site has an exact instruction
signature checked against the live image before arming; signatures are also
checked at each stop. All addresses below are RVAs in runtime text SHA-256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

1. Slot A remains at error entry `0x22475e0`: RCX = transport, EDX = actual
   error code. It covers errors from the start, including decompression and
   header errors that prevent the first version verdict from being reached.
2. Slot B starts at `0x22486d1`, immediately after version comparison:
   RBX = transport; transport+0xbc = expected version; stack+0x30 = received
   version; AL = actual comparator result. Non-main versions are observed
   without consuming this checkpoint. After the first expected-2056 verdict,
   it moves to common main dispatch `0x9a070`, reached only after a successful
   transport read, for both initial and drain-loop messages. RDI = owner;
   type is at stack+0x30. It never reads an uninitialized empty-poll parser
   or depends on a stale AL after other calls. Snapshots include
   owner+0x53a/+0x53b and transport state/version/stored error/compression flags.
3. On a type-7 dispatch, slot B moves to fixed call successor `0x9a0f3`.
   It records the settings consumer's actual AL return and post-call gate,
   plus the pre-call waiting flag. This is not a stack return-address hook.
4. If the consumer succeeds and +0x53a is clear, slot B moves to `0xaf36d`
   to record actual registration entry calls and their gate/policy state.
   Registration arguments/names are not read, and the function's return is
   not observed. Otherwise slot B returns to initial dispatch.

The dispatch site covers initial and drain-loop messages. Empty transport
polls are not intercepted. After the first successful settings result, later settings
replacement is intentionally outside scope; the registration/error probes
remain. Thus absent settings markers must be interpreted with the preceding
POLL records, trace limit markers, and server capture—not as proof of absence.
No main POLL checkpoints are armed until the first main version verdict;
absence of both VERSION and ERROR leaves initial receipt undecided. Later
version verdicts after rotation are not observed, but the error slot remains.

## Boundaries and interpretation

Public markers start `ISAC_BACKEND_TRACE_`: READY, VERSION, POLL, SETTINGS,
REGISTRATION, ERROR, END. Object pointers map to bounded session-local numeric
IDs; no addresses, payloads, channel names, tickets or account data are added.
Repeated identical initial-poll snapshots are suppressed. Diagnostic limits
are 4096 stops, 128 events, 32 tracked object pointers and 90 seconds checked
on a trace stop. Limits retire only diagnostic breakpoints. If no traced
site executes, the time limit is not a background timer. Unreadable or
unexpected diagnostic state also retires the trace without altering the
game; instruction mismatch before arming refuses the run. Existing isolation
validation remains enforced, including periodically during diagnostic stops.

The new observer performs no game memory/register writes, inferior calls,
software breakpoints, VirtualProtect calls, certificate changes or server
response overrides. Existing opt-in adapter/certificate behavior is unchanged.
Hardware stops can perturb timing, so any timeout remains diagnostic evidence,
not automatically proof of a semantic protocol error.

Known transport error codes derived from `0x22485d0`/`0x2248730`: 5 length
header, 6 header read, 7 type read, 8 decompression, 14 version read,
15 version mismatch, 16 version arriving after an application frame. Other
codes are retained numerically without invented names. Capturing ERROR at
function entry avoids relying on transport+0xd0, which preserves only its
first stored error and may already contain a generic close reason.

Expected useful combinations:

- VERSION accepted=0 + ERROR code=15: actual version mismatch.
- ERROR code=8: client rejected inbound compressed data.
- SETTINGS consumer_result=0: client settings consumer rejected the dispatch
  (parsing or its waiting-state precondition); does not alone distinguish them.
- SETTINGS consumer_result=1 + waiting_before=1 + waiting_settings=0:
  observed startup gate transition, not just structurally valid server bytes.
- REGISTRATION with gate clear: registration was actually attempted. Its
  server wire request/response must still be correlated in the backend log.
- VERSION accepted=1 but no POLL: no application dispatch reached the common
  checkpoint while it was armed. ERROR and END markers constrain this claim;
  it is not proof of why receipt/dispatch stalled.

## Verification

Unit tests exercise signature refusal, two-slot rotation, accepted/rejected
settings, non-main versions, valid-parser dispatch, de-duplication, numeric errors,
read-only memory behavior and retirement limits. The real GDB fixture uses
synthetic-only relocated sites to exercise all four hardware slots, rotation,
new-thread adapter installation, exact-pin certificate handling and register
preservation. It does not execute the game or claim a live settings result.

Verification: 59 SDK tests passed with the real-debugger and isolated-service
fixtures enabled. All five production checkpoint signatures also match the
attested static image. The live game's trace has not yet been captured.

For the game capture, wait for ready, launch normally using the same wrapper,
remain at loading for about 30 seconds (or stop at an error), exit the game,
then press Enter in the runner. Desktop networking can remain enabled; game
and backend retain their existing isolated network namespace.
