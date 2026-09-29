# Thread-sweep A/B test and exception diagnostics

Date: 2026-09-26

## Why this test

Runs `20260926-151343-offline-login-handoff-linux` and
`20260926-151416-offline-login-handoff-linux` both stopped after the local
27015 server sent its 36-byte greeting, with no client preface. The latter's
socket timeline shows all 36 bytes still in the receive queue. Neither run
reached the previous certificate, directory and latency exchanges. The new
sweeper reported 112 verified peer threads without register/conflict/resume
errors, but zero handoff checkpoints. Successful register readback does not
prove runtime safety.

The second run was offline: kernel journal shows Wi-Fi disconnection at
15:14:05, before the 15:14:22 launch, and reconnection at 15:14:37, after the
15:14:31 process exit. The first run had remote connect/resolve activity and
must not be treated as isolated. The startup packet filter is not an audit of
all outbound traffic. No matching core dump or fresh Proton log was available;
the game's crash-reporter log only records failure to open its IPC pipe.
Neither those messages nor Steam's missing-process exit codes identify a fault
instruction. The sweep change is a suspect, not an established crash cause.

## Controlled variable

`ISAC_LOGIN_HANDOFF_SWEEP=1` now explicitly enables periodic thread enumeration,
suspension and repair. Otherwise it is off. Initial and socket-triggered arming
remain enabled in both arms, as do the same three checkpoints, exception logger
and existing local certificate/directory/latency/channel backends. Off is not a
completely uninstrumented run. No game login state or backend reply changed.

The Steam wrapper accepts `--sweep off` or `--sweep on` (default off), clears
stale ISAC variables, enables `PROTON_LOG=1`, directs logs to
`evidence/proton-logs`, and sets the same `+timestamp,+pid,+tid,+seh` Wine debug
channels in both arms. Exception-channel logs can be large; run one loading
attempt, not a long gameplay session. Local logs can contain sensitive runtime
information and should be reviewed before sharing publicly.

The runner accepts a third argument `off` or `on` (default off), using evidence
labels `offline-login-handoff-sweep-off` / `offline-login-handoff-sweep-on`.
It cannot set Steam's environment itself. `LOGIN_HANDOFF_CONFIG` records the
actual client mode and the analyzer checks it against the runner's expected
mode. Missing/mismatched configuration produces a warning, not a valid A/B arm.
Scripts do not print launch-option reminders.

## Exception recorder

Before installing the exception handler, open a shared append handle to the
existing stack log. During exception dispatch, capture at most 32 first-chance
metadata records: code, flags, sequence/tick, process/thread, instruction address,
game RVA (all-ones if outside the known image), access kind and DR6/DR7.
The handler performs no printf, allocation, stack walk, module lookup, payload
read or game call. A nonblocking recursion/concurrency guard prevents recursive
logging; concurrent records can be dropped. No exception parameters containing
fault addresses or payloads, general registers, ticket values or stack contents
are dumped. Context and last-error state are preserved.

Known probe single-steps, local certificate single-steps, C++ exceptions,
debug thread names and debug-output notifications are excluded. Unexpected
single-steps and other exception codes are eligible. Records do not swallow
exceptions or change existing exception handling. A first-chance record is not
proof of a fatal crash; later handlers may recover. Missing records cannot rule
out an exception, termination or a hang, especially if another handler consumed
the exception first. Proton logging provides a second source.

## Verification and procedure

190 Python tests pass, including wrapper argument preservation, default-off,
stale-variable clearing, identical arm environments except sweeping, invalid
argument rejection, mode mismatch reporting and sanitized exception summaries.
The native Wine suite passes late-thread coverage and actual breakpoint delivery,
disabled-sweep gating, first-chance pass-through, context/last-error preservation,
normal-event filtering, unexpected-single-step logging, recursive-call rejection,
the 32-record cap and no payload output. Shell syntax checks and loader build
with warnings-as-errors pass. The full-loader Wine transport smoke test also
passes. Installed loader matches tested build SHA-256
`047ae77808409f9e558ecda3d745263616b017834263490c434beb3ab4a8d384`;
the original loader backup is retained.

Keep networking off for both runs. Run off first, then on using the same loader
and backend. Match the wrapper's `--sweep` option to the runner's third argument.
Begin capture before launching. Stop at a stable menu/error or after a crash and
finish the capture; completely exit before the next arm. If off also crashes,
the sweep is not necessary to reproduce that failure. If only on crashes, that
implicates sweeping or the additional breakpoint coverage, but the exception
trace is still needed to distinguish suspension effects from checkpoint/handler
faults. No retail result or crash fix is claimed yet.
