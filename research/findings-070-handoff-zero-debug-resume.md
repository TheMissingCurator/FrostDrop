# Retail single-step with zero debug status: targeted resume handling

Date: 2026-09-26

## Evidence

A/B captures used the same loader hash, with configuration confirming sweep off
in `20260926-152436-offline-login-handoff-sweep-off-linux` and on in
`20260926-152536-offline-login-handoff-sweep-on-linux`. Both reported network
interfaces down at finish. Off completed local certificate/directory exchanges
and all three latency pings. On stopped before sending the port-27015 preface.

The on stack log shows thread 448 armed/read back, followed by exception
`0x80000004` at game RVA `0x185daf0` on that same thread, with supplied DR6 and
DR7 both zero. That is exactly the frontend-before-sync checkpoint. Proton's
trace shows our vectored handler returning 0 (continue search), then unwinding
through the game's handlers and entering minidump/crash reporting. No checkpoint
record was emitted because `handle_echo_breakpoint` required the DR6 slot bit
before accepting the matching instruction address.

This identifies a concrete handler-recognition failure, not evidence that the
frontend path never ran. Sweeping exposed this checkpoint on a previously missed
thread. It does not establish that periodic suspension itself caused a memory
fault, nor explain why this Proton exception context omitted debug state.

## Change and constraints

Before normal exception dispatch/diagnostics, an additional handler accepts only:

- Active login-handoff mode, sweep on, echo checkpoints enabled and installation
  complete.
- Continuable `EXCEPTION_SINGLE_STEP` with DR6=DR7=0, trap flag clear, and exception
  address equal to the supplied instruction pointer.
- One of the three exact handoff RVAs, whose eight instruction bytes still match
  the validated signature.
- A current thread lifetime previously verified by the sweep: both thread ID and
  creation timestamp match an immutable published ownership entry.

The single sweep worker publishes ownership before resuming a verified thread.
The registry is bounded to 512 thread lifetimes; thread ID reuse alone cannot
grant ownership. If publication fails after new breakpoint installation, it
attempts to restore the prior context and reports the thread unverified. The
normal DR6-based handler is unchanged. DR0 certificate handling is unchanged.

The fallback records the normal handoff observation and sets only the resume
flag in the supplied context. It preserves instruction pointer, general/debug
registers, context flags and last-error state; it does not invent debug-register
contents or alter login results. The first 16 accepted fallback events receive
`LOGIN_HANDOFF_ZERO_DEBUG_RESUMED` records. They are not misreported as unhandled
first-chance faults by the separate exception recorder. All other exceptions
continue through existing handling.

The ownership record proves prior successful arming of this thread lifetime,
not perpetual ownership against arbitrary external debugger changes. The exact
address/signature/exception gates narrow this workaround to the observed case.
Polling can still miss short-lived threads and early calls. Retail validation
is required; a synthetic test cannot establish full Proton/game stability.

## Verification

Native tests reproduce zeroed-debug exceptions at all three signed checkpoints
and require continue-execution, state observation, whole-context preservation
except RF, and last-error preservation. Negative tests cover unregistered and
reused thread identities, changed signatures, mismatched exception address,
unrelated instruction addresses, nonzero debug status/control, trap flag,
noncontinuable exceptions, access violations, inactive mode and incomplete
installation. Existing real Wine late-thread breakpoint delivery and exception
logging tests remain in place. Analyzer output now counts fallback records
separately from fault records.

191 Python tests, the native Wine suite and the full-loader transport smoke
test passed. Installed loader matches tested build SHA-256
`604aef56d7888d8ffacd6c6086f9073f404b3c239b27d09eceeeb7d20652cc67`.
The original loader backup is retained.

## Next capture and playable milestone

Use the existing sweep-on runner and wrapper, with network off. One loading
attempt is enough. Check that the observed frontend single-step resumes, then
inspect services/auth states, ticket-presence predicates, suppression flags and
the auth-channel setup gate. If a different exception occurs, retain both the
stack and Proton logs instead of interpreting missing observations as empty
login state.

The immediate goal is a clean local-start path reaching the main 55001 backend,
not merely directory/latency success. The services session/ticket handoff and
auth state are still unresolved. After that, the encrypted channel needs working
login/profile/world exchanges. Earlier plaintext/replay walking experiments do
not prove this cold-start wire path or an authoritative world backend complete.
A walk-around milestone then needs correct spawn/map/region state and session
continuity; combat, loot and persistent progress are additional backend work.
No world-loading or gameplay success is claimed by this probe repair.
