# Login handoff: late-thread coverage repair

Date: 2026-09-26

## Evidence and scope

Capture `20260926-150549-offline-login-handoff-linux` used the intended DLL and
recorded `LOGIN_HANDOFF_READY`, but zero handoff checkpoints. Startup reported
one armed thread (320); subsequent launcher activity occurred on other threads,
including 512. The old late-arming mechanism was reached through socket hooks,
not every frontend or services thread. Readiness validated code signatures; it
did not prove these other threads had working hardware breakpoints.

Local 27015 certificate and 51000 directory exchanges completed, as did the
three 55002 latency pings. The 55001 listener was ready but received no recorded
connection. Network interfaces were down at capture finish. Missing checkpoint
hits cannot distinguish an unexecuted path from missing instrumentation. This
coverage gap is established in the implementation, but is not proof of the sole
cause of the zero-hit run or the game's login failure.

## Change

Only the login-handoff mode now uses the existing bridge worker to enumerate
process threads every 250 ms, independent of game socket activity. For each
peer, it opens a handle, suspends it, reads its actual debug registers, repairs
missing DR1–DR3 checkpoints and reads them back. It balances its own suspension
before logging or moving to the next thread; no logging, allocation or project
lock acquisition is performed while the target is suspended. Existing DR0
certificate breakpoint state is preserved and checked. Active foreign debug
breakpoints are reported as conflicts, not overwritten. Old thread-ID cache
entries do not substitute for readback; repeated passes also detect cleared
registers and reused thread IDs.

`LOGIN_HANDOFF_THREAD` reports individual repairs/conflicts/failures, capped at
128 records. `LOGIN_HANDOFF_COVERAGE` reports aggregate seen/verified/repaired,
conflict and failure counts every five seconds and on repairs or resume errors.
Enumeration errors are explicit. Reports are emitted to the stack log and are
already included by the runner's `LOGIN_HANDOFF_` extraction. The analyzer
summarizes coverage and warns when readback evidence or checkpoint hits are
missing. Other probe modes do not run these sweeps.

This is sampled coverage: threads can start, execute important code, and exit
between passes. Readback confirms register state at the sampling instant, not
delivery of every possible event. Retail checkpoint hits remain the stronger
test. No game login state, service replies, ticket values or network routing
were changed. This does not implement a missing services backend.

## Verification and next capture

The native Wine test creates a thread after an initial sweep with no socket
activity, verifies its registers, tests repair after a cleared breakpoint,
preservation of DR0, rejection of a foreign breakpoint and balanced suspension.
It then lets the thread execute a synthetic checkpoint and asserts delivery
through the actual exception handler. Rate limiting and mode gating are also
checked. This test passed, along with 185 Python tests and the full-loader Wine
transport-startup smoke test. Installed loader matches the tested build SHA-256
`b80254da85f1d181014e2ae57ce5ac2ff584b312f4fee90a0ce65e3993c92fc2`;
the original loader backup is retained. No retail gameplay success is claimed.

Use the same `run-offline-login-handoff.sh` command and
`steam-login-handoff-wrapper.sh` Steam option, with networking off. Begin the
capture before launching, attempt loading once, exit at the stable result and
finish capture. Look for coverage reports plus the three handoff checkpoints;
do not infer missing tickets from silence alone.
