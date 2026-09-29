# Combined services/frontend/auth-channel probe

Date: 2026-09-26

Implements the observational next step from findings 066. It does not supply
a services session, fabricate successful completion, or change backend replies.
The existing local certificate, directory, latency and main-channel listeners
remain in use. Networking must remain off for the capture.

## Three simultaneous checkpoints

DR0 is retained for existing local certificate acceptance. DR1–DR3 now observe:

| Slot | RVA | Observation |
| --- | --- | --- |
| DR1 | 0xf17d0 | Services worker poll entry: result-object presence, numeric asynchronous state, worker byte +0x108 |
| DR2 | 0x185daf0 | Frontend before ticket synchronization: services/auth states, string-nonempty predicates, suppression flags, auth-client/request/channel presence and manager state |
| DR3 | 0x5c337 | Channel setup before manager-state branching: manager state, selector kind and numeric channel parameter |

The frontend checkpoint precedes the +0x29aa suppression branch, unlike the
later predicate-return site. Its records can therefore show suppression even
when the ticket-copy block is skipped. Values are before this frame's copy and
auth-dispatch work; a source/destination difference may be normal until a later
frame. The +0x330 and +0xea0 fields retain offset-based labels because their
precise identity semantics have not been established.

String predicates recognize four statically verified direct getters at RVAs
0x12920/0x12940/0x12960/0x12980 and storage offsets +0x48/+0x408/+0x88/+0x808.
They use bounded self-process reads of the vtable, pointer and first byte only;
no virtual game method is called and no string content is logged. Other layouts,
null/unreadable storage, or failed reads give -1. Scalar/pointer reads also
distinguish unreadable (-1) from absent (0).

All three site signatures and the four getter signatures must validate before
activation. Mixing this mode with the old startup-leads mode is rejected.
Handlers preserve context apart from normal debug-status/RF resume handling and
restore last-error state. They neither write game memory nor replace registers
with fabricated results. Per-site last-state caches track up to eight objects;
unchanged states are suppressed, with a maximum 128 records per site and an
explicit limit marker. Cache eviction or lock contention can lose observations;
this is not a complete event trace or proof of absence.

This mode does not dump static data again or enable private resolver-name
capture. Existing transport connect metadata and listener logs remain the check
for a connection beyond the newly observed channel-state gate. The old selector
and constructor hardware checkpoints are replaced, not simultaneously retained.

## Running

Runner: `tools/run-offline-login-handoff.sh GAME_DIRECTORY COMPATDATA_DIRECTORY`.
Steam wrapper: `tools/steam-login-handoff-wrapper.sh` followed by `%command%`.
The wrapper clears inherited ISAC flags and enables only this mode's existing
local-backend dependencies. Neither script prints a launch-options reminder.

Start the runner with the game stopped, press Enter to begin capture, then
launch through Steam. Attempt loading once, exit at a stable menu/error, and
finish capture. No gameplay is required.

Evidence label: `offline-login-handoff`. `LOGIN_HANDOFF_READY` confirms signature
initialization, not that all thread breakpoints fired. `LOGIN_HANDOFF_CHECKPOINT`
records appear in the stack log and `tctd-echo-checkpoints.txt`.
`login-handoff-analysis.txt` reports stages, numeric transitions and observed
positive signals. It warns if readiness is missing. It does not interpret a
state-2 channel attempt as a successful selection, login or world load.

## Verification

183 Python tests pass, including four new report tests for missing readiness,
unknown values, channel/suppression signals and malformed/unexpected content.
The native synthetic checkpoint test passes signature/mode rejection, DR0
preservation, resume/register and last-error preservation, pointer predicates,
unreadable/overflowing addresses, deduplication, suppression visibility and
record limits. Existing allocation/certificate tests pass in the same run.
Shell syntax checks and the full-loader Wine transport-startup smoke test pass.
Installed loader SHA-256 matches the tested build:
`538fd0f2bd025748a12bac6898524beb2f1b62d788801e708e55c13355484e9e`.
The original loader backup is retained. Retail capture remains necessary to determine which
handoff is missing; no gameplay success is claimed.
