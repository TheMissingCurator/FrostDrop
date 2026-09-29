# SDK route guard: per-stage diagnostics

Date: 2026-09-26. Diagnostic change, not a confirmed startup fix.

## Capture evidence

`evidence/20260926-171639-offline-sdk-local-linux` reached `LOCAL_SHIM_READY`,
then `SDK_LOCAL_ROUTE_ERROR ... signature-or-protection-mismatch,terminating=1`.
The guard calls `TerminateProcess(..., 0x4953)` on that path. The SDK service
was listening but logged no request. Proton now showed Steam IPC calls and no
previous `Failed to connect to Steam` message.

The installed executable's size, PE timestamp and image size match the guard.
The earlier `private/startup-leads-jcoCPbG7/static-rdata.bin` runtime snapshot
contains the expected original URL at RVA 0x3471510. Neither observation proves
that the file APIs succeeded or those bytes were present at this launch's check.
The on-disk `.rdata` section has no raw contents; early initialization remains a
possible explanation, not a finding.

## Diagnostics

The error event now includes a distinct `stage`:

- `file-module-path`, `file-path-truncated`, `file-name`, `file-open`,
  `file-size-query`, `file-size`, DOS/NT read, short-read and signature checks,
  `file-nt-offset`, `file-nt-seek`, `file-pe-magic`, `file-timestamp`,
  `file-image-size`.
- `image-base`, `image-bounds`, `memory-query`, `memory-state`,
  `memory-readable`, `region-bounds`, `template-mismatch`, `protect-write`,
  `protect-restore`.

`win32_error` is captured immediately after a failed API call, before cleanup;
semantic mismatches use zero, not a stale last-error value. `expected` and
`observed` describe numeric file checks. Memory failures include state and
protection flags. A template mismatch includes its first differing offset,
`all_zero` and `already_local` flags, not actual bytes. `modified=1` identifies
failure restoring protection after replacement. No paths, memory dumps, request
bodies or credentials are logged.

Exact-byte matching and stop-on-failure remain. No deferred retry, permissive
fallback, new hook, or network exception was added. Readability checking now
also explicitly rejects execute-only/unknown protection before comparing bytes.

## Verification and next run

- DLL rebuilt with warnings treated as errors.
- Native Wine route smoke passed, including injected query/write/restore
  failures, state/region checks, no-access/guard/execute-only rejection,
  zero/already-local/NUL mismatches, and successful protection restoration.
- Standalone DLL smoke passed. A second run opted into SDK routing and verified
  `stage=file-name,win32_error=0` and termination status 0x4953 for the synthetic
  non-game executable. This exercises the real diagnostic log path.
- Python regression: 219 discovered, 214 passed, five opt-in tests skipped.
  Sandbox socket restrictions required rerunning outside the sandbox.
- Installed DLL SHA-256:
  `c801ed15cba4461714b34b330948f6101db0586faf2c6a141bcd19d1e4b77e69`.
  Verified retail backup retained. No retail game launch performed here.

Use the same `run-offline-integration.sh GAME COMPAT sdk-local` command and
`steam-login-handoff-wrapper.sh --sdk-local %command%` Steam option. Keep Steam
open; the runner supplies isolation, so desktop networking can stay enabled.
One startup attempt is sufficient; no gameplay is needed. Stop at the first
error or exit and complete capture. A failed guard will still stop the game;
the new evidence should identify the precise failing stage.
