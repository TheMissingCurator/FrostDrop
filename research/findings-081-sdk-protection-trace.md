# Diagnose the existing SDK URL mapping

Date: 2026-09-26. Focused diagnostic for the existing SDK URL patch, not another
protection candidate or a new backend schema.

## Known failure, unresolved cause

The latest retail capture (`20260926-180437-offline-sdk-local-linux`) still
matches the expected executable and exact SDK URL literal at RVA `0x3471510`.
The target is readable and reported as a read-only executable-image mapping.
Changing its protection to copy-on-write fails with Windows error 5, before
modification. The guard terminates the process with code `0x4953`.

The attempted replacement is `http://127.0.0.1:55003/{version}`; the original
template is `https://{env}public-ubiservices.ubi.com/{version}`. This experiment
does not change those strings, the selected protection, the exact-build gate,
the restoration requirement or the failure guard. Synthetic mapped-file and
image tests pass, but do not reproduce the retail access-denied result.

## New evidence collected together

Opt-in flag `ISAC_SDK_PROTECT_TRACE=1` adds `SDK_PROTECT_CALL` markers around the
existing operation. They report the phase, Unix milliseconds, absolute target,
length, requested protection, immediate Windows error, VirtualQuery metadata
and the exported VirtualProtect/NtProtectVirtualMemory entry addresses. Export
addresses do not establish whether calls are intercepted. The helper captures
GetLastError before invoking the observer, preserving the original failure.

If startup fails in this mode, `SDK_PROTECT_HOLD` pauses for two seconds before
the same required termination. It does not allow gameplay with an unpatched
SDK URL. Non-diagnostic SDK mode has no added delay or syscall tracing.

`watch-sdk-protection.py` starts before the launch prompt, follows only newly
appended markers, and selects same-user `thedivision.exe` processes belonging
to the chosen Proton prefix by directory identity. It records only the mapping
covering the target, its permissions/backing classification, VmFlags, Linux
thread IDs and numeric Seccomp/NoNewPrivs/TracerPid metadata. Backing paths and
memory contents are not emitted. Snapshots are sampled after a marker during
the failure hold, **not** synchronous pre-call snapshots. Unreadable process
metadata or a very short lifetime can leave coverage gaps.

The Steam wrapper adds `strace -D -f` with Unix timestamps, tracing only failed
`mprotect`/`pkey_mprotect` calls and suppressing signal details. It does not
trace exec arguments/environment, socket I/O, file reads/writes, memory bytes
or register dumps. `-D` retains the tracee's normal parent relationship; failed
status filtering can alter printed ordering, so correlation uses timestamps
and thread IDs, not line order. See the [strace manual](https://man7.org/linux/man-pages/man1/strace.1.html).
Tracing itself can change startup timing. Missing strace stops an explicitly
requested trace launch rather than silently running without evidence.

## Outputs and interpretation

New files in the completed capture:

- `sdk-protection-maps.jsonl`: markers, redacted mapping snapshots and lifecycle.
- `sdk-protection-maps-errors.log`: generic observer startup errors.
- `sdk-protection-linux-*.log`: failed Linux permission changes from this launch.
- `sdk-protection-analysis.txt`: correlated summary.

The analyzer requires a syscall's page range to cover the URL, its timestamp
to fall within the recorded call window (100 ms allowance), and its Linux
thread ID to belong to a sampled game process. A matched errno establishes a
Linux refusal at that address/window; it does not identify the responsible
security policy. No matched call is **not** proof of API interception: verify
the launch, markers, mapping visibility, thread IDs and trace coverage first.
Wine's additional `+virtual` channel is enabled in the Proton log for this mode.

The route inventory stays enabled and SDK packet capture stays disabled.
Host networking remains unchanged. Unreplaced routes can still reach Ubisoft;
this diagnostic does not establish backend independence or world readiness.

## Validation

- DLL builds with warnings treated as errors.
- Proton smoke tests pass for private/image/file mappings, observer phases and
  preserving the original error when observer logging alters LastError.
- Standalone DLL smoke confirms the opt-in failure hold followed by the same
  termination; it does not launch Division.
- A real Linux shared read-only file fixture produces `EACCES` under the actual
  trace wrapper. Its private bytes and filename are absent from the syscall log.
- The tracer successfully launches `true` through the installed Steam runtime.
  This checks runtime launch plumbing, not retail mapping behavior.
- Marker parsing, correlation exclusions, prefix scoping, path redaction,
  observer lifecycle and capture EOF cleanup are tested.
- Full Python regression: 244 discovered, 239 passed, five opt-in skips.
  Shell syntax and Python compilation pass. Ptrace/local-socket tests were run
  outside the restricted sandbox; no game or Ubisoft connection was initiated.

Installed diagnostic DLL SHA-256:
`e4c9ffe2f8cdccc11c05105253091ba289c297cfd5a2a794d7662360d96ee197`.
The verified retail backup is retained. No retail diagnostic capture has yet
been made, so the underlying cause remains unresolved.

## Next capture

Steam launch options (supplied here, not printed as a script reminder):

```text
"/path/to/ProjectISAC/tools/steam-login-handoff-wrapper.sh" --sdk-local --sdk-protect-trace %command%
```

Capture command:

```bash
./tools/run-offline-integration.sh \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  "/path/to/SteamLibrary/steamapps/compatdata/365590" \
  sdk-protect-trace
```

Keep Steam open, use the same host-network setup, and wait for the capture
script's launch prompt before starting the game. No gameplay is needed. Finish
after the first failure and the game has exited. Inspect the analysis, mapping
snapshots and Proton virtual-memory log before choosing a repair.
