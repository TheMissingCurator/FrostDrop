# Inspect the NtProtect jump destination and raw return

Date: 2026-09-26. Diagnostic implementation, not a protection bypass.

## Retail evidence

`20260926-190740-offline-sdk-protect-trace-linux` contains stable before/after
prefix DLL references and six live entry windows. kernel32.VirtualProtect's
24 bytes and kernelbase.VirtualProtect's 176 bytes match their references.
ntdll.NtProtectVirtualMemory differs in the first five bytes at both phases:

```text
0x6ffffff3f400: e9 10 0c 0b 00    jmp 0x6fffffff0015
```

The existing Wine virtual log shows the destination's allocation at
`0x6fffffff0000..0x6fffffff1fff` and its first page made execute/read at
15692.846, before the shim's URL attempt at 15693.410. It also shows protection
changes on the NtProtect entry page in that earlier interval. These records do
not identify the installer of the jump. The sample demonstrates a runtime
entry change, not proof of DRM/Ubisoft involvement or the source of error 5.
The URL remains unmodified and the explicit ISAC guard stops the game.
The local SDK service was listening but received no HTTP requests.

## One-pass diagnostic

The existing `sdk-protect-trace` mode now adds:

- `SDK_JUMP_CODE`: exactly one E9 edge from the validated named NtProtect
  entry; at most 128 bytes of its committed, readable executable MEM_PRIVATE
  destination, before and after the first protection attempt. No recursive
  sweep, image/game-code window, payload capture or discovered-function call.
  Private code's origin is unknown: do not assume it is stock Wine code.
- `SDK_PROTECT_PATH`: one-shot calling-thread hardware execution breakpoints
  on the NtProtect entry, that destination, and the instruction immediately
  after kernelbase's NtProtect call. The return site requires the installed
  hotpatch prefix, exact FF15 call/post-call pattern and matching IAT slot.
  Unsupported shapes disable the execution trace rather than guess.
- The entry handler verifies process handle -1, the requested protection and
  the two numeric address/length parameters match the URL operation. No other
  stack contents or object/payload data are read. The post-call handler records
  EAX as the raw NTSTATUS before kernelbase's normal Win32 translation.

The trace arms last in the pre-call observer and finishes first in the immediate
post-call observer. All handler logging is deferred until after the original
call. It preserves last-error, arguments, general registers and return values;
only debug-register state and the normal resume flag are changed. Debug
registers must be unused; existing debugger breakpoints are not replaced.
The saved debug registers are restored on completion, mismatch or post-call
cleanup. Failed cleanup stops the diagnostic rather than leave dangling traps.
No extra protection call, success override, instruction patch, alternate
system-call route or SDK guard removal is introduced.

The analyzer correlates entry bytes, E9 destination, kernelbase return site,
calling thread, URL target, length and requested protection before presenting a
raw return. Incomplete/unsupported/unmatched traces do not treat zero as
success. A returned STATUS_ACCESS_DENIED establishes this call's status, not
the deeper instruction responsible or the identity of the jump's installer.
Disassembly may include unreachable instructions/data and is not itself an
execution trace. Hardware observation and existing strace can affect timing.

## Verification and handoff

The installed Proton Experimental passes a harmless test-only assembly chain:
entry -> jump -> constant STATUS_ACCESS_DENIED -> caller return. All three
hardware points are hit; the result is unchanged, last-error preserved, and
saved debug registers restored. An unrelated exception is not consumed;
wrong parameters abort observation without changing the fixture's result;
an unused armed trace cleans up as incomplete. Readers also test branch
overflow, non-executable targets, exact return-shape/IAT rejection and read
bounds. Existing SDK route/binding fixtures still pass.

Python coverage tests bounded records, redaction, missing/mismatched call/code
correlation, incomplete observations and missing jump hits.
Full Python regression: 255 discovered, 250 passed, five opt-in skips.
Standalone rebuilt-DLL loader and SDK guard tests pass, as do shell syntax and
Python compilation checks. No retail game was launched by these tests.

Use unchanged `sdk-protect-trace` runner and
`--sdk-local --sdk-protect-trace` Steam wrapper options. Keep Steam open and the
network on for comparison with the previous diagnostic, not an offline proof.
No gameplay is needed. Launch once when prompted and finish after the expected
guard shutdown. Retail jump bytes and raw return are still pending this run.

Built and installed DLL SHA-256 (active loader verified equal to the build):
`b9e2de8044ffe667e2a9811258816dd98543f607df916dc4aa823a91b7f09702`.
The original backup remains verified at
`df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8`.
