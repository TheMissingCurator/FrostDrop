# Native dispatcher entry/return diagnosis

Date: 2026-09-26. Implements the user's request to try Wine-side tracing.
This is observation, not a hook bypass or backend fix.

## Previous capture

`20260926-193008-offline-sdk-protect-trace-linux` ran the expected
`b9e2de8044ffe667e2a9811258816dd98543f607df916dc4aa823a91b7f09702` DLL.
The private NtProtect destination at `0x6fffffff0015` contains FF25 with a
zero RIP-relative displacement, followed by pointer `0x144b73120`. That points
to game RVA `0x04b73120` in the executable's `.UBX0` section. Its on-disk raw
section size is zero, so those runtime instructions were not recovered from
the installed EXE. The snapshots show a jump chain, not execution of the
handler or responsibility for the denial.

Hardware trace status is `arm-failed`; no entry, jump or return was hit.
No raw NTSTATUS was captured. The URL protection change still returns Windows
error 5, with `modified=0`, followed by the explicit guard stop. SDK service
listening does not imply any SDK request reached it.

## Native path selected

The installed Proton ELF contains `trace_syscall`, `trace_sysret`,
`NtProtectVirtualMemory` and `NtSetContextThread`. Its native dispatcher supports
the built-in `+syscall` channel. The [Wine trace implementation](https://github.com/ValveSoftware/wine/blob/bleeding-edge/dlls/ntdll/unix/loader.c#L679-L706)
prints numeric argument slots and returned values. It does not dereference
argument buffers. The installed binary, rather than that moving source branch,
was exercised in a disposable prefix to verify the actual format and coverage.

Fixture runtime: Proton Experimental `experimental-11.0-20260924-x86_64`.
Installed `x86_64-unix/ntdll.so` SHA-256:
`f3e5fa3c540e4fcabd9a2f4580b983f6428e8655fdaea53fbd5d96a85df2d267`.

New runner selection `sdk-native-trace` and Steam wrapper switch
`--sdk-local --sdk-native-trace` enable `+virtual,+syscall` along with the
existing timestamps/PID/TID/exception channel. Linux strace and hardware
breakpoint arming are disabled in this mode. There is no debugger attachment,
sudo requirement, Wine rebuild, ptrace-policy change, register-success override
or instruction patch added by this diagnostic.

One controlled context request reads this thread's debug-register context and
submits that same context unchanged. It neither adds nor removes breakpoints
and does not set general registers. Immediate errors are captured before any
observer logging. There is no retry after a failed get/set. A successful set
is checked with another read of breakpoint addresses/control, not repaired if
they differ. The helper restores the caller's previous LastError.

`SDK_NATIVE_CONTEXT` brackets get/set/verification operations with numeric
metadata and context-pointer identity. `SDK_NATIVE_PROTECT_BOUNDARY` brackets
the existing URL operation, separately from the extra diagnostic reads.
The original URL/build gates, protection choice, restoration and shutdown
guard remain unchanged. Earlier API/jump code snapshots are still collected;
`SDK_PROTECT_PATH native-only` explicitly contains no observed raw return.

## Output and interpretation

`sdk-native-analysis.txt` streams bounded Proton logs, retains only four named
NT APIs and pairs entries/returns by Windows process, thread, API and nesting.
It never pairs across log files. Context operations additionally require the
matching pointer and complete, identity-consistent marker window. A protection
return is labelled target-correlated only for a unique candidate with the
requested protection plus a decoded `+virtual` entry for the URL address/size.
Pointer-valued dispatcher arguments alone cannot identify the URL.

Missing entries, missing returns and incomplete marker windows are distinct.
Startup calls are not labelled the SDK operation. Native success versus a
Win32 failure is flagged for investigation rather than attributed to Wine.
No native call can be logged if an earlier handler never reaches the Wine
dispatcher. Absence therefore needs verified channel coverage; it does not
identify the installer of the `.UBX0` jump or prove a bypass.

The raw Proton log includes other NT call names/numeric slots and returns; it
is not limited to the four report APIs. No payload buffers are dumped by the
new channel. Logging increases volume and can change timing. Host networking
is unchanged: unreplaced routes can still reach external services.

## Validation and handoff

- Installed-Proton fixture verifies entry/return pairs for protection and both
  context APIs, plus successful unchanged-state submission and verification.
- Mocked failure contracts verify identical submitted registers, immediate
  get/set errors, no retry, and preserved caller LastError despite observers.
- Analyzer tests cover numeric parsing/redaction, API allowlisting, nesting,
  pointer/thread/window identity, cross-file exclusions, missing returns and
  decoded-target requirements.
- Full Python regression: 264 discovered, 259 passed, five opt-in skips.
  Rebuilt standalone DLL loader/SDK guard tests, shell syntax and Python
  compilation pass. Tests do not launch the retail game.

Installed DLL SHA-256, verified equal to the build:
`8cefc825927bcd249900ff1b73d8801e6759342d01d7d5c2c437ac30f53b8765`.
The verified retail backup remains intact.

For the next capture, keep Steam and network on as in the previous diagnostic.
Use the new native runner/wrapper mode, launch when prompted, and finish after
the expected guard stop. No gameplay is required. Retail native results are
still pending.
