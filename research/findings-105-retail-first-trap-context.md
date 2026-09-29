# Retail first hardware trap: empty Proton debug context

Date: 2026-09-27

## Evidence and cause boundary

The two retail attempts at 02:56/02:57 passed runtime signatures and armed
114 threads, but stopped without field/end records. Their last periodic report
had zero hits; that does not exclude a later exception. No corresponding game
exception dump was found. Do not claim a proven real-game crash stack.

The existing synthetic Windows observer fixture, previously passing system
Wine, failed with the installed Proton Experimental inside Steam Runtime 4.
On both the initial and late-created thread, the first consumer-read hardware
exception had the correct RIP and RF, but Dr0/1/2/3/6/7 were all zero. The old
handler rejected it, resulting in an unhandled 0x80000004. Later exceptions
on the initial thread did contain the expected slots and status bits.
Private synthetic diagnostics: `private/type5-proton-failure-ps4c7d_5/`.
These contain fixture strings only, not retail account data.

The mechanism is consistent with the debug-register cache paths in Valve's
[Proton 11 Wine signal implementation](https://github.com/ValveSoftware/wine/blob/proton_11.0/dlls/ntdll/unix/signal_x86_64.c):
NtGetContextThread may use cached registers for the current-thread pseudo-handle
when cached Dr7 is disabled. A real thread handle takes the server-read path.
This source comparison explains the observation; the checked branch is not
claimed to be the exact build commit of the installed binary.

## Correction

- Publish the retained thread handle before resuming the newly armed thread.
- Only for an entirely empty debug context at an owned candidate instruction,
  read debug registers through that real handle, not GetCurrentThread().
- Still require exact four-slot addresses, enabled execution modes, a matching
  Dr6 trigger bit, and no foreign debug/TF status. On any failure, leave the
  exception context untouched and continue searching.
- Copy only the verified debug state into the exception context; normal
  observation/slot rotation/RF then proceeds. No gate, IP or GPR patching.
- Count verified refreshes in the final event.
- Move the large temporary gate result into preallocated per-thread storage.
  The former parser helper reserved about 26 KiB on every hit. The rebuilt
  integrated handler reserves 0x768 bytes plus saved registers instead. This
  stack reduction did NOT alone fix the Proton reproduction and is not claimed
  as the demonstrated crash cause.

## Regression evidence

`tests/test_retail_type5_proton.py` is an explicit opt-in synthetic test using
a new temporary prefix, the installed Proton and its Steam Runtime. It does
not launch the game or access Ubisoft. Before the fix: exit 11, unhandled
hardware exception and missing records. After the fix: exit 0, two complete
type-5 records, paired copies/gates, at least two verified context refreshes,
no unhandled-exception log entry, and successful disarm. Added guard cases
verify unrelated exceptions, TF/BS status, wrong slot addresses/trigger bits
and unknown instructions remain unhandled and unmodified by our observer.

The backend/channel/service-directory implementations and both backend server
scripts retain the frozen hashes from findings-104. Retail remains direct
Steam launch with normal Ubisoft Connect, no GDB and no network isolation.
The corrected DLL requires a new real retail startup capture before claiming
the actual game crash resolved or the expected type-5 name captured.

Validation completed: six retail tests with system Wine enabled, the actual
Proton integration test, and nine existing producer/archive tests all pass.
Installed with approval: corrected retail DLL SHA-256
`cebbd0d0769ff8c7fd85b8593f2b22d20d2c074ee5bb068ae195bba6a209abe1`.
Installer verified the active DLL matches the build and the original backup
remains `df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8`.
