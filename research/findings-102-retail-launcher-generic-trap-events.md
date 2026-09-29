# Retail launch: program-owned SIGTRAPs reported as generic stop events

Date: 2026-09-27

## Real capture

`evidence/20260927-020937-104166-retail-service-name-linux` passes the earlier
mixed-ABI handoffs. It reaches the initial `thedivision.exe` launcher, which
starts the 32-bit `UbisoftGameLauncher`/`upc.exe` path. No service producer
observer is initialized and no private service artifact is written.

At log line 1947 the UPC thread begins reporting SIGTRAP at steadily advancing
instruction addresses. The sequence dominates the rest of the capture until
interruption, consistent with program-owned single stepping whose handler is
not receiving its traps. This real capture does not include siginfo/TF values,
so the precise UPC signal code is not retrospectively proven. The next capture
has a bounded pass-through marker to check it. No stalled host game/debugger
process remains at investigation time.

## Cause-backed synthetic reproduction

An opt-in native fixture installs a SIGTRAP handler, executes INT3, sets TF in
its own flags, and expects eight TRAP_TRACE deliveries before its own handler
clears TF in the saved ucontext. The old observer delivers INT3 but suppresses
all trace traps (`trace_count=0 breakpoint_count=1`), generating thousands of
stops and exiting before the producer checkpoint.

In this local GDB 17.2 build those native traps are exposed through Python as
`gdb.StopEvent`, with empty details, **not** `gdb.SignalEvent`. Diagnostics show
`si_code=2` and TF set. The old fallback recognized only an INT3 byte at PC-1,
and also only read RIP, not i386 EIP. Its ordinary `continue` under SIGTRAP
nopass therefore discarded these program signals. Checking only SignalEvent
could not resolve this failure.

Changing SIGTRAP globally to pass, including nostop pass, was rejected in tests:
it lets debugger-owned native loader traps terminate the initial helper. A
queue-signal change to the SignalEvent branch was also ineffective because
the relevant events never enter that branch.

## Targeted correction

Keep normal debugger SIGTRAP policy and process recognized observer hardware
breakpoints first. For a generic stop, read only `$_siginfo.si_signo`, `si_code`
and EFLAGS. Forward SIGTRAP for TRAP_TRACE (2) with TF set. For INT3, require
SIGTRAP, TRAP_BRKPT/SI_KERNEL (1/128), and the actual instruction byte at PC-1,
using EIP or RIP according to the current native ABI. Unknown generic stops
are not blindly treated as program traps. The driver neither clears TF nor
changes signal context, client code, protection state or gate state.

Emit one `ISAC_RETAIL_PROBE_TRAP_PASSTHROUGH` marker per affected inferior,
containing only inferior number, native architecture, event classification
and constant signal code. No signal-context payload or account data is logged.
The [GDB signal documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Signals.html)
describes nopass/pass and the kernel-provided siginfo inspection facility; the
local synthetic result establishes the event-class behavior used here.

## Verification and remaining work

Both a static i386 launcher (no multilib libc) and the x86-64 native fixture
now receive one INT3 and exactly eight TRAP_TRACE signals through their normal
handlers. The mixed-ABI launch, repeated exec/failed exec, munmap, pthread
creation, four-slot bounds, producer -> record -> gate data lineage and Stop
cleanup still pass. Backend responses, installed game executable and retail
loader are unchanged. The real game still needs a rerun; this correction does
not itself establish successful Ubisoft startup or the missing type-5 fields.
