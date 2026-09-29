# Retail type-5 service-name producer capture

**Superseded for retail launch:** use [retail-forward-probe.md](retail-forward-probe.md).
The Steam wrapper now selects the direct forwarding-DLL type-5 observer, not this GDB
implementation. The bounded parser/assignment observer is ported; gate capture
is final-value-only, not the entire GDB selection-branch trace. The material
below is historical; its DLL requirements, capture artifacts and test status
do not describe the current launch option.

This is a deliberately **online retail startup capture**, not an isolated
custom-backend test. The local server currently sends no main-channel type-5
advertisement. This capture establishes the real producer's name/attributes
and follows the assignment into the registry and selection at registration.
It does not fix login/world loading by itself.

## Run

Close Division and Ubisoft Connect completely, including their game-prefix
Wine processes. If Steam still shows Running from the previous custom test,
fully exit/reopen Steam first. Do not kill a PID merely because Steam lists it.
The new probe does not repair the older custom PID-namespace launch mode.

Keep networking **on**. Replace Steam launch options with this one line:

```text
"/path/to/ProjectISAC/tools/steam-service-name-probe.sh" -- %command%
```

Launch normally. Reach the character-selection/main menu, then quit the game.
No gameplay, separate backend, terminal capture command, or Enter prompt is
needed. If an error/crash occurs instead, stop there and retain the capture.
After testing, clear this launch option for ordinary retail play.

The wrapper checks the known retail executable/loader hashes and refuses a
custom DLL or an already-running Wine session in this game's prefix. It does
not install, copy or mount any game DLL. No new PID/network namespace, host
network changes, endpoint redirect, certificate override or backend is used.
Steam's original loader/Python settings are restored only to its game command;
host helpers and GDB use the existing clean-environment boundary.

## Capture

Output goes to `evidence/<timestamp>-retail-service-name-linux/` (directory
0700). `producer-trace.log` and `metadata.json` are created mode 0600. The
private producer directory contains hash-named JSON artifacts and bounded
copied service-name `.bin` files.

The structured `ISAC_BACKEND_TRACE_TYPE5` event reports parsing/acceptance,
declared-field completeness, name length/hash, attribute counts, record
assignment/copy equality and registry count before/after. Existing
`ISAC_BACKEND_TRACE_NAME_LINEAGE` events link the selected record's name hash
to the gate's name hash and report whether the gate input was empty.

Exact name and ordered key/value bytes are retained as hex in private JSON.
Duplicate keys and embedded NUL bytes are preserved; parsed attribute count
may differ from wire pair count. `wire_has_type_auth` only means that pair was
seen, not that a later duplicate could not replace it. Unknown/missing reads
are explicitly incomplete, not fabricated as empty or as a complete schema.

Do not publish the capture wholesale. Names/attributes may contain internal
service metadata, and ordinary GDB/Proton diagnostics are not sanitized. Only
the structured observer events use lengths/hashes instead of raw field values.
The JSON is decoded field evidence, **not** an original framed packet or a
claim that the original varint byte encoding has been recovered.

## Observer and limits

Four execution hardware slots are used in the identified game process: two
for the existing assignment/selection lineage, two for type-5 parsing. All
game instruction sites and getter/stack-layout signatures are checked before
arming the observers. An early address-only guard is not trusted until hit.
No game instructions/registers are changed, no target functions are called,
and no general stream buffers, authentication tickets or account objects are
captured. GDB may use its ordinary internal native-loader breakpoints; these
are distinct from the game hardware sites.

The launch driver removes a process's guard at native `execve`/`execveat` entry,
then re-arms on completion/failed return. Kernel exec/fork catchpoints take no
x86 hardware slots. New processes receive their own syscall observer after
their first thread is initialized, before resume; their guards are independently
scoped. Exit events are never replayed as stale exec/fork stops.
Syscall catchpoints are conditioned on their owning inferior and rebuilt when
an exec changes its native ABI. GDB resolves syscall names at creation: i386
`execve` is number 11, which is `munmap` on x86-64. The observer validates the
actual event number against the current ABI and never arms a PE64 guard in a
32-bit native helper. `ISAC_RETAIL_PROBE_NATIVE_ABI` records these bindings.
Program-generated SIGTRAPs are preserved. GDB 17.2 may emit a generic StopEvent
instead of a SignalEvent for INT3 or single stepping. The driver uses kernel
siginfo and the trap flag to distinguish those from its already-consumed
hardware stops; it forwards them to the program without changing registers.
`ISAC_RETAIL_PROBE_TRAP_PASSTHROUGH` is emitted once per affected inferior.

Each observer has a 180-second/12,000-stop/256-event budget after arming; the
producer accepts at most 64 observed advertisements. Rotating, thread/frame-
paired observations are not an exhaustive census of concurrent calls. Pending
or limit-retired paths remain explicit in END events. The launch has a five-
minute wall-clock limit. Stop signals interrupt GDB, which cleans up only its
own launched/traced inferiors; existing game-prefix Wine sessions are refused.

Synthetic tests cover repeated exec, failed exec, a forked game, an exec'ing
helper interleaved before startup, the production env command hop, a static
i386 fork/exec launcher followed by an x86-64 process with repeated munmap and
thread creation, per-process slot limits, exact field/copy/gate linkage and
interruption/helper cleanup.
The first retail attempt failed before the game observer was armed due to
stale cross-ABI syscall catchpoints. The mixed-ABI regression passes with the
correction. The second retail attempt reached i386 Ubisoft Connect, then
stalled on thousands of advancing SIGTRAP stops before observer initialization.
A synthetic native trap fixture reproduced suppressed single-step delivery;
the targeted generic-StopEvent fix passes both i386 and x86-64 handlers while
retaining producer/gate capture. A new retail capture is still required.
Clearing launch options lets Ubisoft Connect start normally on the user's
baseline. No Connect reset, trap disabling or client protection patch is used.
