# Retail forwarding probe (current retail path)

Retail probes now launch Steam's command directly. No GDB, ptrace, namespace,
network isolation, backend process, route override, certificate override or
offline identity is used. Ubisoft Connect and its normal ownership checks stay
on the retail path. Offline/custom mode is unchanged and is a separate workflow.

## Current scope

The existing 89-export forwarding wrapper loads the verified original Ubisoft
DLL. A separate `--retail-only` build links `retail_type5_win.c`, NOT the legacy
`stack_probe.c` implementation containing optional local bridges and hooks.
ABI/argument sampling is disabled at compile time. It records export names in
`project-isac-uplay-probe.log`. The launch option enables a separate, bounded
type-5 observer: declared name bytes, ordered attribute pairs, the paired
record assignment, registry counts and final prepared gate name. Tickets,
account objects and general packet buffers are not captured.

The synthetic Wine test checks forwarding return/output preservation with a
fake original DLL while stale offline and ABI flags are set. Actual VEH tests
cover main/late-created thread observations, the four hardware slots, foreign
slot refusal, unrelated exceptions, copy/gate values and cleanup. The user
confirmed the preceding forwarding-only build reaches the retail main menu.
The first type-5 build crashed. A first-trap context defect was then reproduced
and fixed using the installed Proton Experimental in Steam Runtime 4, without
launching the game. The corrected build still needs real-game confirmation;
see `research/findings-105-retail-first-trap-context.md`.

## Installation and use

Close the game and Ubisoft Connect. Build and install:

```bash
./tools/build-uplay-probe.sh --retail-only
./tools/manage-uplay-probe.sh install "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" --retail-only
```

The manager retains `uplay_r1_loader64_isac_original.dll`, verifies its retail
hash and refuses to replace an unknown active loader. This is an on-disk
forwarding DLL installation, not a private overlay. Keep networking **on**.
Use this Steam option (the existing filename is retained for compatibility):

```text
"/path/to/ProjectISAC/tools/steam-service-name-probe.sh" -- %command%
```

The wrapper verifies the executable, original DLL and installed probe against
the local build, removes ISAC flags, restores Steam's loader environment and
executes the original command. No Enter prompt, separate capture process or
backend is needed. Ubisoft Connect may follow its ordinary lifecycle; the
wrapper does not reject an already-open Connect session or translate Stop.
Reach the character/main menu, wait about five seconds for the writer, then
quit. No gameplay is required. Do not enable any of the old probe flags.

## Private output and limits

Each launch creates `evidence/<timestamp>-retail-type5-<unique>/`, mode 0700,
with metadata and a `producer-private/type5-<windows-pid>.jsonl` stream for each
game process. An initial launcher process may exit before attestation; inspect
all process files. The wrapper uses umask 077 so Wine-created capture files are
0600. Exact name/key/value bytes are hex in this private stream: do not publish
it wholesale. Only export names appear in the older game-directory log.

Events: `starting`, `ready` (23 runtime signatures/PE build passed), `coverage`,
`type5`, `gate`, `end`, or `refused`. Missing reads use null/-1 and incomplete
fields; duplicates, wire order and embedded NUL bytes are preserved. Record
copy equality compares the C-string prefix while retaining the exact wire name.
Gate observations show the final prepared name, not the full preferred/automatic
selection branch. Equal names do not independently prove selected-record identity.
Owner IDs are process-local observed addresses assigned opaque numbers, not
permanent identities; an address can be reused after destruction.

Four per-thread execution hardware slots rotate over parser and assignment
sites, with a fixed gate site. A worker checks new game threads every 100 ms;
this is sampled coverage, not interception of every thread's first instruction.
Per-thread state prevents cross-thread pairing. Reentrant/unwound calls and
missed startup events can remain pending. A new thread with any occupied slot
is skipped; existing foreign debug state is never overwritten. Coverage counts
expose conflicts and failures. No IP/GPR, gate, URL, constructor or code patches
are made; debug registers and RF are used only to observe/resume instructions.
If Proton supplies an entirely empty debug context at an owned candidate site,
the handler reads the retained real thread handle and requires all four slots,
their execution modes and the actual triggering bit to match before handling
the exception. It does not accept a trap on instruction address alone. The
`end` event's `debug_context_refreshes` counts these verified recoveries.

Budgets: 30 seconds waiting for attested runtime text, then 180 seconds,
12,000 hardware hits, 256 distinct threads, at most 64 advertisements and
128 gate results. These limits retire observation, not the game. The handler
publishes bounded records without allocation or file IO; the worker writes
them and disarms owned slots. The module/handler remains pinned for safety if
cleanup cannot be verified. Process exit can truncate the final JSON line or
leave buffered observations unwritten; do not treat that as a complete census.

## Restore pure retail

**Clearing launch options alone does not remove the forwarding DLL.** Close
the game/Connect, restore the original, then clear launch options:

```bash
./tools/manage-uplay-probe.sh restore "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division"
```

This retains the verified backup. Restore before using the older isolated
custom-mode launcher, which expects a retail loader on disk. No files in the
Proton prefix or login data need to be reset.

## Historical implementation

`retail_service_name_gdb.py`, `retail_service_name_probe.py` and their fixtures
remain as reference evidence, but are no longer invoked by the retail Steam
option. There is no automatic fallback to GDB. See findings-101/102 for the
old observer's field evidence and launcher problems.
