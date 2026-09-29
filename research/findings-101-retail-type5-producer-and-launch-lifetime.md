# Retail type-5 producer inputs and debugger launch lifetime

Date: 2026-09-27

## Purpose and freeze

Follow-up to findings-100. The latest local name-lineage capture has an empty
owner registry, and the frozen local backend sends no outer-2056 type-5
advertisement. Existing captures do not establish its exact successful retail
name/attributes. A separate read-only retail capture is therefore required;
another unchanged local run cannot produce that missing value.

No gate/name, SDK constructor, descriptor, URL, certificate or server response
is patched. All five frozen response implementation SHA-256 values from
findings-100 were rechecked unchanged. Installed executable and retail loader
also still match the known hashes; no game/prefix file was modified.

## Narrow read path

The main type-5 consumer's body RSP is S; its RBP is S+0x100. Parsed name is
S+0x20 (verified getter 0x12920, pointer+0x48); parsed attribute collection is
S+0x78 (verified count getter 0x5b9d0). A new two-slot producer observer pairs:

- `0x8b60b`: verified consumer input, owner R14, parser RDX, root type 5.
- `0x21830`: name's unsigned-varint declared length at name-reader RSP+0x48;
  reader frame S-0x60, RDI=parser, RSI=S+0x20, bound EBX=0x40.
- `0x654c6`: attribute count at RBP+0x77 after successful varint read; <=24.
  Attribute-reader RSP=S-0x100, RBP=S-0x97, RSI=parser, R14=S+0x78.
- `0x6556e`: key declared length at attribute-reader RBP+0x67, bound <64.
- `0x65623`: pair before insertion; value declared length at RBP+0x67, <512.
  Key string is RBP-0x49, getter 0x12860, pointer+0x18. Value string is
  RBP-0x21, getter 0x69160, pointer+0x30. Preserve all ordered wire pairs.
- `0x8b610`: parser AL result, exact declared name bytes after successful read,
  and parsed collection count. This checkpoint remains armed while nested
  field reads run, so early parse failure cannot strand the control slot.
- `0x8b755`: consumer success is **BL**, not AL; registry count after insertion
  or duplicate acceptance. Existing name-lineage assignment observer forwards
  only matched owner/thread/S record-copy results to this producer context.

All 7 sites and 15 auxiliary entries match the attested runtime text snapshot
`dc921cc2...eefb74`; some anchors intentionally overlap existing lineage checks.
Count/length reads use the identified scalar fields, not guessed C-string
lengths or arbitrary stream buffers. Getter layouts, thread, RSP/RBP, parser,
collection pointer and loop index are checked before reading bounded fields.
Unknown/missed fields remain incomplete. Zero attributes are measured at the
count reader, not inferred from the absence of pair hits.

The existing two-slot NameLineageTrace captures record+0x358 assignment and
the preferred/automatic copy into the temporary checked by the gate. Its hash
can be compared with the producer artifact's name and record copy. Record
destruction/reallocation and concurrent missed calls still limit a lifetime
claim; allocation IDs are not permanent server identifiers. No exact retail
value or full registration/world schema has been established yet.

## Cause-backed launch correction

The initial synthetic exec regression ran through the owner's checkpoint
without stopping, despite an enabled hardware breakpoint. The targeted private
diagnostic `private/retail-probe-lifecycle-i7at9acb/debugger.log` showed the x86
debug-register mirror retaining a reference across exec, then reaching
`DR0 ref.count=2` with only one visible observer breakpoint. Deleting/recreating
the guard *after* exec did not clear that extra reference. Simply delaying its
initial creation passed one exec but failed a second exec; changing visibility,
reinsertion or trap printing did not solve that repeated-handoff failure.

The corrected driver deletes the process's hardware guard at native exec
syscall **entry**, in the old address space, then arms a fresh guard at exec
completion/return. A passing private diagnostic shows removal to DR7=0,
DR0/refcount=0, then re-insertion at refcount=1 and the intended hardware hits.
This establishes an effective fix for the observed local GDB lifetime failure;
it is not a general claim that every GDB/kernel build has the same defect.

A second synthetic test put the game in a forked child. Ordinary exec/fork
catchpoints fired there, but the original syscall catchpoint did **not** supply
that child's exec-entry stops. The child again missed the hardware checkpoint.
Installing a kernel syscall observer in each child's debugger context once its
first thread exists supplies the missing entry stops and passes the forked-game
test. Initial new-inferior creation is too early: its program space/target may
not be ready. Callback setup does not resume/step/call the target or edit its
registers; it restores the debugger's previous selected thread.

Guards are independently scoped per inferior, so an exec'ing helper cannot
replace the game's guard. Stop events are consumed once; exited events clear
the cached stop. Previously a no-bootstrap exit replayed an old fork/exec stop
against an exited inferior and produced a secondary shutdown error.

## Validation and next capture

### First retail failure: native ABI mismatch

`evidence/20260927-015354-124759-retail-service-name-linux` never reached
`ISAC_RETAIL_PROBE_READY` and produced no service-field artifact. Its native
chain passed from the 32-bit Steam reaper into 64-bit bash/runtime/Wine. A
catchpoint installed in the child while it was i386 still held syscall 11 after
exec into x86-64. The log explicitly labels `munmap()` as an `execve` catch.
Thousands of false lifecycle stops churned guards; this is not service-schema
evidence. The launcher also attempted a truncated PE64 guard in i386 helpers.

A static i386 fork/exec fixture now reproduces the 64 -> 32 -> 64 transition,
including a waiting 32-bit parent alongside the 64-bit child. The old driver
fails when syscall 11 hits x86-64 munmap. The corrected driver uses one syscall
catchpoint per inferior, an `$_inferior` condition to reject other processes,
re-resolves names on ABI-changing exec, validates actual stop numbers against
the current ABI, and arms game guards only in native x86-64 processes. Existing
guards are retained at redundant completion/fork notifications; deletion at
actual exec entry is preserved. New threads reuse the process observer.

GDB 17.2's Python `.thread` setter for a catchpoint was tested and rejected:
it aborts internally at `catchpoint::re_set` after clearing its dummy location.
The inferior condition avoids that setter; no debugger binary was changed.
This behavior is consistent with the [GDB breakpoint implementation](https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/master/gdb/breakpoint.c)
(`breakpoint_set_thread`, `catchpoint::re_set`); the local synthetic assertion,
not an assumption about every GDB version, is the deciding evidence.

The mixed-ABI fixture passes 32 repeated munmap calls, new pthread creation,
four-slot checks, decoded fields and gate linkage. It asserts that no PE64 guard
is created in i386 and that munmap neither produces an observer event nor
causes guard churn. Conditions do not promise zero internal ptrace overhead.
The installed retail executable/loader hashes and frozen response sources
remain unchanged. No stale host game/Wine/debugger processes were found.
The user confirms that clearing Steam launch options starts Ubisoft Connect;
there is no current evidence requiring a prefix reset or Connect reinstall.

Nine focused producer/archive tests pass. The real synthetic GDB integration
passes decoding -> assignment -> registry insertion -> nonempty prepared gate,
with exact private fields and no raw name in structured output. It covers two
successive execs, failed exec return, a forked game, an interleaved exec'ing
helper, the production /usr/bin/env invocation, four-slots-per-inferior checks,
and interruption/own-helper cleanup. The existing SDK/transport/runtime suite
also passes 105 tests. No actual game or Ubisoft connection was launched by
these tests. The first retail attempt failed as described above; a corrected
retail capture remains pending.

Use `docs/retail-service-name-probe.md`. Networking is deliberately on, loader
retail, no local backend running. Startup to character/menu is enough; retain
the first stable error if startup fails. Inspect producer completeness, matched
record assignment and successful gate linkage before proposing any type-5
server advertisement. The prior custom-mode PID/Steam-tracking issue is not
repaired by this separate retail launcher.
