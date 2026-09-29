# Inspect the live SDK protection API entries

Date: 2026-09-26. Implements the user's request to inspect live entry code,
without modifying or bypassing a protection API.

## Established lead

`20260926-185059-offline-sdk-protect-trace-linux` contains eight binding records:
all three named import destinations and the kernel32 forwarding slot match the
export references before and after the attempt. They are owned by the expected
Wine modules. The URL write still returns error 5 with `modified=0`, followed
by the explicit ISAC shutdown. There is no recorded matching failed Linux
permission change or Wine NtProtectVirtualMemory entry for the URL; 882 other
Wine entries demonstrate the virtual debug channel was active. This does not
prove interception or identify the source of the refusal.

Matching import addresses do not establish that their entry instructions are
unchanged. The new probe closes that specific gap in one startup capture.

## New bounded capture

The same `ISAC_SDK_PROTECT_TRACE=1` mode emits `SDK_API_CODE` at each existing
SDK observer phase. It samples only these allowlisted API entries:

| API | Bytes |
| --- | ---: |
| kernel32.VirtualProtect | 24 |
| kernelbase.VirtualProtect | 176 |
| ntdll.NtProtectVirtualMemory | 32 |

The reader requires the entry's allocation to belong to the named MEM_IMAGE
module, executable/readable committed pages, valid x64 PE metadata and a fully
contained bounded window. Metadata includes the entry/allocation/RVA, PE
timestamp/image size and status. Hex bytes are emitted only for successful
named Wine API samples, not arbitrary destinations or game code. Unlike the
earlier binding-only probe, this mode deliberately records these small code
windows. The overall limit is 232 code bytes per phase.

For the exact observed ntdll syscall-stub pattern, `SDK_WINE_DISPATCH` also reads
the flag at `0x7ffe0308` and pointer at `0x7ffe1000`, which are referenced by that
stub's instructions. It emits numeric metadata only and does not follow or
call the pointer. An unsupported pattern or unreadable field is explicit; no
address is guessed from arbitrary code.

There are no new API calls to discovered destinations, patches, hardware or
software breakpoints, instruction stepping, protection retries, or changes to
the URL guard. Existing backend listeners and host networking are unchanged.
No SDK request bodies, credentials or packet payloads are collected.

## Reference identity and analysis

Before capture, `sdk-api-reference.py` reads only the selected prefix's
`drive_c/windows/system32/{kernel32,kernelbase,ntdll}.dll`. It locates the
named exports through the PE export table, not a similarly named symbol.
It records file SHA-256, build/image metadata, preferred image base, window RVA,
reference bytes and overlapping supported relocations. Reads and PE table
walks are bounded. Errors are redacted to generic types, not paths/messages.

The runner saves `sdk-api-reference.json`, then an after-capture snapshot in
`sdk-api-reference-after.json`. It retains the before snapshot on early capture
failure. Missing references do not block launch, but invalidate comparison.
For this installation, all three prefix DLL file hashes were verified equal
to the corresponding installed Proton Experimental files before handoff.

The analyzer requires matching PE timestamp, image size, export RVA/window
length and stable before/after reference file hashes. It adjusts wholly
contained DIR64/HIGHLOW relocations for the sampled allocation base. Unknown,
partial, duplicate/overlapping or malformed fixups invalidate comparison.

`sdk-protection-analysis.txt` now includes live/reference hashes, differing
byte counts and first offsets, phase changes, and bounded objdump disassembly
of pre-call live instructions. Valid differences also include reference
instructions. Unknown/mismatched identities are not labelled code alteration.
Legitimate loader modifications must be considered even for a valid difference;
the report does not attribute it automatically to Ubisoft or DRM.

These are code snapshots, **not execution traces**. Matching windows cannot
prove the APIs were executed, identify their return values, exclude a transient
change between sampling phases, or inspect the rest of Wine's Unix dispatcher.
Observer timestamps mark entry into the observer; individual reads occur later
during that phase. Extra logging can change startup timing.

## Verification and next run

- Native disposable-prefix tests on the installed Proton pass for all named
  API windows, exact stub recognition, module ownership, length rejection and
  unchanged sampled code. Routing and binding regressions pass.
- Synthetic PE tests cover export lookup, forwarded/missing/invalid exports,
  file/image bounds, relocations, metadata mismatches, reference freshness,
  code-record allowlisting and disassembly. Seeded unrelated secrets/paths do
  not appear in the reference output.
- Full Python regression: 253 discovered, 248 passed, five opt-in skips.
- DLL builds with warnings treated as errors. Standalone loader/guard tests,
  shell syntax and Python compilation pass. No retail game launched by tests.

Installed DLL SHA-256:
`73dabe3a6a3cdae5e5b6dc6531a175408d03efc1a25c2a55ee6a9bc47d0b75ec`.
The verified original backup remains intact.

Use unchanged Steam options and `sdk-protect-trace` command from
[findings-081](findings-081-sdk-protection-trace.md). Keep Steam and network on
for the same diagnostic setup. Launch once when prompted; no gameplay is
required. Finish after the game exits. The expected guard stop remains; the
retail entry-code result is still pending.
