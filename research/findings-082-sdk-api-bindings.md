# SDK protection API binding-only probe

Date: 2026-09-26. Builds the requested read-only forwarding-chain diagnostic.

## Lead from the previous capture

`evidence/20260926-183006-offline-sdk-protect-trace-linux` recorded the URL at
`0x143471510`, a 50-byte copy-on-write request, Windows error 5, and the existing
guard termination. Linux sampled an anonymous `r--p` mapping with `mw` among
its VmFlags. The tracer was attached, but no failed mprotect/pkey_mprotect call
was parsed. Wine logged 882 other NtProtectVirtualMemory entries on the same
Windows process/thread, but none for this target. Neither absence proves an
API hook or a kernel fault. The Linux trace also contained two unparsed ENOSYS
probe records, not matching protection failures.

Static inspection of our built DLL confirms that the SDK attempt calls the
MinGW `__imp_VirtualProtect` slot with the expected target, length, selected
flag and valid stack output pointer. It captures GetLastError immediately on
failure. The old observer recorded exported API addresses, not that slot's
live destination, leaving a specific diagnostic gap.

## Implementation

With the existing `ISAC_SDK_PROTECT_TRACE=1` flag, each SDK call phase now emits
four `SDK_API_BINDING` records:

| Edge | Read-only evidence |
| --- | --- |
| shim-to-kernel32 | Exact `__imp_VirtualProtect` slot used by the compiler, compared with kernel32 export |
| kernel32-to-kernelbase | Named kernelbase VirtualProtect import, compared with kernelbase export |
| kernelbase-to-ntdll | Named NtProtectVirtualMemory import, compared with ntdll export |
| kernel32-entry | Recognized indirect forwarding slot, compared with the named import and export |

Records contain the phase/time, status, slot/destination/reference addresses,
comparison flags, destination allocation/RVA/protection/type and an allowlisted
owner category. No filesystem paths, account information, packet payloads or
raw memory/code bytes are emitted. The probe reads metadata; it never calls a
discovered destination, changes a binding, retries VirtualProtect, or removes
the existing URL failure guard. Sampling before/after is not an instruction
trace and may miss a concurrent change between samples.

`sdk_api_bindings.h` validates readable committed regions, pointer arithmetic,
x64 PE headers and import-directory bounds. Descriptor/thunk scans are capped
at 256/8192. Missing original thunks, ordinal-only entries, unavailable imports,
guard/no-access pages and invalid metadata produce explicit unavailable results
rather than guessed pointers. Normal named-import metadata is used, not a broad
code/data scan. Loaded modules are assumed stable during this startup sampling.

The installed kernel32 export is at RVA `0x110dc` and starts with an exact
eight-byte hotpatch no-op followed by an FF25 RIP-indirect jump to its import
slot at RVA `0x554e0`. The reader recognizes this exact prefix and the plain
FF25 form, including signed displacements. It does not skip arbitrary NOPs,
search for jumps or classify unsupported entry shapes as hooks. An earlier
inspection of the separately named VirtualProtect symbol at RVA `0x14560`
missed that the export table points to the hotpatch-prefixed import thunk.

## Analysis and limits

`sdk-protection-analysis.txt` now includes the live binding records and missing
pre-call coverage. Address comparisons are derived from numeric fields, not
trusted logged booleans. It flags changed destinations and mismatches against
export references, but requires alias/forwarding validation before attributing
interception. Matching imports do not prove entry code is unchanged or identify
the instruction returning access denied. A later instruction-level trace may
still be required if all three bindings are ordinary.

The old SDK mode, trace wrapper, mapping observer, permission-only strace filter,
two-second failure hold and backend listeners are otherwise unchanged. Host
networking is still unrestricted; this is not proof of backend independence.

## Validation and handoff

- Native tests on the installed Proton verify all three import destinations
  against exports and the hotpatch-prefixed forwarding slot against the IAT.
- Synthetic PE tests verify bounds, malformed directories/thunks, missing and
  ordinal imports, no-access/guard pages, pointer overflow, exact-prefix checks,
  unknown entry shapes and no fixture mutations. Discovered addresses are never
  invoked, even when a fixture deliberately contains a fake pointer.
- Python tests cover redaction/allowlisting, malformed numeric fields, derived
  comparisons, missing coverage, mismatches, changed bindings and cautious
  ordinary-binding interpretation.
- Full Python regression: 246 discovered, 241 passed, five opt-in skips. DLL
  builds with warnings treated as errors. Standalone guard and routing-helper
  regressions pass. No retail game was launched automatically.

Installed DLL SHA-256:
`8f0b1d772d8fb000287d0b6be6397791e0ae6bd78759130e33e1c30ab345e51f`.
Verified retail backup retained. This is not a fix for the protection failure.

Use the unchanged `sdk-protect-trace` capture command and Steam options from
[findings-081](findings-081-sdk-protection-trace.md). One startup attempt is
enough; no gameplay is needed. Finish after the game exits. Expect the existing
guard stop unless the underlying attempt behaves differently. Inspect all
binding records in `sdk-protection-analysis.txt` before choosing a repair.
