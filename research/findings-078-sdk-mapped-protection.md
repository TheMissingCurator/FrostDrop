# SDK URL replacement: mapped-page protection candidate

Date: 2026-09-26. Candidate fix, not confirmed retail startup success.

## Captured failure

`evidence/20260926-173316-offline-sdk-local-linux/project-isac-stack-probe.log`
records `stage=protect-write,win32_error=5,state=0x1000,protect=0x2,modified=0`.
Executable verification, memory readability/bounds and the exact NUL-terminated
URL comparison passed. `VirtualProtect(..., PAGE_READWRITE)` returned access
denied; the guard terminated without modifying the URL. The SDK listener was
running but received no request. Early URL initialization is not the cause of
this particular failure.

The capture did not record memory type or allocation protection. Therefore it
does **not** establish the underlying mapping or why write permission was denied.

## Relevant mapping rules and change

Microsoft's [VirtualProtect documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
requires a mapped view's requested protection to be compatible with its mapping.
The [file-mapping documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw)
allows copy-on-write access for read-only mappings. Valve's
[Wine virtual-memory implementation](https://github.com/ValveSoftware/wine/blob/bleeding-edge/dlls/ntdll/unix/virtual.c)
distinguishes mapped-view access checks from failures applying host page
protection; both read/write and copy-on-write ultimately request host write
permission. Consequently copy-on-write is not guaranteed to resolve an access
denied error from the host kernel. This inspected branch is not a verified
source match for the installed Proton build.

The SDK helper now selects `PAGE_WRITECOPY` for `MEM_IMAGE`/`MEM_MAPPED` and
retains `PAGE_READWRITE` for `MEM_PRIVATE`. Unknown types are rejected. There
is one protection attempt, no execute-permission escalation, remapping,
unbounded fallback or direct OS write bypass. Existing exact signature,
readability/bounds, original-protection restoration and stop-on-failure remain.
Only the SDK literal helper changes; existing instruction hooks are untouched.

Success and error records now include the memory type and selected write
protection; errors additionally include allocation protection. If a mapped-page
copy-on-write attempt also returns access denied, do not repeat unchanged tests
or conclude that some other byte signature failed. Inspect the host mapping/
protection failure next. If the memory is private, the existing write request
is intentionally unchanged and the new type field will distinguish that case.

## Verification

The native smoke test uses an actual read-only file mapping with two views.
Ordinary read/write protection is rejected with error **87**, while the actual
helper's copy-on-write replacement succeeds. Tests verify the untouched second
view, unchanged file bytes, padding/adjacent bytes, read-only restoration and
fail-closed behavior with an injected mapped-page write refusal. It also patches
a read-only constant in the smoke executable's real `MEM_IMAGE` mapping and
verifies the result through `ReadProcessMemory` to avoid compile-time folding
of a C constant's initializer. Private-page and per-stage diagnostic tests remain.

These tests passed using the installed Proton Experimental `files/bin/wine`
(`wine-11.0`) and a temporary prefix, with its matching wineserver. The rebuilt
standalone DLL smoke also passed under that Wine, including the diagnostic
termination test. These direct Wine tests are not a retail Steam game launch or
an exact reproduction of the game's error **5**.

Python regression: 219 discovered, 214 passed, five opt-in tests skipped.
DLL SHA-256: `2c57cfacb063641252646b728fe0bbcfe77d609ec0ebe7a2429d91d1ec0cf892`.

## Next capture

Same `sdk-local` runner command and Steam launch options. Keep Steam open;
desktop networking may remain on because the runner handles game isolation.
Startup only, no gameplay requirement. First look for `SDK_LOCAL_ROUTE_READY`
with `write_protect=0x8`, then SDK HTTP requests. If the guard still stops the
game, retain its mapping type/allocation/protection fields and exact stage/error.
This changes no backend message schemas and makes no claim that world loading
is implemented.
