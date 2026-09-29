# 093 — Native sender wiring and guarded pre-publication installation

## Status: implementation foundation, not an enabled game mode

Added `sdk_http_native_service.{h,c}`, connecting the portable route policy,
native request helpers and native failure-result helper to a two-slot Windows
x64 service interface. Added the Win32 private-pointer installer primitive and
an isolated Windows integration-library build. No game files, live memory,
installed shim or Steam options changed. Existing `sdk-local` still uses the
older template-patching path; running it does not test this adapter.

**Still missing:** a production transport-enforcement/drain capability and an
authenticated, held pre-publication initialization event (including live build
validation). Those callbacks exist only as fixtures. Consequently this is **not
yet a self-contained loopback sender or automatic live installer**. A numeric
URL check is not proof that the original SDK transport cannot follow redirects,
use a proxy or reuse an external connection. Do not replace these missing gates
with callbacks that just return true.

## Native sender and ownership

The adapter now has native ABI dispatch and deleting-destructor entries. Dispatch
clones and rewrites through the existing core. Immediately before forwarding,
the sender re-describes the actual clone and requires exact equality with the
canonical loopback route (not merely acceptance by the production/local routing
allowlist). It verifies the original service vtable and both entries again.

Under a separately enforced transport lease it calls the saved native dispatcher
with the original service, fresh output, owned rewritten clone and unchanged
options identity. This preserves the SDK's request serialization, job queue,
response parsing and asynchronous result machinery; it does not implement a new
HTTP stack. The SDK constructs its own queued request clone before returning.
The adapter's clone can then be destroyed. A pending native result is normal.

Before entering native dispatch, rejection may construct a completed failure.
After entering it, a wrong returned output pointer is fatal: queued work/output
may already exist, so it must not retry, construct a second result over the
same storage or fall back to another sender. Failure-result construction errors
are also fatal at this boundary. Fatal messages are fixed strings, not payloads.

The required lease must cover queued work, redirects, proxies, retries, DNS and
existing connections, with destination restricted to `127.0.0.1:55003`. A failed
readiness check refuses new sends; enforcement of previously queued work must
remain in force. A boolean/environment variable alone does not meet the contract.
This narrow SDK policy does not by itself isolate the game's separate backend,
launcher or other networking paths.

Preparation acquires a lease but does not take ownership of the original SDK
interface. Successful installation transfers that ownership to the adapter.
At normal teardown, the owner must exclude new dispatches; the active-call
counter detects misuse but cannot create that exclusion. The adapter requires
queued work to drain, deletes the original through its SDK destructor with
flags 1, and only then releases the lease. Its own shell is released through
its own allocator when flag bit 1 is set. Flags 0 release members but leave shell
storage to the caller. The supplying DLL and SDK must remain loaded throughout.

Native exceptions/allocation faults are still not caught. The forwarding and
teardown contracts require live validation; fixture success is not evidence of
retail quiescence, fault recovery or cancellation behavior.

## Installation path

Required event remains **RVA 0x20fa7ff**, immediately after concrete state binding
at `0x20fa7fa -> 0x21e30a0`, before wrapper publication at `0x20fa81b`.
At that point the inspected getter holds:

| Register/value | Meaning |
| --- | --- |
| R14 | Facade |
| RBX | Address of facade+0x50 owner slot |
| RDI | Newly initialized HTTP wrapper |
| wrapper+0x08 | Facade back-pointer |
| wrapper+0x10 | Bound original HTTP interface |

The installer accepts these values only through a caller-authenticated stopped
initialization event. It checks the exact instruction, slot relationship, empty
owner slot, wrapper vtable/back-pointer and original interface identity. It then
compare/exchanges **only wrapper+0x10**. The getter retains responsibility for
publishing wrapper into facade+0x50 after the callback returns. Failed preparation
or installation is discardable without deleting the original interface.

`sdk_http_install_win32.c` implements that write using `VirtualQuery` and
`InterlockedCompareExchangePointer`. It refuses unaligned, overflowing, crossing,
uncommitted, image-backed, guarded, executable or non-writable slots. It accepts
only an already committed `MEM_PRIVATE` / `PAGE_READWRITE` allocation. There is
no `VirtualProtect`, shared vtable modification or executable-byte patch.
The live barrier must pin allocations/protections across the query and write;
the API calls alone do not prevent races.

**Not implemented:** reaching that event automatically or authenticating it in
the current launcher. Filling a register snapshot from polling is not equivalent.
The old hardware-breakpoint/protection failures were not assumed resolved.
No per-descriptor-constructor hook, late-slot polling or silent fallback was added.

An installed service persists across descriptor replacement within its owner
epoch. Shutdown deletes it; a fresh service must be admitted/installed again
before publication. There is no hot-uninstall or reuse of an old adapter pointer.

## Static anchors checked this pass

Same text/rdata snapshots as findings-092. The read-only verifier now additionally
checks:

- Original service vtable `0x346d628`: destructor `0x212fe30`, dispatch `0x21dbad0`.
- Wrapper vtable `0x346cf68`, destructor `0x212fde0`: load +0x10 at `0x212fdf9`,
  invoke its slot zero with flags 1 at `0x212fe05`/`0x212fe0a`.
- Original deleting destructor calls member cleanup `0x21204d0` at `0x212fe3f`
  and conditionally frees SDK storage at `0x212fe4c -> 0x21fbf80`.
- State-binding call, post-binding instruction and publication instruction above.

The dispatch prefix saves RCX as service, RDX as output, R8 as request and R9
as options. These native arguments must not be confused with the portable core's
semantic method enum. Whole-text snapshot verification still is not live build
validation or proof that an initialization barrier is available.

## Tests and build

Five tests pass in `test_sdk_http*.py`, normally and under address/undefined/leak
sanitizers. The new service fixture covers pending-output preservation, unchanged
caller/options, clone ownership, canonical-local rechecking, enforced-lease
refusal/loss, failed installation without ownership transfer, late-publication
refusal, descriptor-change requests, teardown order and a fresh epoch.
Separate child processes verify fatal result/return/drain failures cannot take an
external fallback. Leak checks are intentionally disabled only in those fatal
exit children (a fatal process cannot cleanly unwind the live SDK epoch).

The Win32 writer fixture supplies synthetic `VirtualQuery`/CAS implementations
and checks permission, range and expected-pointer refusal. It does not execute
Wine's actual memory manager. The other native request/result suites remain
separate; service fixture SDK/transport functions are stand-ins, not retail code.
No socket-level redirect, retail login, configuration replacement or world-load
test has been performed.

```sh
python3 -m unittest discover -s tests -p 'test_sdk_http*.py' -v
ISAC_ADAPTER_SANITIZE=1 python3 -m unittest discover -s tests -p 'test_sdk_http*.py' -v
bash tools/build-sdk-http-adapter.sh
python3 tools/verify-sdk-http-request-abi.py
```

The build compiles all five modules with MinGW warnings-as-errors into
`build/sdk_http_adapter/libisac_sdk_http.a`. This is an integration library, not
a replacement game DLL. It deliberately is not linked into either active shim
until the two missing production gates are implemented and verified.
