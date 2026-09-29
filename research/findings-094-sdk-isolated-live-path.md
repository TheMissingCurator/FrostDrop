# 094 — Opt-in isolated SDK adapter and Linux-side installation entry

## Outcome and limits

Implemented both production connections missing in findings-093: process-lifetime
kernel network isolation and a Linux-debugger-controlled pre-publication entry.
Built the experimental local shim into `dist/uplay_sdk_adapter/`, separately from
the old build. [Test instructions](../docs/sdk-adapter-test.md) provide the runner,
Steam options and recoverable installation. The user explicitly approved adding
a separate isolated test mode; the existing host-network mode remains available.

**No retail game run has verified this path yet.** Real-kernel/Steam/debugger
fixtures pass, but retail acceptance, native SDK allocation/completion behavior,
live anchor availability, startup timing and successful session/configuration
requests still require the first game test. This is not world-load completion.

## Transport enforcement

The new runner uses the retained `isac-netns.py` implementation: game/backend
share only private loopback, without external routes or inherited host sockets.
The launcher verifies namespace/prefix identities, clears proxy and legacy ISAC
flags and refuses to launch without a matching active capture and installed DLL.
The debugger independently checks the actual tracee namespace before admission
and each installation. Environment markers alone cannot authorize the adapter.

This is permanent per-process IP isolation, not a temporary per-request lock.
It remains in force after backend shutdown or adapter destruction. Therefore
`transport_process_lifetime` allows normal SDK interface destruction without
pretending all queued jobs have drained: releasing this lease cannot reopen an
external route. The ordinary finite lease/drain contract remains for other
bindings. Native job/request/result reference ownership is unchanged.

Initial SDK requests are restricted to the canonical `127.0.0.1:55003` routes.
Kernel isolation additionally blocks direct external destinations reached by
redirects/retries/proxies. It does not limit every socket to port 55003: private
loopback services remain reachable. The supplied SDK server never redirects or
forwards unknown requests. The fixed Steam IPC bridge reaches only the verified
host Steam endpoint. Steam-mediated activity/other host IPC is not an air-gap
guarantee, and no host interfaces or firewall rules are altered.

## Initialization/ownership path

The experimental shim's first local-export initialization verifies the executable
SHA-256 `31c74abfedb52fa2ef8342e8f434d766184eca32d85ea9419bcbb46c09a6e379`
and live instruction anchors for all bound functions, request methods/destructors,
clones, and the publication path. Anchors are generated only from the hash-checked
private snapshot. The SDK root must still be null. The debugger repeats the root
check while all threads are stopped, closing the race between the shim's check
and breakpoint installation. Unexpected/late state is fatal, not polled away.

The shim rendezvous is an `int3` in **our own DLL**. GDB creates an explicitly
hardware, inferior-specific execution breakpoint at game+`0x20fa7ff`. It follows
the command's process tree and covers newly created threads. No software
breakpoint fallback, game instruction rewrite, shared vtable write, Windows
`SetThreadContext` call or `VirtualProtect` call is used for this SDK adapter.

At the verified stop, GDB checks R14 facade, RBX=facade+0x50 (still null), RDI
wrapper, back-pointer, private writable allocation ranges, original interface
identity and the `eb 03` instruction. It locks scheduling to the stopped thread,
temporarily disables that execution breakpoint, redirects RIP to our register-
preserving entry and single-steps its initial NOP. The NOP is necessary with
GDB 17: otherwise a later completion trap was misclassified as a delayed hardware
trap. Stepping `pushfq` instead would save the debugger's TF, so the explicit
NOP precedes flag preservation.

The entry preserves flags, volatile integer registers and XMM0–XMM5; nonvolatile
registers are preserved by the Windows ABI C callback. It calls the verified
private-slot installer after state binding, then resumes game+`0x20fa804`, the
original jump destination, so the getter publishes the wrapper normally.
The debugger verifies a matching completion and changed slot before re-enabling
the breakpoint and resuming the other threads. It keeps the breakpoint for later
service epochs. No descriptor-constructor hook or published-slot polling exists.

Eight service/core objects are reserved before entering stopped publication
callbacks. Binding/installation at the stop uses only bounded reads of debugger-
validated memory, comparisons and an atomic pointer CAS—no heap allocation,
Wine RPC, file logging or Windows VM query while other Wine threads are held.
This avoids deadlocking against a stopped allocator/wineserver. Epoch exhaustion
refuses the test instead of allocating inside that stop. Unused reservations
remain process-owned until exit. The original SDK destructor retains its normal
ownership role; the adapter shell uses its own allocator.

The production private-slot write uses debugger-validated Linux mapping/range
checks and CAS under the held stop. The standalone Win32 `VirtualQuery` writer
remains available for other admitted callers; it is intentionally not invoked
while the debugger holds Wine's other threads/processes.

Unexpected stops, mismatched completion, failed hardware arming or native
installation refusal terminate only descendants launched by this debugger.
They never detach a partially installed game and resume it on the old sender.
If the debugger itself is forcibly killed, kernel external-IP isolation still
holds; that is not a claim of clean game recovery.

## Test scope and verification

The first game test enables only SDK session/configuration HTTP. Legacy
certificate/handoff/world hardware probes are disabled to prevent debug-register
competition. A separate backend/world startup failure is possible and expected
to need later integration; it is not proof that an earlier SDK installation failed.

Passed:

- 41 SDK tests, including the new launcher/backup checks, request/result/service
  fixtures, the real Linux debugger fixture and local SDK HTTP service tests.
  Adapter fixture builds also ran under address/undefined/leak sanitizers.
- Real debugger fixture: two concurrently released threads, created after arming,
  each installed before publication; preserved integer/XMM register sentinels and
  correct resume path, including a followed forked child and launcher-parent exit.
  Uses the actual entry assembly and production driver with
  a separate synthetic-only fixture entry, not the retail SDK.
- Namespace suite: 13 passed, one optional Steam-runtime check skipped; private
  loopback works, host/external IPv4/IPv6 paths fail, prefix/cleanup guards hold.
- Steam IPC suite: four passed, including actual installed Steam pipe/user
  handshake inside isolation and negative network controls.
- MinGW DLL build and saved-snapshot ABI verification passed.

Socket/ptrace/sanitizer checks needed approved runs outside the execution sandbox.
These permissions are test-harness constraints, not evidence that Windows memory
protection was repaired. No game was launched by these tests.

Relevant GDB contracts: [hardware breakpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Breaks.html),
[all-stop/scheduler locking](https://sourceware.org/gdb/current/onlinedocs/gdb.html/All_002dStop-Mode.html),
and [inferior-specific Python breakpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html).
Local GDB 17.2 support was checked directly and exercised by the fixture.

## Handoff

Installed the experimental DLL with user-approved filesystem escalation; the
verified preceding local shim remains beside it as
`uplay_r1_loader64_isac_before_adapter.dll`. No retail backup was changed.
An actual runner EOF smoke test reached isolated SDK listener readiness, then
shut down and removed its session records without launching a game. Its artifact
`evidence/20260926-215758-633232-sdk-adapter-linux` is harness evidence only,
not a user capture or evidence of retail installation/HTTP acceptance.

## Steam debugger-loader failure and launcher correction

User capture `evidence/20260926-220107-388954-sdk-adapter-linux` reached
`SDK_SERVICES_READY`, but GDB could not start: Steam's pinned `libcurl.so.4`
lacked `CURL_OPENSSL_4`, required by system `libdebuginfod.so.1`. No shim output
or Proton log was produced in that capture. This is a Linux loader mismatch,
not an adapter installation failure or the previous Windows access-denied error.

The runner now explicitly uses `/usr/bin/gdb` with inherited `LD_*` and
`PYTHON*` overrides removed. `/usr/bin/env` restores those exact values only
when executing the original Proton command under GDB. Restoration uses argv,
not shell interpolation. Proxy removal, isolation checks, adapter opt-in and
capture settings remain unchanged. No DLL or game-file change is needed.

Verification: five adapter-tool tests pass, including host GDB/embedded Python
startup with the installed Steam pinned-library path supplied to the environment
splitter. Two opt-in real-debugger tests pass outside the sandbox: the existing
publication/register fixture and a child verifying exact restored environment
values (including spaces and shell metacharacters). These are synthetic checks;
a new Steam/game capture is still needed to validate retail startup.
