# SDK adapter plus isolated transport startup

## Baseline and remaining boundary

User capture `20260926-220921-664912-sdk-adapter-linux` installed the native
adapter (epoch 1) and received HTTP 200 from local session creation and
configuration. Configuration authorization checks the newly issued session
ID/ticket, so that second request also demonstrates reuse of the local session.
This does not prove complete game login, main-channel setup, or world loading.

The old walking-around slice uses the port-55000 plaintext bridge. Findings
063/064 establish a separate encrypted main transport and unresolved
registered application bindings. Do not copy bridge selectors or ISACWBS1
bytes into an arbitrary encrypted channel.

## Combined mode

`sdk_adapter_test.py run GAME COMPAT transport` preserves the working SDK
adapter and adds existing certificate (27015), split directory (51000),
main-channel (55001) and latency (55002) listeners. The old `sdk` default stays
available. All listeners share the existing isolated network and must report
readiness before the launch prompt. Partial startup and normal exits stop all
children. No plaintext-bridge/world replay server is started.

Game launch uses a private mount overlay for `/etc/hosts` and `/etc/nsswitch.conf`:
only the two known bootstrap names are reassigned, and hosts lookup uses files
only. Desktop DNS/hosts files are not edited. The final launch order establishes
the overlay before GDB, while avoiding ancestor namespace-link reads as described
below. Record hashes attest the inferior's mount view and the
per-run public certificate snapshot. The existing fixed Steam IPC relay remains;
this is external-IP isolation, not a guarantee against all host IPC mechanisms.

## Local certificate admission, without the legacy Windows hooks

Same attested runtime text snapshot as findings 094. Read-only disassembly:

- 0x20655d2 zeros R13D; RBP retains the TLS object.
- 0x206563e loads the certificate-list buffer from RBP+0x58.
- 0x2065674..0x2065698 reads the 24-bit list length into R14D and checks it
  against message size; RDI advances past the list-length prefix.
- 0x20656c0..0x206572e accumulates certificate lengths including each 3-byte
  prefix in R15D, parses certificates, and advances RDI to their end.
- 0x2065736 calls verification. At the existing return seam 0x206573b, the
  13-byte instruction signature matches the former local-accept probe.

The Linux debugger now owns a second hardware breakpoint at that seam. Before
changing a failing EAX result to 1 it requires: current network isolation,
matching live signature, R13D=0, R14D=R15D=3+local DER length, and byte-for-byte
equality of `[RDI-R14D,RDI)` to the one-certificate list containing our generated
bootstrap certificate. It also checks verification mode at RBP+0x140. Unmatched
or unreadable certificates keep their original result. A 256-stop limit bounds
retries. Neither Windows VirtualProtect/SetThreadContext nor executable patches,
shared vtable patches, broad TLS disabling, or global trust-store edits are used.

This is a static-derived extension to a previously observed verifier seam.
Its complete-buffer pin layout still needs retail confirmation. A `pinned=0`
result must not be fixed by dropping the equality check.

## Verification and handoff

Synthetic checks cover hosts/NSS filtering, exact pin and rejection cases,
SDK-only preservation, startup-failure cleanup, all five real loopback service
ports in one isolated namespace, CA-trusted TLS exchanges, latency completion,
main registration/heartbeat responses, and closed ports after teardown.
The mount wrapper -> system GDB -> child launch chain is exercised separately
from the game. A real debugger fixture exercises the certificate instruction
anchor and both positive/negative pins alongside the existing two-thread SDK
installation/register-preservation fixture. Socket/ptrace checks require an
approved run outside the execution sandbox.

Verification result: all 49 `test_sdk*.py` tests passed with real debugger and
isolated transport tests enabled, including the 12 adapter-specific cases.

No game file or DLL changes. Steam launch options remain the SDK adapter
wrapper; only add `transport` to the terminal command. Keep desktop networking
on. Stop at the first stable result, exit the game, then end the capture.
Next evidence is main-channel registration and inner request binding—not a
claim that replay or persistent gameplay is already connected.

## Namespace-owner permission regression and first attempted correction

Retail capture `20260926-222435-491625-sdk-adapter-linux` reached
`SDK_ADAPTER_WAITING`, then failed in `netns.check` while inspecting the separate
supervisor's `/proc/121835/ns/net`. The game PID was 122496, not 121835. The
debugger's fail-closed handler killed its tracees before adapter installation;
all listeners started, but no SDK/certificate requests arrived. This is not
Windows VirtualProtect or a certificate-pin failure.

Adding the real owner check to the former mounted-GDB integration fixture
reproduced the same PermissionError. The extra bwrap layer restricts GDB's
access to the ancestor namespace supervisor. The fix places the mount wrapper
under GDB's `--args`, before the existing `env`/Proton command. GDB retains its
previous permissions; bwrap still starts with the sanitized loader environment.
Steam's loader settings are restored only for Proton, as before.

The debugger now checks routing-file hashes through the stopped inferior's
`/proc/<pid>/root/etc` rather than its own `/etc`. The supervisor identity,
current network negative controls, inferior namespace equality and exact
certificate pin remain enforced. No added capability, host-network fallback,
permission-error suppression or changes to game files are used.

Regression: the strengthened synthetic test failed before the change and
passed afterward. It verifies the supervisor both before launch and at a
real inferior stop, checks that inferior's mounted files/network, exercises
the local service bundle, and verifies cleanup. A negative mount-hash/read
test ensures inaccessible or changed routing files still fail closed.

## GDB crash reproduction and final launch arrangement

The first correction above was superseded after user capture
`20260926-222940-740442-sdk-adapter-linux`: GDB itself segfaulted after Steam's
`srt-bwrap` probe helpers exited, before any game shim output. No backend
requests arrived. This was not the intentional namespace-error handler.

The installed SteamLinuxRuntime_4 entry point, production Driver, and a trivial
payload reproduced the same fatal GDB backtrace in a fresh isolated test.
Detaching only the outer bwrap supervisor and disabling optional libthread_db
did not fix it; those experiments were removed. Keeping the extra mount setup
outside GDB's traced process tree did fix the reproduction. We have isolated a
working topology, not diagnosed or patched GDB's internal C++ defect.

The remaining ancestor-read problem is addressed with explicit member
validation, not a PermissionError fallback: the session records supervisor
start time from /proc/PID/stat at creation. GDB validates that PID's UID and
start time, its own held network namespace against the validated session,
loopback/IPv4/IPv6 negative controls, and the target's network namespace and
mounted routing files. The held namespace cannot recycle its inode while the
debugger inhabits it; PID plus start time detects supervisor reuse. No ancestor
ns symlink dereference is needed from the nested user namespace. Joining still
uses validated namespace handles and the original strict check.

Tests now exercise the actual Steam runtime with production multiprocess
settings and require the final marker-printing payload to execute before the
expected no-adapter refusal (no game runs in this fixture). The nested-GDB
fixture validates namespace membership/supervisor lifetime before launch and
at a real inferior stop. Negative tests reject wrong namespaces, stale/missing
owner lifetime, inaccessible owner records and changed/inaccessible mounts.
All 50 SDK tests passed, plus 15 namespace tests; one separately gated runtime
namespace test was skipped. The actual Steam-runtime regression above ran.

No game/DLL changes and no new privilege grants. Same `transport` command and
Steam options; a fresh capture is required to create the new lifetime record.

## Runtime NSS mismatch (223730 capture)

`20260926-223730-455667-sdk-adapter-linux` reached the game's SDK rendezvous
without the GDB fatal signal or supervisor permission error. Its intentional
stop was `Game transport mount view changed: nsswitch.conf`. Hosts hashing had
already passed. No adapter was installed and no service requests arrived.
The exact failing game's NSS contents were not captured, so its active policy
cannot be reconstructed from this log alone. The installed runtime includes
a different NSS file with `hosts: files myhostname dns` and different non-host
entries. The whole-file-equality requirement was unnecessarily restrictive.

The target check now retains exact hosts-file equality and validates one
unambiguous NSS hosts entry against three explicit profiles: `files`,
`files dns`, `files myhostname dns`. No action clauses, duplicate entries,
DNS-first ordering or resolve/mdns/wins/nis providers are admitted. The two
known names resolve via the pinned hosts file before fallback. Kernel network
isolation, negative controls, owner lifetime and certificate pin remain
unchanged; this does not claim an air gap from arbitrary host IPC.
`ISAC_TRANSPORT_ROUTING` prints only the approved policy label. The source
capture files remain hash-checked against the active session before launch.

The regression now runs a synthetic Python payload inside the actual Steam
runtime with the production debugger: it checks the target mount policy and
performs real lookups of both bootstrap names, requiring only 127.0.0.1 results.
It passes with our files-only overlay and with the installed runtime's NSS
profile while retaining the original expected NSS hash. Negative policy cases
fail closed. All 51 SDK tests passed with real debugger/runtime checks enabled.
Retail confirmation of the actual game's accepted policy is still pending.

Moving GDB to a host network namespace would not address this failure: the
rejected configuration belongs to the game process's runtime mount view, and
GDB already reached and inspected that process in this run.
