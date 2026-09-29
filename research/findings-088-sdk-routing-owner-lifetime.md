# SDK routing ownership, descriptor replacement and shared dispatch

Date: 2026-09-26. Read-only static continuation of findings-087. No retail
launch, new probe, game-memory write, installed DLL change, constructor hook,
backend change or launch-options change. All addresses are RVAs in the
inspected build, not portable absolute addresses.

## Result and decision

The longest-lived **direct descriptor owner** established here is the
ConfigurationClient owned by the SDK facade. Its configuration allocation
at client+0x20 stays in place during configuration application, but its
resource-map entries are destroyed and recreated. A saved descriptor pointer
or one-time default-descriptor edit is not persistent.

No separate native base-URL/routing-policy field was found in the traced
facade initialization, client construction, configuration-copy and URL-builder
paths. This is a bounded negative finding, not proof that no such facility
exists anywhere in the executable. The resource map is mutable routing
state, but incoming configuration replaces it.

The first common **request-dispatch** seam verified for session creation and
normal application-configuration GET is:

`facade+0x50 -> HTTP wrapper+0x10 -> interface vtable+0x08`

Interface vtable RVA **0x346d628** has dispatch target **0x21dbad0**. Both
requests reach that same implementation, not merely the same slot number on
unrelated classes. Configuration application does not replace this interface
on the inspected paths.

Prefer a future persistent policy attached to this service-owner boundary
over per-descriptor-constructor hooks. An instance-scoped forwarding adapter
is a candidate design, **not an implemented or proven safe installation
mechanism**. No writable-page permission, safe publication timing,
cross-build compatibility or retail acceptance is established by this trace.

## Inputs and limits

- Runtime text:
  `private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin`.
  SHA-256 is the hash in the filename; file offset zero corresponds to RVA
  0x1000. The existing analyzer verifies that hash.
- Static data: `private/startup-leads-jcoCPbG7/static-rdata.bin`.
  ISACRD01 header; payload RVA 0x2901000, length 22,203,530 bytes. Vtable
  pointer values use preferred image base 0x140000000.
- Bounded disassembly verifies the edges below. Raw E8/RIP-relative byte
  searches locate candidates only; they are not an exhaustive call graph.
- Some synchronization-related calls in this runtime snapshot lead into
  redirected/UBX code. Their precise lock/thread-safety contracts remain
  unknown. Atomic reference counts do not make arbitrary concurrent writes
  to descriptors or interface slots safe.

## 1. Initialization and owners

```text
SDK initialization epoch
  global root [image+0x4849630], reference count at root+0x08
    root+0xa8: registry tracking facades (not their deleting owner here)
    root+0x1d0: separate process-wide transport/service subsystem

Game-side SDK wrapper -- owns --> SDK facade (0x98 bytes)
  facade+0x18 -- owns --> ConfigurationClient (0x90 bytes)
    client+0x20 -- owns --> Configuration (0x148 bytes; stable outer address)
      config+0x90 -- owns --> replaceable resource-map nodes/descriptors
  facade+0x50 -- owns --> HTTP wrapper (0x18 bytes)
    wrapper+0x10 -- owns --> HTTP interface (0x30 bytes)
      dispatch+0x08 -> 0x21dbad0 -> owned asynchronous request clone
```

The facade is the longest common owner of configuration and dispatch. The
global SDK root is longer-lived shared state, but not the direct owner of
these descriptors.

### SDK root

Root acquisition **0x21592d0** checks image+0x4849630. If null, it allocates
0x2c8 bytes, calls **0x2111b30** at 0x2159310, stores the root at
**0x2159318**, and calls service initialization **0x218a640** at 0x215931f.
Acquisition increments root+0x08 at 0x215932b.

The root constructor copies initialization environment arguments+0x128 into
root+0x10 and copies application/other initialization strings. It does not
supply a base URL to the descriptor constructors. Service initialization
allocates the facade registry at root+0xa8 and the separate subsystem at
root+0x1d0 (store 0x218a72b). Do not confuse this subsystem with the per-facade
HTTP interface.

Release code at 0x21be452 onward checks the count, performs shutdown checks,
decrements it, invokes the virtual destructor when zero, and clears the
global pointer at **0x21be4c3** on the last-acquisition path. Deleting
destructor 0x21304b0 calls root teardown **0x2120d10**, which tears down the
registry and transport subsystems. The zero-count virtual slot+0x08 points
to release helper 0xe8740: it invokes slot+0x00 with EDX=0 at 0xe8752, then
frees the allocation at 0xe8757. A root-scoped policy would need to handle
SDK shutdown/reinitialization rather than retaining one pointer forever.

### Facade

The game wrapper allocates 0x98 bytes at **0xed100**, constructs the facade
with **0x210eab0** at **0xed10d**, and stores it in its first qword at
0xed115. The constructor zeroes service slots, including +0x18 and +0x50.
If the SDK root is present, it registers the facade through root+0xa8 /
**0x21be1a0** at 0x210eb33. The registry records facade pointers; teardown
0x21202f0 stops/tracks them without freeing their facade allocations here.

The game wrapper calls facade teardown **0x21200b0** at **0xedc77**, then
frees the facade through 0x2124700. Teardown unregisters/stops the facade,
destroys HTTP wrapper+0x50 at 0x21201bc–0x21201cd, and destroys its
ConfigurationClient+0x18 at 0x212027d–0x212028e.

This establishes ownership, not complete live initialization ordering. The
constructor explicitly tolerates a missing SDK root. Installation timing
must account for registration/publication rather than assume the root
always predates this constructor.

### ConfigurationClient

Both URL paths acquire the client through lazy getter **0x20fa350** with
RCX=facade and RDX=address of facade+0x18. Existing slots are returned
unchanged. Otherwise it allocates 0x90 bytes, calls **0x210a8d0** at
0x20fa3d8, and publishes the pointer at 0x20fa3fc.

| Client offset | Established use |
| --- | --- |
| +0x10 | Direct facade back-pointer; no owning reference operation observed |
| +0x18 | Configuration-applied byte, initially zero |
| +0x20 | Owned 0x148-byte configuration allocation |
| +0x28 | SDK-managed application-ID wrapper, not a base URL |
| +0x80 | Derived feature-switch bits |
| +0x88 | Synchronization-related object used during application |

Configuration allocation/default-construction/store are 0x210a986 /
**0x210a993 -> 0x210a310** / 0x210a998. Client deleting destructor 0x212f650
calls **0x211f7a0**, which destroys and frees the owned configuration via
**0x211f640** / 0x21fbf80 at 0x211f816 / 0x211f81e, and releases its other
owned state. It does not release an owning facade reference at client+0x10.

## 2. Descriptor lifetime and replacement

### Defaults and URL materialization

Default constructor **0x210a310** builds application/session descriptors
using 0x214a370 / 0x214afd0, then copies names, complete URL templates and
versions into config+0x90. Findings-087 records the individual construction,
map-insertion and SDK string-assignment calls.

| Location | Meaning |
| --- | --- |
| config+0x90 | Resource-map header/root reference |
| node+0x20 | SDK-managed tree key |
| node+0x78 | Mapped descriptor name wrapper |
| node+0xd0 | Mapped descriptor complete URL-template wrapper |
| node+0x128 | Descriptor numeric version |

Session helper **0x2144b80** takes client+0x20 at 0x2144bde and calls common
builder **0x217c060** at 0x2144bf5. Application helper **0x21459d0** calls
that builder at 0x2145a54, then substitutes the application ID. Each builder
invocation looks up the current map and uses node+0xd0 at **0x217c148**.
A missing resource returns an empty SDK string at 0x217c114–0x217c11c;
removing descriptors is not a usable redirect.

The builder creates a substituted output value, not a lasting alias to the
map node. Jobs materialize/parse URLs into request objects before dispatch.
A later configuration edit cannot be assumed to retarget a pending request
whose URL was already built.

### Configuration GET -> active owner

The response path builds a separate default configuration at 0x21b4ff2,
parses it through 0x21a4210, then copies it into an async result through
0x21261c0 at **0x21b52db**. This temporary/result is not the active owner.

Successful JobPostLogin branch **0x218cba0** checks state via job+0x230.
The result at job+0x238 supplies configuration at result+0x10
(0x218cc16). It acquires the same facade's client at 0x218cc11 and invokes
configuration application **0x21e1460** at **0x218cc1d**.

### Later connection-notification replacement

A second apply path is **0x21b77e0**, labeled in its continuations as
`JobManageConnection::checkMessageAvailability`. It examines
notificationType/content, constructs a temporary default configuration at
**0x21b7e4f**, recognizes an object member named **configuration** at
0x21b7fa2, parses it at **0x21b7fc3**, acquires the client at 0x21b7fd7,
and invokes **0x21e1460** at **0x21b7fe6**.

This is a connection-message/update path, not evidence that the session
HTTP response contains configuration. The exact notification type selected
by an indirect global-string comparison remains unresolved. Neither apply
path is proven to have executed in the latest failed retail run.

### Replacement semantics

Apply function **0x21e1460** loads the existing client+0x20 pointer at
0x21e148b and calls assignment **0x21261c0** at **0x21e1492**. It does
**not** assign a new pointer to client+0x20 on this path.

The assignment's resource-map section **0x2126376–0x21263c1** checks map
identity, recursively destroys old destination nodes through **0x2138610**
at **0x2126393**, resets sentinel links/count, then clones the source tree
with **0x20e47e0** at **0x21263bc**. Recursive clone 0x20e53a0 calls
node allocator/copy **0x20e40c0**, which allocates fresh 0x130-byte nodes,
copy-constructs key/name/URL through 0x211aab0, and copies numeric version
at 0x20e4154–0x20e415a.

Consequences:

- Outer configuration and destination sentinel persist during assignment;
  descriptor nodes do not. Retaining a descriptor address across application
  is invalid even if an allocator later reuses it.
- A retained SDK string reference can outlive its old node, but is no longer
  necessarily the URL selected by the current map.
- This is whole-map copying, not a merge with old active routes. Omission
  can leave the incoming temporary's defaults rather than preserve an edit.
- Other maps/sdkConfig settings are also copied. Application rebuilds feature
  state through 0x21e1580 at 0x21e14a2, updates global timeout/retry/logging
  consumers, and sets client+0x18=1 at 0x21e1547.
- No independent policy is demonstrated that reapplies a routing override
  after copying. Owner-level normalization would need both initial
  publication and every successful apply, or policy at a service boundary
  outside the replaced data.

## 3. Ownership contracts

SDK strings are 0x58-byte wrappers with intrusive references and cached
narrow/wide state, not char pointers. Assignment **0x2124910** retains the
new reference before exchange and releases the old. Tree destruction
**0x2138610** releases node+0xd0/node+0x78 references, frees cached buffers
as applicable, then frees nodes. Any future replacement must use SDK
construction/copy/release operations, not memcpy URL pointers or retain a
constructor's stack wrapper.

Facade service ownership uses deleting destructors, unlike ref-counted
strings/tasks/results. HTTP wrapper destructor **0x212fde0** calls interface
vtable+0x00 with EDX=1 before freeing the wrapper. Interface deleting
destructor **0x212fe30** invokes **0x21204d0**, releasing interface-owned
state and queued work. A future forwarding adapter must preserve teardown;
it must not leak, prematurely delete or double-delete the original interface.

## 4. Shared downstream dispatch

Lazy HTTP getter **0x20fa750** returns an existing facade+0x50 wrapper or:

- Allocates the 0x18-byte wrapper at 0x20fa7a1; stores facade back-pointer
  at wrapper+0x08, 0x20fa7c5.
- Allocates the 0x30-byte interface at 0x20fa7cc; calls **0x210f5f0** at
  0x20fa7d9; stores it at wrapper+0x10, 0x20fa7de.
- Binds state obtained through facade+0x88 via **0x21e30a0** at 0x20fa7fa.
  This references task-related state; it is not a proven URL-override setter.
- Publishes the wrapper at **0x20fa81b**.

Constructor 0x210f5f0 installs vtable **0x346d628** at 0x210f610:
slot+0x00=0x212fe30; **slot+0x08=0x21dbad0**. Adjacent qwords belong to
other tables, not extra methods of this interface.

| Request | Acquire wrapper | Read wrapper+0x10 | Dispatch |
| --- | --- | --- | --- |
| JobGetSessionInfo::createSession, 0x215e230 | 0x215e5f5 -> 0x20fa750 | 0x215e608 | **0x215e63b** |
| JobRequestConfig::requestConfig, 0x21cc980 | 0x21ccfcc -> 0x20fa750 | 0x21ccfde | **0x21cd0a0** |

Both pass RCX=interface, RDX=output async destination (stack+0x40),
R8=request (session RBP+0xa30; config RBP+0x440), R9=options/label structure.
The options' 7/8 values are **not HTTP methods**.

Request vtables 0x346d738 / 0x346d750 have method-query slot+0x08 returning
0 / 1 through 0x217a5e0 / 0x217a5f0. Dispatcher **0x21dbad0** queries this
at 0x21dbb17 and maps those values to GET / POST literals.

URL storage starts at **request+0x08**, as a parsed/composite SDK URL value.
Session construction **0x21106e0** copies it through **0x211b3e0** at
0x211070c; configuration construction uses the same typed copy. It copies
several SDK strings and a numeric component. Rewriting one cached string
without consistent scheme/authority/port/path is not sufficient. URL parsing
is **0x211b490**; formatting is **0x217db90**, called on request+0x08 at
0x21dbd0a.

The dispatcher constructs an HTTP work item with **0x2113d40** at
0x21dc2aa / 0x21dc306 and queues it through **0x21e6630** at 0x21dc33e.
Work-item construction invokes **request vtable+0x10** at **0x2113d8c**
to obtain an owned clone. Config/session clone functions **0x2153e30** /
**0x2153e70** allocate 0x350 bytes and copy via 0x21100a0 / 0x2110250.
This permits caller-stack request cleanup after dispatch; an adapter must
not retain that stack pointer.

One detail needs preservation: 0x21dc061 onward inspects a URL component
at request+0x110 against `ubiservices.ubi.com`, then checks another component
for `remotelog` and selects a different work-item context branch. A loopback
rewrite can change this classification. The seam is common and persistent,
but transparent forwarding must be validated rather than assuming a host
rewrite has no SDK-side consequences.

## 5. Interception candidates

| Candidate | Survives descriptor replacement? | Assessment |
| --- | --- | --- |
| Root/session environment | May persist; session can supersede root | Fixed prefix selector, not a loopback base-URL override |
| Active config resource map | **No**, nodes are recopied | Correct data owner but a one-time edit is insufficient |
| Client publication plus post-apply 0x21e1460 | Only with reapplication at every event | Owner-level fallback; needs multiple lifecycle checkpoints and synchronization |
| Common URL builder 0x217c060 | Yes, looks up current nodes | Earlier common URL seam; special/external paths may bypass it |
| **Facade HTTP interface / 0x21dbad0** | **Yes on inspected apply paths** | Preferred service-owner policy candidate; covers both verified initial requests |
| Default descriptor constructors | Not by themselves | Do not implement; later supplied URL values defeat constructor-only policy |

Environment getter **0x21730b0** prefers live session+0x270 while its
ticket/deadline checks permit, otherwise root+0x10. Prefix mapper
**0x217ec40** chooses fixed strings such as `dev-`, `uat-`, `cert-`, `cn-`
or empty/default. It leaves the rest of the descriptor template unchanged.
That enum cannot express `http://127.0.0.1:55003` with the default template.

Recommended future design: instance-scoped routing policy at the HTTP
service owner, outside incoming configuration, with exact supported
destinations/paths mapped locally and no forwarding of unsupported external
requests. Preserve method, body/headers, options, async outcomes, cloning
and deletion. If the facade/interface is recreated, the new instance needs
the policy before its first request.

This establishes **SDK HTTP coverage**, not isolation of the separate game
backend, launcher, certificate/directory sockets, WebSockets or every network
path. It does not establish local parser acceptance or world loading. Local
configuration must still advertise deliberate resource routes rather than
rely on defaults or hide schema errors through a transport rewrite.

## Before modifying the game

Follow-up [findings-089](findings-089-sdk-http-routing-installation-contract.md)
traces service stop, URL components/destruction, request-token return and the
shared lower transport seam. It narrows the prerequisites below without
claiming a safe live installation mechanism.

No new broad capture is needed to establish these static code edges. The
remaining prerequisites are specific:

1. Validate publication/teardown timing, including stop/reset/reinitialization
   paths outside configuration application.
2. Confirm writable owner-slot permissions and exact adapter ABI/allocation/
   destructor contract, without editing protected image vtables.
3. Finish typed URL reconstruction and domain-dependent dispatch-context
   handling, preserving owned request clones and async failures.
4. Validate initial session, initial config and later replacement against the
   same instance policy using bounded destination/result metadata, not
   credentials or payload dumps.

Neither a virtual interface nor a writable-looking heap field proves a safe
installation mechanism. No routing adapter or per-constructor hook was
implemented in this work.

## Rechecking anchors

```sh
python3 tools/analyze-startup-static.py \
  private/startup-leads-jcoCPbG7/static-rdata.bin \
  --text private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin \
  --contains Facade:: --contains ConfigurationClient --rva 0x3471510
```

Use `objdump -D -b binary -m i386:x86-64 --adjust-vma=0x1000` on the same
text file with bounded start/stop addresses. Useful windows:

- 0x210eab0–0x210ec20: facade initialization.
- 0x20fa350–0x20fa44c / 0x210a8d0 onward: client publication/config ownership.
- 0x21e1460–0x21e1570 / 0x2126376–0x21263c1: apply/map replacement.
- 0x218cba0–0x218cc22 / 0x21b7e3c–0x21b7feb: both apply callers.
- 0x20fa750–0x20fa855 / 0x210f5f0–0x210f7d7: HTTP ownership.
- 0x215e5ea–0x215e64a / 0x21ccfc1–0x21cd0a3: dispatch callers.
- 0x21dbad0–0x21dc3b4: dispatch, work-item creation and queueing.
- 0x21200b0–0x21202e6 / 0x211f7a0–0x211f82e: owner teardown.

Begin at actual instruction/function boundaries. Inline jump tables are data
even when objdump prints them as instructions.
