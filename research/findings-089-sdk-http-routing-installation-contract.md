# SDK HTTP routing: publication, typed URLs and request-token behavior

Date: 2026-09-26. Read-only static follow-up to
[findings-088](findings-088-sdk-routing-owner-lifetime.md). Documentation only:
no constructor hooks, game-memory writes, new probe, DLL installation, backend
changes or launch-option changes. Addresses are RVAs for the inspected build.

## Decision

The facade-owned HTTP interface remains the preferred **owner-level policy
candidate** for the session/configuration requests. Descriptor replacement
does not invalidate it. This pass establishes three additional constraints:

1. Its lifetime is a service initialization epoch, not necessarily the entire
   lifetime of the facade allocation. SDK stop destroys and clears it.
2. A replacement interface must be installed **after concrete state binding
   and before publication/first dispatch**. Polling an already published slot
   is not a demonstrated race-free installation mechanism.
3. Rewriting the URL before dispatch changes a domain-dependent request-token
   gate. Both branches still reach the same transport, but their scheduling
   is not identical.

There is now also a verified lower fallback seam: HTTP job creation callback
**0x215ab70 -> transport request preparation 0x215b290**. It is after the
domain gate, consumes an owned request clone, and copies the structured URL
before queueing transport work. It is not a discovered virtual routing setter
or an approved/implemented hook.

No persistent native base-URL setting has emerged from these bounded traces.
Do not equate that with proving that no such setting exists anywhere.

## Evidence and limits

Same inputs and address mapping as findings-088:

- `private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin`;
  file offset zero is RVA 0x1000.
- `private/startup-leads-jcoCPbG7/static-rdata.bin`; ISACRD01 header,
  payload RVA 0x2901000. Stored vtable addresses use image base 0x140000000.

Disassembly plus decoded literal/vtable data supports the findings below.
No new live observation establishes page permissions, thread synchronization,
ABI compatibility of a custom adapter, TLS acceptance or successful login.
Redirected synchronization calls in the snapshot remain opaque.

## 1. Publication and service lifetime

Lazy HTTP getter **0x20fa750** has an existing-slot fast return at
0x20fa846. On its construction path it:

| Instruction | Action |
| --- | --- |
| 0x20fa7d9 | Constructs the concrete HTTP interface through 0x210f5f0 |
| 0x20fa7de | Stores interface at new wrapper+0x10 |
| 0x20fa7ed | Acquires facade+0x88 state through 0x20faa40 |
| 0x20fa7fa | Binds that state through concrete function 0x21e30a0 |
| 0x20fa81b | Publishes new wrapper in facade+0x50 |
| 0x20fa823 onward | Leaves the synchronization-related section and returns |

The desired lifecycle point is **after 0x20fa7fa and before 0x20fa81b** on
successful initialization. This is an ordering requirement, not evidence
that this location can be intercepted without protected-code modification.
A fake interface substituted before binding risks having the concrete setter
interpret adapter memory as the original layout.

A raw direct-E8 scan found only the getter call at 0x20fa7fa targeting
0x21e30a0. This supports the traced initialization edge but does not exclude
indirect calls, inlining or other accesses to concrete fields. Likewise,
additional candidate callers of the HTTP getter are not automatically proven
to obey a two-method interface contract.

The verified session/config callers dispatch immediately after the getter
(findings-088). An observer waiting for facade+0x50 to become non-null can
lose the first request. Atomic pointer replacement alone does not resolve
publication, in-flight calls or teardown races.

### Stop invalidates the service even while the facade allocation remains

Facade stop **0x21605b0** deletes the ConfigurationClient via its virtual
destructor at **0x21606f0**, clears facade+0x18 at 0x21606f2, then deletes
the HTTP wrapper at **0x2160707** and clears facade+0x50 at **0x2160709**.
It also destroys/clears synchronization objects at facade+0/+0x08.

Both facade destruction (call 0x21200ea) and SDK registry shutdown (call
0x2120337) reach stop. This refines findings-088's teardown description:
later null-checked service deletion in the facade destructor need not be
where deletion first occurs.

A policy associated with an old wrapper must not survive as a dangling
pointer after this event. Any newly initialized service needs policy before
its first send; this trace does not prove the stopped facade itself is reused.
Configuration application alone is not this stop event.

## 2. Typed URL contract

The URL value is **0x2c8 bytes at request+0x08**. Parser 0x211b490 and
formatter 0x217db90 establish the component layout below. String fields are
SDK-owned 0x58-byte wrappers, not pointers to interchangeable C strings.

| URL-relative offset | Meaning | Formatter evidence |
| --- | --- | --- |
| +0x000 | Scheme | Appends `://` at 0x217dbc3/0x217dbd1 |
| +0x058 | Username | Conditional user-info processing at 0x217dbd6 onward |
| +0x0b0 | Password | Conditional `:` portion at 0x217dc0b onward |
| +0x108 | Host | Appended at 0x217dde7–0x217de01 |
| +0x160 | Numeric port, 32 bits | Omitted if zero; decimal conversion at 0x217de45/0x217de51 |
| +0x168 | Path component | Prepends `/` at 0x217e0d9–0x217e0ee |
| +0x1c0 | Semicolon parameters | Optional `;` at 0x217e18e onward |
| +0x218 | Query | Optional `?` at 0x217e251 onward |
| +0x270 | Fragment | Optional `#` at 0x217e314 onward |

Parser defaults include `http` (literal 0x29fa2c0) and `localhost`
(0x33c9978). These defaults are not evidence that a malformed URL should
be accepted for routing. Port conversion is called at 0x211baf1 and stored
at **0x211bafe**. Decoded delimiter literals are:
0x346ec28 `://`, 0x346ec2c `@`, 0x291d004 `:`, 0x2932634 `/`,
0x2912530 `;`, 0x2924db8 `?`, 0x2934978 `#`.

Consequently request+0x110 is host and request+0x170 is path. Rewriting an
original/full-string cache cannot substitute for updating this value.

### Copy and destruction

- Typed URL copy constructor: **0x211b3e0**.
- Typed URL destructor: **0x21240f0**; destroys all eight string wrappers in
  reverse order through 0x3c160, ending at 0x2124152.
- Request destruction **0x21207c0** releases body/header state and tail-calls
  that URL destructor for request+0x08 at **0x2120835**.
- HTTP work-item construction clones the request through its virtual
  slot+0x10; work-item destruction **0x2121c50** deletes that owned clone
  at **0x2121d33**.

Future implementation should operate on an owned clone, use the SDK parser
to construct a validated replacement URL in fresh storage, and respect the
existing value's destruction/assignment semantics. Calling a copy constructor
over an initialized URL without releasing its old state is not assignment.
Exception-safe replacement and a general URL assignment routine remain
unverified; these are design constraints, not implemented code.

Preserve method, request subtype, headers/body, path and query deliberately.
Use exact supported routes, not arbitrary host substring replacement; reject
unexpected authorities/user-info instead of leaking them into a local URL.
The formatter adds delimiters itself, so component-level reconstruction must
not add them twice. Prefer parsing a complete validated URL over hand-writing
component/cache fields.

## 3. Domain-dependent dispatch is a request-token gate

Dispatcher **0x21dbad0** checks host for `ubiservices.ubi.com` at
0x21dc0d9 and path for `remotelog` at 0x21dc135. For the domain-matching,
non-remotelog branch it increments interface+0x28 at **0x21dc266** and
supplies the resulting sequence and interface+0x20 counter state to the
HTTP work-item constructor. The other branch supplies sequence zero and
empty counter state.

Work-item constructor **0x2113d40** stores sequence at job+0x130 and
retains the counter at job+0x138. Its callback selection at 0x2113ecb onward
is confirmed by literal labels:

```text
Ubisoft-domain, non-remotelog request
  -> waitForRequestToken (0x21f5090)
  -> createRequest (0x215ab70)

Other host, including loopback
  -> createRequest (0x215ab70)

Both -> waitRequestCompletion (0x21f60c0)
```

`JobHttpRequest::waitForRequestToken` is literal 0x346dcb8.
The wait function compares job+0x130 with counter+0x10 at
0x21f5094–0x21f50a8. If the sequence is larger, it remains waiting and
adjusts linked async dependency counts; otherwise it changes callback to
createRequest at 0x21f50da–0x21f50f0. The interface initializes the counter
value to six in the previously traced constructor.

Importantly, **job destruction**, not just successful HTTP completion,
increments counter+0x10 at **0x2121c84** before releasing its reference.
This is consistent with a bounded outstanding-request/token window. It is
not established here as a time-based rate limit or an authentication check,
and the full scheduler/cancellation contract has not been proven.

Changing the host before dispatch therefore bypasses this gate for that
request. It does not, at this branch, select a separate TLS backend or reject
loopback. That bounded finding says nothing about certificate validation or
later server-response acceptance.

## 4. Common lower transport seam

**0x215ab70** loads the owned request clone from job+0x88 and transport
from global SDK root+0x1d0. It calls **0x215b290** at **0x215abb5** with
RCX=transport, RDX=output destination, R8=request clone, then queues the
result through **0x21bb9d0** at **0x215abc6** and signals the worker.
It retains the transport result at job+0x128, binds async state through
0x21efb60 at 0x215ac91, and selects waitRequestCompletion.

Inside **0x215b290**, request preparation copies headers (+0x2d0), queries
the method via virtual slot+0x08 at 0x215b2ea, and copies request+0x08 URL
through **0x211b3e0 at 0x215b2fe**. The bounded prefix also reads
request+0x348 and branches by method; later transport details are not fully
traced here.

This establishes a common downstream point after domain classification and
before the transport's URL copy. A future rewrite here could leave the
original token decision intact, but installing it is a separate problem:
the observed call is direct, not a discovered replaceable virtual slot.
Do not trade a known owner boundary for another unproven protected-code hook
without resolving that tradeoff.

## Next implementation gate

Prefer the facade service policy if its installation can be made deterministic.
Before enabling writes, establish **one supported pre-first-send installation
mechanism** with the current launcher/probe, verify slot permissions without
changing them, and audit dispatch/direct concrete accesses plus deletion.
Do not silently fall back to polling an interface that may already be active.

Then a bounded validation should cover initial session, initial configuration,
configuration replacement, shutdown and a fresh SDK epoch. Record instance
identity, lifecycle ordering, route category and outcome only; credentials,
tickets, bodies and full sensitive query strings are unnecessary. Preserve
normal async failure when an unsupported route is blocked. Test HTTP redirects
and separate game traffic independently: this interface is not an egress
firewall and does not prove that every network path is covered.

This investigation reduces the unknowns; it does not claim the game can now
load a world. No additional user capture is required merely to reproduce
these static findings.

## Rechecking

Use the text/rdata inputs above and the objdump address mapping in findings-088.
Verified function windows:

- 0x20fa750–0x20fa855: service initialization/publication.
- 0x21605b0–0x216078b: stop/service destruction.
- 0x211b490–0x211bde0 and 0x217db90–0x217e3fd: URL parse/format.
- 0x21240f0–0x2124157 and 0x21207c0–0x212083a: URL/request destruction.
- 0x2113d40–0x2113f2a and 0x2121c50–0x2121d51: HTTP job ownership/token return.
- 0x21f5090–0x21f5126: token gate.
- 0x215ab70–0x215acf4 and 0x215b290–0x215b355: transport preparation edge.

Do not treat arbitrary disassembly starts or inline jump-table data as valid
instruction boundaries. Function names above are inferred except for the
explicitly decoded job labels.
