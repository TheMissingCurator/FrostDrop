# Upstream SDK resource descriptors and template argument

Date: 2026-09-26. Static investigation requested before working on builder
output. No retail launch, new probe, game-memory write, installed DLL change,
or launch-options change. Runtime routing remains unimplemented.

Follow-up: [findings-088](findings-088-sdk-routing-owner-lifetime.md) traces
the owning client, configuration replacement and shared HTTP dispatch.
It supersedes the constructor-argument preference below: pursue persistent
service-owner routing first; no per-constructor hooks have been implemented.

## Result

Both requested upstream leads exist: an ordinary narrow template argument at
SDK string construction, and resource descriptors containing the complete URL
template before substitution. The default descriptor constructors hardcode
their template input; no caller-supplied base-URL option was established.

The cleanest candidate is substituting the template argument at the two
specific construction calls, letting the SDK allocate its own strings. Finding
an argument boundary is not finding a safe interception mechanism: nothing
here proves that executable-page writes, thread-context changes, or debugger
attachment would be unnecessary. No such mechanism was installed.

## Inputs and validation

Existing private snapshots:

- `private/startup-leads-jcoCPbG7/static-rdata.bin`: ISACRD01 header, RVA
  0x2901000, 22,203,530 payload bytes.
- Runtime text SHA-256
  `dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`;
  file offset zero corresponds to RVA 0x1000.

The existing static analyzer verified the header/text hash and decoded the
named literals. Bounded objdump disassembly verified the instruction edges
below. Raw E8 searches were used only to locate candidate callers; counts of
byte matches are not a verified call graph. All addresses below are RVAs.

## 1. Template argument before string construction

The base template at 0x3471510 remains:

`https://{env}public-ubiservices.ubi.com/{version}`

| Resource | Descriptor constructor | Load template into RDX | Call SDK string constructor 0x211abe0 |
| --- | --- | --- | --- |
| applications | 0x214a370 | 0x214a3bb | 0x214a3c6 |
| sessions | 0x214afd0 | 0x214b01b | 0x214b026 |

At each call, RCX points to a local SDK string destination at RBP+0, and RDX
points to the NUL-terminated narrow template. The entry RCX supplied to the
outer descriptor constructor is saved in RDI as its destination. The
constructors load the URL directly with RIP-relative LEA; they do not accept
it from their outer caller in RDX or another verified configuration argument.

The endpoint suffix is constructed separately using the same SDK string
constructor:

- Application suffix literal 0x3471548:
  `/applications/{applicationId}/configuration`, loaded at 0x214a3cb, call
  0x214a3d6.
- Session suffix literal 0x3471578: `/profiles/sessions`, loaded at
  0x214b02b, call 0x214b036.

The base string is retained in a temporary SDK wrapper; each constructor then
inserts the suffix at the end of its narrow string through 0x218dd60
(application call 0x214a4e1; session call 0x214b141). The helper computes the
insertion offset and passes the suffix range to 0x21c00c0 with zero removed
characters. This is concatenation of the base and suffix, not a stored pair of
independent base-URL/path pointers in the final descriptor.

Consequently a replacement argument such as the existing loopback base
`http://127.0.0.1:55003/{version}` would retain normal suffix construction and
SDK ownership. This is the intended substitution, not a tested retail result.

## 2. Descriptor shape and insertion into the resource map

| Descriptor-relative offset | Meaning established by construction/parser |
| --- | --- |
| +0x00 | SDK-managed name string wrapper |
| +0x58 | SDK-managed full URL template string wrapper |
| +0xb0 | 32-bit numeric version field |

The constructors retain name references at +0x00 and assembled URL references
at +0x58. Application URL storage is the XCHG at 0x214a608; session URL storage
is 0x214b268. Default version writes are 1 at 0x214a647 and 2 at 0x214b2a7.
These are object-relative offsets, not pointers to raw URL bytes.

Default configuration constructor 0x210a310 sets R14 to configuration+0x90,
the resource map. It selects map keys `applications` (0x346bf80) and `sessions`
(0x346c020) and performs:

| Resource | Descriptor construction | Map slot lookup/insertion | Name assignment | URL assignment | Version copy |
| --- | --- | --- | --- | --- | --- |
| applications | 0x210a64c | 0x210a65e | 0x210a66c | 0x210a67c | 0x210a691 |
| sessions | 0x210a6cb | 0x210a6da | 0x210a6e8 | 0x210a6f8 | 0x210a70d |

Both map operations call 0x212aba0. Its result is node+0x78, as shown by the
return-address construction at 0x212ae43. Thus the mapped descriptor's URL is
node+0x78+0x58 = **node+0xd0**, matching the builder's source at 0x217c148.
The tree key at node+0x20 is distinct from the mapped descriptor name.

Assignments call 0x2124910: it increments the new reference before exchanging
the destination pointer, then decrements/releases the old reference. Writing a
plain char pointer into descriptor+0x58 would violate that contract.

The JSON resource parser independently confirms name/string, url/string and
version/number at those same descriptor offsets (0x21a49e0). The resources
callback 0x2135670 parses each entry at 0x21359bc, obtains its map slot at
0x21359d1 and assigns both references plus version. It receives a destination
whose resources map is at +0x18; the full configuration's map is +0x90. Do not
confuse callback-relative offsets with full-object offsets.

## 3. Owning configuration and initialization boundaries

Session/application URL callers get the ConfigurationClient through
0x20fa350, passing the facade and facade+0x18. Its creation path allocates the
client and calls 0x210a8d0. That constructor allocates a 0x148-byte configuration
at 0x210a986, calls default construction at 0x210a993, and stores its pointer
at client+0x20 at 0x210a998. Its incoming R8 participates in application-ID
validation; it is not an established URL-template argument.

Later successful configuration application 0x21e1460 copies a new configuration
into client+0x20 via 0x21261c0 at 0x21e1492. This means a one-time descriptor
replacement cannot be assumed to survive later configuration updates. The
local response must preserve local resource routes as well.

Other default-configuration callers include the request result allocation at
0x21d7ae2 and parser-result defaults at 0x21b4ff2. Modifying any convenient
configuration instance is not sufficient: it must be the one used to build
the initial session and configuration requests, at an established safe point.

A separate `custom.resources` lookup in 0x2172c00 traverses configuration+0x118
and returns a nested value. The common URL builder instead reads
configuration+0x90. The shared spelling `resources` does not establish a
bootstrap routing override through this custom path; none was demonstrated.

## Ordering correction and next target

The literal at 0x34717cc is `{env}`; at 0x34717d8 it is `{version}`. The common
builder applies environment substitution at 0x217c161, then version substitution
at 0x217c31a. Findings-086 had those labels reversed and has been corrected.
This does not change the descriptor/template targets.

We now have two explicit candidate boundaries, upstream of completed URLs:

1. The two narrow-template arguments before SDK string construction.
2. The resource-map URL assignments during default configuration initialization.

Next work is finding how to enter one of those boundaries safely before request
dispatch, preferably through initialization/data plumbing rather than patching
the image template or casually overwriting an active object. A public startup
URL override, stable writable root, safe initialization callback and live
thread/ownership timing have not yet been established. No additional game
capture is needed just to continue tracing those callers.
