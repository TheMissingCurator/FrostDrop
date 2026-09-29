# SDK session response and post-login configuration

Date: 2026-09-26

## Scope and runtime boundary

Read-only static investigation following capture
`20260926-154244-offline-login-handoff-sweep-on-linux`. No backend, injected
loader, game files, or launch options changed; no live service requests made.

The repaired logger records services states 1, 2, 5, 10, with both services
and game-auth tickets empty. Game auth remains state 4 and has no auth client.
The local certificate/directory/latency exchanges do not establish a main
55001 connection. This identifies the missing services-session handoff, not
the precise SDK error or proof that an HTTP response was parsed in this run.

Static input: runtime text SHA-256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`,
loaded at RVA 0x1000, and the ISACRD01 static-data capture in
`private/startup-leads-jcoCPbG7/static-rdata.bin` (payload RVA 0x2901000,
16-byte header). All code addresses below are RVAs, not absolute addresses.

## State 10 really is a login failure

The handler at 0x1813850 has a branch for incoming message code 0x3b.
At 0x18138ec it admits services states 5 or 7, calls 0x18589e0, then passes
EDX=10 and the literal `Login failed` (data RVA 0x31b0910) to state setter
0x18bb890 at 0x1813918. This gives the observed state a concrete label; it
does not identify the failure's original cause.

## Login job to response parser

The worker-to-SDK entry chain is described in findings-066. The new links are:

1. AuthenticationClient::login (0x215d560) constructs a job with 0x2114380
   at 0x215ded0 and schedules it through 0x218f280 at 0x215dee6.
2. The constructor installs callback 0x217ce40 at 0x211467e. That callback
   constructs a child with 0x2113a90 at 0x217ce91. The child's constructor
   selects 0x215e230, labeled `JobGetSessionInfo::createSession`, at
   0x2113cf6–0x2113d04.
3. The createSession function selects callback 0x21c3c90 at 0x215ee9e,
   labeled `JobGetSessionInfo::reportOutcome` at 0x215eeb5, and passes it
   to 0x21f9920 at 0x215eed9. There are earlier parameter-validation exits;
   reaching the login worker does not prove an HTTP request was submitted.
4. reportOutcome extracts response text through 0x21712d0, builds a JSON
   representation through 0x214bb80, and calls **0x21ac740** at 0x21c3dbe.
   It tests AL and branches on failure to 0x21c3ff6. That branch references
   `Failed to parse profile/sessions response. JSON: ` at 0x21c4012 and
   constructs an error record with numeric code 10 at 0x21c40ab. This SDK
   error code must not be conflated with the game's services state 10.

The endpoint descriptor constructor at 0x214afd0 references
`https://{env}public-ubiservices.ubi.com/{version}` and `/profiles/sessions`.
It is installed under the key `sessions` by the call at 0x210a6cb. These
are templates, not confirmation of the concrete hostname/version used in
the latest capture. HTTP method, final routing and TLS behavior still need
verification before wiring a local endpoint.

## Session schema recovered from the parser

0x21ac740 takes the destination session object in RCX and a JSON wrapper in
RDX. It requires an object node (numeric type 6), iterates members, compares
keys, checks value types and copies/converts accepted fields. String type 4
is also corroborated by the JSON string writer in 0x215e230. Boolean nodes
use types 0/1. The accountIssues branch expects array type 5.

Offsets are relative to the parser's destination session object, NOT the
game's services/auth objects. String slots are SDK string objects, not raw
character arrays suitable for direct memcpy.

| JSON key | Accepted value / processing | Destination | Presence bit |
| --- | --- | --- | --- |
| token | string | +0x60 | none |
| ticket | string | +0xb8 | 0x001 |
| profileId | string, UUID-shape helper 0x218f1a0 | +0x110 | 0x002 |
| userId | string, UUID-shape checks | +0x168 | none |
| nameOnPlatform | string | +0x1c0 | none |
| hasAcceptedLegalOptins | boolean | +0x3a8 | 0x004 |
| spaceId (or productId) | string, UUID-shape helper | +0x218 | 0x008 |
| environment | string, enum conversion 0x2173200 | +0x270 | 0x010 |
| expiration | string, date conversion 0x21a0d60 | local date; derived deadline +0x2d8 | 0x020 |
| serverTime | string, same date conversion | local date / SDK time update | 0x040 |
| clientIp | string | +0x278 | 0x080 |
| initializeUser | null/boolean handling; additional fallback branch | +0x2d0 | 0x100 |
| sessionId | string, normalization helpers | +0x08 | 0x200 |
| platformType | string | +0x2e0 | 0x400 |
| accountIssues | array; element parser 0x21a31a0 | +0x338 | 0x800 |
| rememberMeTicket | string | +0x350 | none |

The missing-field helper **0x214fc40** checks six bits: ticket, profileId,
hasAcceptedLegalOptins, spaceId, environment, expiration (mask 0x3f). It
returns true when its missing-fields list is empty. Thus those six are the
ordinary missing-field validation baseline, not proof of a sufficient login
response or a strict universal JSON schema.

Important qualifications:

- The parser calls that helper only when a local flag is clear and the
  accumulated mask is numerically below 0xeff (0x21ad50d–0x21ad547).
  This is an unsigned numeric comparison, not `(mask & required)==required`.
  Some invalid-identifier branches set the local flag and skip that helper.
  Do not build an emulator around these permissive/error-path quirks.
- profileId/spaceId helper 0x218f1a0 checks length 36 and hyphens at offsets
  8, 13, 18, 23 before calling another validator. Accepted identifiers still
  have to be consistent with later profile checks; arbitrary strings are not
  established as sufficient.
- `token` and `ticket` are separate fields and destinations. Only ticket
  sets bit 1. Likewise, this SDK session ticket is not automatically the
  launcher's ownership ticket.
- Expiration and serverTime go through a date parser and deadline arithmetic;
  the presence bits alone do not guarantee sensible time values. Exact date
  grammar and environment enum behavior remain to be fully specified.
- No token content, account credentials or live response body was collected
  for this investigation. The game's own parse-error logging can include
  response JSON; any future diagnostics must avoid exposing tickets.

## Configuration is a separate post-login gate

The successful branch in JobLogin's continuation selects 0x21b4c40 with
the label `JobLogin::processPostLogin` at 0x2151c50–0x2151c5f.
0x21b4c40 constructs JobPostLogin with 0x2114810 and waits for it before
selecting `JobLogin::reportOutcome` (callback 0x21c5170).

JobPostLogin's constructor selects `JobPostLogin::retrieveConfig`, callback
0x21d7c10, at 0x21149b8. That callback calls 0x21d7a20 and waits for the
result, then selects `JobPostLogin::initiateConnection`, callback 0x218cba0.
The latter checks the configuration async object at job+0x230. Numeric
states 3/4 branch to 0x218d0ee, which emits:

`PostLogin failed while fetching the config for the following reason: '`

and then:

`'. Perform a delete session now. User shall retry to login later.`

Therefore session parsing alone is not the complete login contract. There is
a configuration result gate in this path. The configuration response schema
and its exact relation to the known `/applications/{applicationId}/configuration`
descriptor still need tracing; the string alone is not proof of that wiring.
The SDK's initiateConnection stage must not be equated with the game's 55001
auth client without establishing the subsequent handoff.

## What this changes / next work

We have a real parser, field destinations, baseline validation and a linked
post-login failure gate. We do not yet have a tested local services session
implementation, or proof of which SDK exit caused the observed empty ticket.

Next static targets are the createSession request builder/HTTP completion
path and the configuration request/response reached from 0x21d7a20. A local
integration should satisfy both contracts, then verify ticket publication
through the existing findings-066 chain and creation of the main auth client.
If runtime evidence is needed, record bounded numeric SDK outcome/HTTP
status and parser-entry/result indicators together, not ticket payloads or
another broad thread sweep. No new game capture is needed just to continue
this static trace. Login success would still precede testing world loading.
