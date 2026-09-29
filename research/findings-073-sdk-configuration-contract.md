# SDK configuration request, parser and consumers

Date: 2026-09-26

Static continuation of findings-072, using the same verified runtime text
SHA-256 `dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`
and ISACRD01 static-data snapshot. All addresses below are RVAs.
No new capture, external requests, injected-loader changes or backend changes.
This establishes code behavior, not that the latest failed login reached it.

## Request and completion chain

| Stage | RVA / evidence |
| --- | --- |
| JobPostLogin::retrieveConfig | 0x21d7c10 calls 0x21d7a20 at 0x21d7c3f |
| ConfigurationClient::requestConfig | 0x21d7a20; name literal at 0x21d7a4c |
| Construct/schedule JobRequestConfig | constructor 0x2115230 called at 0x21d7b86; scheduler 0x218f280 at 0x21d7b9b |
| JobRequestConfig::requestConfig | callback 0x21cc980 installed at 0x21153cf; constructor also labels request `JobRequestConfig/queryGET` |
| Select normal application configuration URL | call 0x21459d0 at 0x21ccdf0; a separate external-session branch uses 0x2145d70 |
| Build authenticated request | 0x217c4d0 at 0x21cce99; dispatch through HTTP interface at 0x21cd0a0 |
| JobRequestConfig::parseJSON | callback 0x21a2e80 selected at 0x21cd1d3; continuation registration 0x21f78e0 at 0x21cd210 |
| Read/parse response body | response at job+0xe0; 0x21712d0 then 0x2118900; parsed wrapper at job+0xf8 |
| JobRequestConfig::processRequest | callback 0x21b4fb0 selected at 0x21a3159 |
| Construct defaults, then parse configuration | 0x210a310 at 0x21b4ff2, then **0x21a4210** at 0x21b5003 |

The normal URL builder 0x21459d0 selects the `applications` resource,
calls 0x217c060, then substitutes `{applicationId}` using 0x21c02f0.
The default configuration constructor installs that resource through
0x214a370 at 0x210a64c. Its literals are:

- `https://{env}public-ubiservices.ubi.com/{version}`
- `/applications/{applicationId}/configuration`

0x217c060 looks up the resource descriptor and substitutes `{env}` and
`{version}` (including a `v` prefix in version construction). This closes
the previously unproven link between post-login and the application-config
endpoint. Concrete runtime host/version/application ID, headers and TLS
routing are not established by this static trace. GET is supported by the
job's explicit queryGET label; the generic HTTP method enum was not decoded.

The request-header helper 0x217c4d0 first requires a session object, a
nonempty ticket at session+0xb8, a deadline not earlier than its clock, and
a successful UUID-shape check of session+0x08 through 0x218f140. It then adds
`Ubi-SessionId` from session+0x08 and constructs `Authorization` with the
literal prefix `Ubi_v1 t=` followed by the ticket. Thus sessionId and usable
expiry matter downstream even though sessionId is absent from the six-field
missing-field helper in findings-072. This is static header construction,
not exposure or capture of any real ticket. The complete HTTP header set
remains unverified.

The parseJSON stage fails on a null parsed node with `Unexpected JSON object`
and error code 10 (0x21a2f81 onward). processRequest has a distinct false-result
branch labeled `Unexpected JSON object for configuration`, also code 10
(0x21b5010 onward). Successful parsing copies the configuration through
0x21261c0 at 0x21b52db and completes with an `OK` outcome.

## Configuration shape

Parser 0x21a4210 builds ten 24-byte field descriptors on its stack. Each
contains a callback, exact field name and accepted JSON type. Type 6 is
object, 5 array, 4 string, 3 number; generic descriptor type 0 accepts both
boolean node types 0/1.

| Section | Type | Callback | Further shape established here |
| --- | --- | --- | --- |
| platformConfig | object | 0x21352d0 | iterates named values into a settings map |
| resources | array | 0x2135670 | entries parsed by 0x21a49e0: name/string, url/string, version/number |
| legacyUrls | array | 0x2134a30 | name/string and url/string pairs |
| sandboxes | array | 0x2135c40 | name, friendlyName and url references; full entry semantics not finished |
| uplayServices | array | 0x2136350 | name/string and url/string pairs |
| punch | object | 0x2135450 | callback located; inner contract not decoded here |
| sdkConfig | object | 0x2135c20 | forwards to 0x21a4c20 with destination config+0xa8 |
| featuresSwitches | array | 0x2134280 | entries with name/string and value/boolean; spelling really is featuresSwitches |
| gatewayResources | array | 0x2134480 | uses resource-entry parser 0x21a49e0 |
| custom | object | 0x2133750 | callback located; inner contract not decoded here |

The resource-entry parser accepts a numeric version into entry+0xb0 and
checks for nonempty name and URL before returning true (0x21a4bd3 onward).
Do not interpret version as another string or put endpoint dictionaries
directly in place of the resources array.

### Acceptance is weaker than a complete contract

- 0x21a4390–0x21a43cc requires an object with at least one child node.
  An empty root `{}` is rejected. Child iteration/counting is corroborated
  by 0x2175720.
- The parser includes special handling for a node *named* `configuration`
  (0x21a443f), including a one-child unwrapping branch. This is not sufficient
  evidence to prescribe a wire-level `{"configuration": ...}` envelope:
  the raw response root and the name of the current JSON node are different
  things. Use the ordinary direct-section shape as the first candidate and
  verify it through the real parser before claiming compatibility.
- Shared dispatcher 0x21322b0 matches existing members by name and type,
  skipping unmatched members. It returns a matched-count comparison at
  0x2132732, but **the top-level parser ignores that result** after its call
  at 0x21a4910 and returns AL=1 at 0x21a4993.
- Thus all ten sections are not mandatory at this parser boundary. A nonempty
  but incomplete configuration can be accepted without supplying useful
  routes. This is not evidence that such a response completes login or loads
  a world. Wrongly typed fields may simply leave defaults unchanged.

## SDK settings and defaults

0x21a4c20 recognizes the following sdkConfig fields. Offsets are relative
to the complete configuration object; the callback starts at config+0xa8.

| Field | Type | Destination | Constructor default |
| --- | --- | --- | --- |
| timeoutSec | number | +0xa8, 32-bit | 30 |
| ticketTTL | number | +0xb0, sign-extended to 64-bit | 10800000 |
| lspPort | number | +0xb8, 32-bit | 0 |
| popEventsTimeoutMsec | number | +0xc0, sign-extended to 64-bit | 3000 |
| httpRetry | object | +0xc8 | maxCount 2, three following delay slots 5000 |
| websocketRetry | object | +0xe8 | same defaults |
| remoteLogs | object | +0x108 | zero-initialized 64-bit slot |
| connectionPingIntervalSec | number | +0x110, 32-bit | 30 |

Retry helper 0x21a7230 references maxCount, initialDelayMsec,
incrementFactorMsec and randomDelayMsec. Remote-log helper 0x21aa7e0
references ubiservicesLogLevel and prodLogLevel. Their full value ranges and
units beyond the literal names were not established. ticketTTL is copied
without an explicit scale operation at the parser assignment; do not assume
it takes seconds just because timeoutSec does.

`keepAliveTimeoutMin` is also recognized and checked as numeric, but its
branch at 0x21a4f57 jumps straight to cleanup without a destination write.
It is not a verified effective setting in this build.

## Applying config, feature switches and WebSocket startup

JobPostLogin's successful configuration branch applies the result with
0x21e1460 at 0x218cc1d. That function copies configuration, rebuilds derived
state through 0x21e1580, updates timeout/retry/logging consumers, and sets
ConfigurationClient+0x18 to 1 at 0x21e1547.

Feature-switch entries are stored in the config map at +0x130. 0x21e1580
iterates 30 recognized names using 0x217d740, then sets or clears their bits
for present boolean entries (0x21e17f2–0x21e1801). Recognized names include
Connection, HttpClient, WebSocketClient, Event, ExtendSession, News and
Everything. Missing entries do not execute either bit update in that loop;
omission is not a demonstrated way to disable services.

The connection-request function starting at 0x218c1b0 checks the applied-config
flag and a mask containing bit 29 plus bit 1 (0x218c219–0x218c22a).
Its rejected branch explicitly logs that the Connection feature/service is
shut down and skips the request. The name mapper's Connection and Everything
cases are at 0x217d767 and 0x217d847. This establishes SDK request gating,
not a firewall or coverage of every game's networking path.

PostLogin constructs a child through 0x2113f30 at 0x218ce34. That constructor
names it **JobInitWebsocket::initiateConnection** and installs 0x218c050.
PostLogin schedules it at 0x218ce5d, stores its handles and builds its own
OK outcome starting at 0x218ce94; it does not wait for the WebSocket result
in that immediate success branch. The WebSocket job itself waits and has
reportOutcome callback 0x21c4d30. Its later effects on game readiness remain
to be traced; do not declare WebSocket success mandatory for the immediate
PostLogin completion or equate this socket with the game's 55001 channel.

## Implementation consequences and remaining boundary

We can now draft a typed local configuration response and test this parser
contract. We must not return `{}` or treat a successful parse as isolation.
The constructor already installs Ubisoft application/session endpoint
defaults. Missing/ignored resource entries can retain those destinations.
The first configuration request also necessarily precedes receipt of the
local configuration: its initial routing must be handled independently.

The next implementation boundary is the SDK HTTP transport: route both
session creation and this configuration GET locally, with tested JSON shapes,
consistent local identifiers, and an independent fail-closed network boundary.
Use explicit local routes for supported resources and deliberate behavior for
unsupported services; do not forward unknown requests to Ubisoft. The trace
alone does not settle request headers, TLS handling, or the full resource set.

A useful integration success sequence is: local session response parsed;
local config response parsed and applied; services ticket published; game
auth client created; local main-backend connection. The existing handoff
probe covers the latter steps, but the last capture does not establish the
first two. World loading remains a separate milestone after those steps.

## Rechecking the static evidence

The existing analyzer verifies the runtime-text hash while locating literals:

```sh
python3 tools/analyze-startup-static.py \
  private/startup-leads-jcoCPbG7/static-rdata.bin \
  --text private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin \
  --contains JobRequestConfig --contains ConfigurationClient --contains /configuration
```

Disassemble the listed anchors with objdump using `-D -b binary
-m i386:x86-64 --adjust-vma=0x1000` on that runtime-text file. Literal
references and direct edges above were checked against instructions; this
was not a live parser execution or a backend integration test.
