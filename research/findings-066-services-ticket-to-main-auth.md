# Services ticket handoff to main-backend authentication

Date: 2026-09-26

## Result and limits

The saved code and static data now connect the services-login worker, its
ticket-ready event, frontend ticket storage, game authentication request, and
kind-0 main-transport selection. These are verified static paths, not evidence
that every stage executed in the latest run.

Capture `20260926-021727-offline-startup-leads-linux` still records only
27015/303, 51000/1572 and 55002/556 constructors. The latency exchange finishes
all three pings and its summary. There are no selector count/result events or
55001 connections. `STARTUP_STATIC_CAPTURED` confirms the complete 22,203,530
byte section was saved; another section capture is unnecessary.

The strongest next investigation is the services-to-game-auth handoff and its
gates. Changing a 55001 response cannot resolve a connection that was never
observed. However, the absence of selector events does not by itself distinguish
missing tickets from an earlier frontend gate or a manager state other than 2.

## Inputs and reproduction

Static section:
`private/startup-leads-jcoCPbG7/static-rdata.bin` (`ISACRD01`, RVA 0x2901000,
length 0x152cc8a, total file size 22,203,546).

Runtime text SHA-256:
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

All addresses below are module-relative RVAs for that build. Static vtable
entries use preferred image base 0x140000000; remove that base before comparing
with the RVA disassembly. Do not treat the preferred base as a live address.

Example read-only disassembly:

```sh
objdump -D -b binary -m i386:x86-64 --adjust-vma=0x1000 \
  --start-address=0x18588f0 --stop-address=0x18589dd \
  private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin
```

String-reference searches use `tools/analyze-startup-static.py`. Its LEA matches
are candidates only; the sites cited here were checked with disassembly.
Inline switch tables were read as little-endian data, not instructions.
No live service requests or credential/payload captures were made.

## Static handoff

```text
services login worker: 0xf1910
  -> SDK Facade::createSession: 0x215dfa0
     -> AuthenticationClient::login with PlayerCredentials: 0x215d560
  -> ticket-ready producer: 0xf1660
     -> services event receiver: 0x1814a50 / 0x18588f0
        -> services object +0x228
           -> frontend synchronization: 0x185d6a0
              -> game-auth object +0xf50
                 -> auth dispatcher: 0x18ce810, state 0
                    -> ticket-login starter: 0x185cad0
                       -> auth_client.login_with_ubiticket: 0x7f430
                          -> auth polling: 0xe2680 / 0x8ff70
                             -> channel setup: 0x5c290
                                -> selector kind 0: 0x9c3e0
                                   -> main constructor: 0x2f500
```

The worker's successful-result producer and the frontend receiver have matching
event layouts; their asynchronous dispatch machinery is not a direct call from
one function to the other. This diagram is a static data/control-flow summary,
not a runtime event sequence from the current capture.

## 1. Services worker and result

The vtable at 0x292ad68 contains worker start 0xf1910, poll 0xf17d0, failed
handler 0xf1740 and result producer 0xf1660. The adjacent source literal names
`ubiservicesloginworker.cpp`.

At 0xf1cac the worker converts credentials from +0x58 through 0xe13e0. At
0xf1cda it calls 0x215dfa0, which references `Facade::createSession` and, on its
non-short-circuit path, calls 0x215d560 at 0x215e1bb. The latter references
`AuthenticationClient::login with PlayerCredentials`. There are existing-session,
in-progress and credential-mismatch short circuits; a call to the facade is
not necessarily a new network request.

Poll 0xf17d0 examines the asynchronous object via worker+0x40:

- 0x218eed0 tests whether handle+8 -> object+0x68 equals 1.
- In that branch, 0x217c800 computes a numeric value over a related collection;
  values above 1 cause a cancellation call and worker return 3. Otherwise the
  worker returns 2.
- In the other branch, 0xe1490 processes the result and 0x218a490 tests the
  asynchronous object's +0x68 against 2. The worker returns 4 if equal, 3 if not.

These numeric fields should be recorded as-is until runtime correlation. Do not
assign the collection value an HTTP-status meaning.

At 0xf1660, 0x5f690 constructs an event with subtype 0. Its constructor 0x32d20
stores the subtype at event+8. Helpers 0xf0980, 0xf09d0 and 0xf0a60 fill event
fields +0xc0, +0x8d8 and +0x918. The populated event is dispatched through
0xd6c40. The static services-event name list begins with `UbiservicesTicketReady`.
The failed handler is a different path and logs
`ubiservicesloginworker.on_failed.01`.

## 2. Event receiver and ticket storage

The `RClient_NF_Ubiservices` vtable at 0x3191958 has event handling at slot +0x40
pointing to 0x1814a50. That routine extracts an event payload via the wrapper's
vtable+0x10, then switches on payload+8. Subtypes 0, 11 and 13 route to
0x1814a9a; these align with the static name list's TicketReady, SessionValid and
TicketExtended entries.

The receiver admits this branch for services state values 5, 7 and 9 at
services-object+0x220, then calls 0x18588f0. That routine first applies 0x3f540
to services+0x330 and event+0x10. Only if this gate succeeds does it copy:

| Event field | Services-object destination |
| --- | --- |
| +0xc0 | +0x228 (ticket passed onward) |
| +0x8d8 | +0x280 |
| +0x918 | +0x2d8 |

The latter two string fields have not been given identity semantics here.
Following the call, 0x1814ad5 sets services state 7 with reason `Login Success`.
That state change alone does not prove the copy gate succeeded: 0x18588f0 can
return without copying.

## 3. Synchronization into game-auth state

Frontend synchronization begins at 0x185d6a0. In the traced portion,
frontend+0x60 is the services object and frontend+0x68 is the auth object.

Unless frontend byte +0x29aa suppresses this block, it tests services+0x330
through 0x790d0 and then whether services+0x228 is nonempty. When admitted,
0x185db84..0x185dba9 compare/copy that string into auth+0xf50 and set auth+0xfa8
when changed. Otherwise 0x185dbb2..0x185dbd4 clear the auth ticket, clear auth
byte +0x10 and set auth state +0x1124 to 4.

0x790d0 is a nonempty-string predicate, not independently a proof of successful
authentication. The exact semantic role of services+0x330 remains unassigned.

At the end, the services object's slot +0x10 is called. Unless frontend byte
+0x29a8 is set, 0x185dc78 then calls the game-auth dispatcher 0x18ce810.
These suppression flags have not been measured in this capture.

## 4. Game-auth state machine

Dispatcher 0x18ce810 reads auth+0x1124 and uses the inline table at 0x18ce85c:

| Numeric state | Function | Verified behavior |
| --- | --- | --- |
| 0 | 0x185cad0 | Start ticket login, then set state 1 |
| 1 | 0x185f460 | Poll the auth client and check a timeout |
| 2 | 0x185af40 | Start another auth operation through 0xce590, then state 3 |
| 3 | 0x185f290 | Poll that operation; may move to state 4 |
| 4 | 0x1856370 | Release auth client and evaluate restart conditions |
| 5 | 0x1854b40 | Separate branch; not assigned a semantic name |
| 6 | 0x185cd10 | Start an alternate operation using auth+0x1130, then state 7 |
| 7 | 0x185f5f0 | Poll that operation and check a timeout |

State 0 asserts `myAuthClient == NULL` and
`myUbiservicesTicketBase64.GetLength() > 0`. At 0x185cca5 it calls 0x7f430,
passing the ticket from +0xf50. The callee references
`auth_client.login_with_ubiticket.01`, creates a pending request via 0x2c130,
and stores it at auth-client+0x28. The frontend stores the auth-client pointer
at auth+0x1128 and writes state 1 at 0x185cccb.

State 4's restart logic requires more than a ticket. It tests auth+0xea0 for
nonempty content and several flags, including +0x10, +0xfa8 and +0x1120. These
conditions can restore state 0 or select state 6. Therefore copying a fabricated
ticket alone is not a verified fix.

## 5. Auth channel reaches main selector

Polling 0xe2680 invokes 0x8ff70. Its reconnect section begins at 0x90b86:
when auth-client+8 is null and its timer gate passes, it obtains the string in
pending-ticket-request+0x9d0, builds a parameter with key `type` and value `auth`,
then calls 0x5c290 at 0x90c29 with EDX=0 and R9D=0x1001.

0x5c290 reads the backend manager's state at +0x38. Only numeric state 2 takes
the branch calling 0x9c3e0 at 0x5c350. The selector kind comes from EDX, so this
auth path requests kind 0. State 1 takes a separate route; other values return
without this selector call.

0x9c3e0 filters candidate+0x5c against that requested kind. It can reuse an
existing connection or construct a new one at 0x9c58f by calling 0x2f500, using
the candidate port at +0x58. As established in findings 064, that constructor
uses transport protocol 2056. Whether the candidate selected in a retail run
is our local 55001 entry still needs runtime observation.

The backend manager's +0x38 state is not the auth-client's +0x38 pending-request
pointer: they are different objects.

## Services versus launcher ticket; CDN separation

`src/uplay_local/local.c` supplies a fixed local launcher ticket. This is not an
implementation of the later SDK session exchange. No public-services session
or configuration responder was found in the current source/tools search.

Static SDK URL constructors separately contain
`https://{env}public-ubiservices.ubi.com/{version}`, `/profiles/sessions` and
`/applications/{applicationId}/configuration`. These templates locate useful
request families but are not captured request URLs or decoded response schemas.
The precise SDK failure and whether configuration is a mandatory prerequisite
have not been established.

The other discovered static URLs cover news-feed images, silver shields, store
tiles and a trial purchase image on `static2.cdn.ubi.com`/`static2.ubi.com`.
Resolver failures on those hosts do not establish a game-auth dependency.
Custom news/images can be handled as a separate local-content feature later.

## Next runtime question, if a new probe is requested

Measure the whole handoff in one bounded observation pass, rather than repeatedly
capturing DNS or changing backend replies:

- Services worker result: asynchronous numeric state and completion/failure,
  without credential strings or ticket bytes.
- Frontend handoff: presence/nonempty predicates, numeric services/auth states,
  auth-client/pending-request presence, and the two frontend suppression flags.
- Auth channel setup: requested selector kind and manager state before the
  state-2 branch; retain an observation that confirms selection/constructor.

Any implementation must respect the four hardware slots (DR0 currently reserved),
validate this build's signatures and object layouts, bound reads/logging, and
avoid calling game methods from breakpoint handlers. State transitions should
be deduplicated to keep per-frame observations from exhausting the record cap.
This note does not install such a probe, redirect new services, alter login
states, or claim that a local services response is already implementable.

## Verification of this trace

A read-only local check passed for the static section header/size, the runtime
text SHA-256, and 28 anchors covering eight direct calls, all eight auth-dispatch
entries and jump targets, the three services-event routes, five vtable entries
and four identifying literals. Instruction boundaries and surrounding gates
were inspected with objdump. No executable code changed, so this was not a
backend regression-test or game-login validation run.
