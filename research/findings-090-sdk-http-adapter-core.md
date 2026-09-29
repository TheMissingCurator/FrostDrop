# SDK HTTP adapter core: implemented, not installed

Date: 2026-09-26. Implementation follow-up to
[findings-089](findings-089-sdk-http-routing-installation-contract.md).

## Status

Added a portable C routing/ownership core in
`src/uplay_probe/sdk_http_adapter.c` and its public contract in
`src/uplay_probe/sdk_http_adapter.h`. It is exercised with mock SDK bindings.
It is **not** linked into the probe DLL, published into a game object, or
installed in the game directory. No constructor hooks, instruction patches,
memory-protection changes, backend changes or launch-option changes were made.

This is the adapter's testable foundation, not a working retail SDK adapter.
The callback signatures and method enum are our own interface, **not the
retail ABI**. Do not cast this allocation to the game's HTTP interface.

## Implemented behavior

```text
borrowed request
  -> describe URL/method
  -> exact origin + method/path allowlist
       rejected -> failed-result callback (no send)
       accepted -> owned clone -> rebuild clone URL -> local send callback
                                                  -> destroy temporary clone
```

Only these canonical origins are accepted:

- `https://public-ubiservices.ubi.com`, with optional explicit `:443`.
- `http://127.0.0.1:55003` (already-local requests are idempotent).

The destination is always `http://127.0.0.1:55003`. Host case variants,
alternate loopback spellings, credentials/user-info, alternate ports,
development/certification hosts and hostname lookalikes are conservatively
rejected. There is no production fallback or DNS resolution in the core.
This intentionally supports fewer URL spellings than a general URL parser.

Routes match the existing `src/isac_backend/sdk_services.py` handler:

| Method | Path |
| --- | --- |
| POST / DELETE | `/v[0-9]{1,3}/profiles/sessions` |
| GET | `/v[0-9]{1,3}/applications/[A-Za-z0-9-]{1,64}/configuration` |

Path escapes, dot segments, semicolon parameters and unsupported resources
do not match. Queries are preserved byte-for-byte, including well-formed
percent escapes; they are not interpreted as redirect destinations. Fragments,
literal controls/whitespace, backslashes, non-ASCII bytes, embedded NULs and
malformed percent escapes are rejected. URL input is bounded to 4096 bytes.
The module performs no logging of URLs, tickets, bodies, headers or pointers.

The adapter validates a route **before** cloning or dispatching. It never
edits the caller's request. The binding clones the original subtype and
preserves method, headers, body and flags; only the owned clone's URL is
replaced. The send callback must retain/copy everything it needs before
returning, after which the core destroys its temporary clone. Failed
description, cloning, rebuilding or sending invokes the failure callback,
not a success placeholder or external fallback. A clone callback that returns
the caller's pointer is rejected without destroying that borrowed pointer.

The binding is copied by value; its context transfers to the adapter only
after successful creation. Adapter destruction releases the context once.
There is no descriptor pointer, first-request cache or global singleton:
new requests after resource replacement are checked by the same policy.
Independent service epochs can create independent adapters.

Dispatch has no mutable core state, but callback thread safety is the
binding's responsibility. The owner must quiesce active calls before
destruction. This is an explicit lifecycle precondition, **not** an implemented
thread-suspension/publication mechanism or proof of SDK shutdown safety.

## Native binding work still required

Follow-up [findings-091](findings-091-sdk-native-request-bridge.md) implements
the request-side helpers below and changes describe to use per-dispatch scratch.
It does not supply native sending/failure results or live installation. The
list below records this report's original implementation boundary.

Each callback has a documented contract in the header. None has a retail
implementation in this change:

1. **describe**: correctly extract/format the SDK typed URL and translate the
   method. The semantic DELETE enum is not a claim about its native method ID.
2. **clone / destroy_request**: preserve subtype and SDK reference/allocation
   semantics, using the verified request virtual operations.
3. **replace_url**: parse into fresh SDK-owned storage and replace the old
   value without leaking or double-releasing it. Failure must leave the clone
   destructible; exception-safe native replacement remains unverified.
4. **send_local**: preserve native options/output and async lifetime. Prove
   loopback-only transport, including HTTP redirect behavior. Simply calling
   the original dispatcher does not establish this contract. The token-gate
   change documented in findings-089 also needs an explicit integration choice.
5. **fail**: construct a normal failed SDK async result. A NULL pointer is not
   a substitute for the missing native failure-result implementation.
6. **release_context / native interface wrapper**: forward original service
   cleanup and implement the exact native deleting-destructor/allocation ABI.
7. **installation**: attach only at a verified pre-publication point after
   state binding; validate build/slot/permissions and SDK epoch. No polling
   installer or guessed early-enough initialization was added.

The core's allowlist prevents its own forwarding callback from being invoked
for an unsupported request. It cannot by itself enforce the future callback's
network behavior or isolate launcher/game sockets outside this HTTP path.
No retail login, configuration replacement, world loading, redirects or live
teardown has been validated by these mock tests.

## Validation

`tests/sdk_http_adapter_smoke.c`, run by `tests/test_sdk_http_adapter.py`, covers:

- Supported methods/routes, exact-origin matching, local idempotence and query
  preservation; credential/hostname/port confusion and malformed URL rejection.
- URL/output length boundaries, 64/65-character application-ID boundary, plus
  10,000 deterministic malformed-input cases.
- Unchanged caller request and preserved body/header/subtype/flags in the
  mock transport; options identity, independent queued copy and clone cleanup.
- All callback failure stages, invalid arguments, aliased clone rejection,
  failed construction ownership and independent adapter instances.
- Mock newly materialized requests after descriptor changes: both supported
  local/production values and an unexpected external destination.

Passed:

```sh
python3 -m unittest discover -s tests -p test_sdk_http_adapter.py -v
ISAC_ADAPTER_SANITIZE=1 python3 -m unittest discover -s tests -p test_sdk_http_adapter.py -v
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -pedantic -fsyntax-only \
  src/uplay_probe/sdk_http_adapter.c tests/sdk_http_adapter_smoke.c
python3 -m unittest discover -s tests -p test_sdk_services.py -v
```

The sanitizer run passed address/undefined-behavior/leak checking after an
approved run outside the tracing sandbox (LeakSanitizer cannot run under its
ptrace environment). All seven existing SDK service tests passed outside the
socket-restricted sandbox using temporary loopback listeners. MinGW checking
is compile-time only: it is not Wine/Proton or retail ABI validation.

No game capture is requested by this change. Existing launch behavior and the
older protection guard are unchanged.
