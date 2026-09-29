# 092 — SDK native completed HTTP failure result

## Outcome and scope

Implemented `src/uplay_probe/sdk_http_native_result.{h,c}`. It uses explicitly
supplied, verified SDK capabilities to construct an HTTP future, complete it
through the native synchronized error path, verify terminal failure and copy
the owned result to fresh caller storage. It neither queues an HTTP request nor
returns a null/pending placeholder. No game binaries or live memory were changed;
the module is not linked into or installed by the game probe.

This is the failure half of the native adapter, not a successful local HTTP
response implementation. Native sending, redirect enforcement, original-service
teardown and safe pre-first-request installation remain outstanding. No new
capture or launch-option change is needed to validate this isolated work.

## Static evidence

RVAs below refer only to runtime text SHA-256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`
and the matching `private/startup-leads-jcoCPbG7/static-rdata.bin` snapshot.
These are static observations, not proof of execution in the latest game run.

The missing-resource branch of `RemoteLogger::sendClientLog` (`0x21d9bd0`)
provides a concrete **completed failure without a queued HTTP job**:

- `0x21d9c72` constructs a 0x130-byte state through `0x2111e60`.
- `0x21d9ccb` initializes the value inside a 0x98-byte shared HTTP response
  through `0x2110e20`. Its outer vtable is `0x3475c50`.
- It builds the error message “Remote logs resource not present in configuration”
  (`0x346e560`), code `0x0f01` (`0x21d9d80`) and detail `-1` (`0x21d9e0b`).
- Under the state lock it copies the error and transitions to failure, cleans
  dependency state and unlocks. It destroys the temporary error message.
- `0x21d9f44` calls the normal future copy constructor `0x2104af0`, then
  releases temporary response/state references. No job is queued in this branch.

The reusable operations match these allocations and ownership semantics:

| Operation | RVA | Relevant contract |
| --- | --- | --- |
| Construct HTTP future | `0x2104ba0` | Fresh 0x18-byte output, SDK string label; allocates state and response |
| Construct state | `0x2111e60` | Vtable `0x346c388`, owned label/message, lock at +0xe0, dependency sentinel |
| Initialize HTTP response value | `0x2110e20` | Called for the shared response's +0x10 value |
| Complete with error | `0x21e3640` | Future pointer and error pointer; locks before state transition |
| Internal transition | `0x21e3720` | Copies error, sets terminal state, cleans dependencies; not called directly by adapter |
| Copy future | `0x2104af0` | Fresh destination; retains both state and response; no allocation |
| Destroy future | `0x212d970` | Releases both references; flag bit 1 also frees wrapper storage |

The reusable constructor installs base future vtable `0x346d030`. The logger's
temporary uses `0x346d648`, but its copied output uses the same base vtable as
the reusable constructor and normal HTTP-dispatch output. No vtable is manually
replaced by this binding. The normal HTTP dispatcher also constructs the same
state/response types at `0x21dbe46`/`0x21dbe9f` and copies output at `0x21dc34b`.

The output is three qwords: vtable +0, owned state +8, owned response +0x10.
The error layout consumed by completion is code +0, native SDK string +8,
numeric detail +0x64 (0x68 bytes including padding/reserved fields).
State contains status +0x68, error code +0x78, SDK message +0x80, detail +0xdc
and lock +0xe0. Code zero yields state 2; ordinary nonzero errors yield state 3;
`0xfffd`/`0xfffe` yield state 4. This binding requires state 3.

## Binding contract and lifetime

1. Construct a native label, then a private native future; destroy the label.
2. Check expected future/state/response vtables, positive owned-reference counts,
   a lock pointer and initial state 0 using the supplied checked reader.
3. Construct an SDK error message with a fixed, redacted adapter diagnostic.
4. Invoke synchronized native completion. Verify state 3, code `0x0f01`, detail
   `-1`. Destroy the temporary error message.
5. Copy into fresh caller output only after successful verification. This retains
   both objects before releasing the private future with destructor flags **0**.
   The caller then owns a normal SDK future and its subsequent destruction.

`0x0f01` is a deliberate local resource-unavailable classification based on the
observed early-failure path, not a discovered official SDK enum name or a Win32/
HTTP status. The game's higher-level UI/retry response to this choice is not yet
tested. Completion here means the returned future is terminal; it does not
guarantee that application-level retry logic will stop or that world loading works.

`isac_sdk_http_failure` returns 1 only after publishing that result. On a checked
normal-return failure it returns 0 without touching caller output, after temporary
cleanup. The core failure callback now returns this success indicator; dispatch
returns `ISAC_HTTP_RESULT_FAILED` if it cannot build the result. A future native
boundary must stop on this condition, not return uninitialized storage to the game
or fall back to external networking. No live boundary is implemented here.

Function pointers/vtables must be verified against the loaded build, and the SDK
must remain alive for these calls. These checks are not a defense against calling
arbitrary/untrusted constructor pointers. The binding does **not** catch native
C++ exceptions or allocation faults. Fixture missing-object cases model normal
returns only and are not evidence that retail out-of-memory paths are safe.

## Verification

Added `tests/sdk_http_native_result_smoke.c` and its Python runner. Synthetic
Windows-x64 ABI callees exercise every adapter error reason, rejection of invalid
reasons and capabilities, terminal-state checks, output canaries, retained-copy
lifetime, temporary cleanup, bad/unreadable objects, incorrect completion fields,
and integration of the real failure binding with portable route rejection.
That integration also verifies that rejected requests never clone or send, and
that result-construction failure propagates as `ISAC_HTTP_RESULT_FAILED`.

Passed all three adapter suites normally and with address/undefined-behavior/leak
sanitizers (the sanitizer run required approval outside the ptrace-restricted
sandbox). Windows MinGW syntax/type checks passed for all three modules/fixtures.
The fixtures do not execute retail SDK locks, allocators or completion callbacks.

```sh
python3 -m unittest discover -s tests -p 'test_sdk_http*.py' -v
ISAC_ADAPTER_SANITIZE=1 python3 -m unittest discover -s tests -p 'test_sdk_http*.py' -v
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -pedantic -fsyntax-only \
  src/uplay_probe/sdk_http_adapter.c src/uplay_probe/sdk_http_native_request.c \
  src/uplay_probe/sdk_http_native_result.c tests/sdk_http_adapter_smoke.c \
  tests/sdk_http_native_request_smoke.c tests/sdk_http_native_result_smoke.c
python3 tools/verify-sdk-http-request-abi.py
```

The read-only snapshot verifier now checks future vtable entries and observed
construction, completion, copy and destruction instruction edges in addition to
the request bridge. Its whole-text hash gate and snapshot checks passed. It is
not a live resolver, signature scanner or installer, and its RVAs must not be
blindly used with another game build.
