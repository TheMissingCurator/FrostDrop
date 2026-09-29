# Native request bridge: typed URL assignment and request ABI

Date: 2026-09-26. Implementation/static follow-up to
[findings-090](findings-090-sdk-http-adapter-core.md).

## Result

Implemented the **request-side** native ABI helpers in
`src/uplay_probe/sdk_http_native_request.{h,c}`: describe/format, clone,
rebuild URL and delete an owned request. These call explicitly supplied
Windows x64 function pointers with the observed object sizes and argument
ordering. A fixture wires these helpers into the existing adapter core.

They are not linked into the live probe. There is no live address resolver,
installer, native sender, failed-result factory or original-service teardown
binding in this change. Test callees are synthetic functions using the Windows
x64 calling convention; **no retail code was executed by the tests**.

New static findings remove two uncertainties:

- **0x2127390 is full typed URL assignment**, not a constructor. It uses native
  SDK string assignment on all eight components and copies the numeric port.
- Native **DELETE is method ID 4**, not our portable enum value. GET/POST/DELETE
  request tables, clone functions and deleting-destructor convention are mapped.

## Native request operations

| Method | Native ID | Vtable RVA | Deleting destructor | Method getter | Clone |
| --- | --- | --- | --- | --- | --- |
| GET | 0 | 0x346d738 | 0x212ff80 | 0x217a5e0 | 0x2153e30 |
| POST | 1 | 0x346d750 | 0x212ffe0 | 0x217a5f0 | 0x2153e70 |
| DELETE | 4 | 0x346d720 | 0x212fe60 | 0x217a5d0 | 0x2153df0 |

Each table has destructor/method/clone at offsets 0/8/16. Clone takes the
request in RCX and returns a pointer in RAX. These clone functions allocate
0x350 bytes and tail-call their respective copy constructors. DELETE clone
tail-calls **0x210f970 at 0x2153e20**; GET/POST use 0x21100a0/0x2110250.
DELETE's deleting destructor calls request cleanup 0x21207c0 at 0x212fe6f,
then frees when EDX bit 0 is set. The bridge passes flag **1**.

Dispatcher 0x21dbad0's method branch maps 0/1/2/3/4 to GET/POST/PUT/HEAD/DELETE
using literals at 0x3473ffc, 0x343e604, 0x3474000, 0x3474004 and 0x346d5bc.
The bridge supports only the three classes above; it does not assume that a
different request subclass is safe because it has similarly numbered slots.

Before virtual calls, a supplied bounded reader checks request vtable identity
against the approved class set and compares all three entries with the supplied
expected functions. Method values must match the class record for description,
cloning and URL replacement. Unknown tables, changed entries and unreadable
metadata fail closed. Deletion checks the approved table/entries but does not
call the method getter just to release an owned object.

This validates shape against a supplied capability table, not live code
integrity. Supplying verified addresses, pinning valid object lifetimes,
verifying code/build identity and providing a safe memory reader remain the
future native integration's responsibilities. The bridge does not discover
arbitrary function pointers and execute them.

## URL construction and assignment

| Operation | RVA | Register arguments |
| --- | --- | --- |
| UTF-8/NUL-terminated string construction | 0x211abe0 | RCX=fresh 0x58-byte wrapper, RDX=text |
| String destruction | 0x3c160 | RCX=initialized wrapper |
| URL parsing/construction | 0x211b490 | RCX=fresh 0x2c8-byte URL, RDX=SDK string |
| URL formatting/construction | 0x217db90 | RCX=URL, RDX=fresh output SDK string |
| **URL assignment** | **0x2127390** | RCX=initialized destination URL, RDX=source URL |
| URL destruction | 0x21240f0 | RCX=initialized URL |

Assignment calls SDK string assignment 0x2124910 at 0x21273a0, 0x21273b0,
0x21273c6, 0x21273dc, 0x21273fe, 0x2127414, 0x212742a and 0x2127440.
Offsets are 0, 0x58, 0xb0, 0x108, 0x168, 0x1c0, 0x218 and 0x270.
Instructions **0x21273f2/0x21273f8** copy the 32-bit port at +0x160.
A concrete caller **0x21e2c20** uses it on an already-existing URL value.
This refines findings-089: a full native assignment routine has now been found.

The bridge's replacement sequence is:

1. Verify the owned request class/method and require an already-canonical,
   supported local URL using the core's existing policy. A production URL is
   not accepted as replacement input; mapping must happen first in the core.
2. Construct a temporary SDK string, then parse a fresh SDK URL.
3. Format that temporary back to a fresh SDK string and require exact agreement
   with the intended local URL. Failure leaves the clone unchanged.
4. Assign into **clone+0x08** using 0x2127390.
5. Destroy all initialized temporary URL/string values.

There is no copying of owning URL bytes, constructor-over-initialized-storage
operation, raw port/string mutation, saved descriptor address or protected
image edit. The borrowed caller request is not modified.

All normal-return rejection paths release constructed temporaries. This C
bridge **does not catch native C++ exceptions or allocation faults**. Constructors
do not return a success bool; inventing a NULL/error convention would be wrong.
Exception/unwind and allocation-failure behavior still need an integration
decision before live enablement. Round-trip validation proves the binding
received the intended formatted value only when these calls return normally.

## Bounded formatted-string extraction

Formatter use at **0x21dbd0a**, followed by **0x21dbd8f onward**, establishes:

```text
referent = wrapper[0]
vbtable = *(referent + 0x10)
displacement = signed32(vbtable + 4)
narrow_storage = referent + 0x10 + displacement
length = uint64(narrow_storage + 0x10)
capacity = uint64(narrow_storage + 0x18)
characters = capacity >= 16 ? *(narrow_storage) : narrow_storage
```

The bridge applies checked address arithmetic, bounded reads, length <= capacity,
the 4096-byte policy limit, sufficient output capacity, a terminator at length,
and no embedded NUL. It copies before releasing the SDK wrapper. Read failures
leave the caller's output/length unchanged. This is a build-specific observed
layout, not a portable claim about every SDK or MSVC string implementation.

The adapter's describe callback now receives **per-dispatch scratch storage**.
Native formatting can therefore destroy its temporary wrapper before returning
without giving the core a dangling pointer or relying on a shared context buffer.
Existing mock binding/tests were updated to this contract.

## Failed async result: trace advanced, binding deliberately absent

Follow-up: [findings-092](findings-092-sdk-native-failure-result.md) adds the
failure-result binding and its static construction/ownership evidence. The
following describes the state at the end of this request-bridge investigation.

Dispatcher output copying **0x2104af0** constructs a three-qword wrapper:
vtable +0, retained state +8, retained result +0x10. It is not a single pointer
that can be zeroed to report a blocked route.

Completion helper **0x21e3640** obtains synchronization state through
wrapper+8 -> state+0xe0 and calls **0x21e3720** unless state+0x68 is already 4.
The latter copies error code at error+0, SDK message at error+8, and a numeric
field at error+0x64; updates state+0x68, clears dependency-related state and
releases an owned reference. Code zero selects state 2; nonzero generally
selects 3, with 0xfffd/0xfffe selecting 4.

These observed fields are not a sufficient complete construction contract.
Standalone HTTP-result initialization, the correct policy-rejection error code,
notification/lifetime semantics and destruction have not all been traced.
No fake failed future, raw state writes or call to this helper with an invented
structure was implemented. This is the next native binding target, alongside
the send/redirect contract.

## Tests and reproducible evidence

Added `tests/sdk_http_native_request_smoke.c` and Python runner. Fixtures cover
Windows x64 calls on the host, request URL offset, virtual call flags, explicit
method translation, unknown/changed vtable rejection, clone failure/alias,
SSO/heap string extraction, bounded/unreadable inputs, URL round-trip mismatch,
temporary cleanup, preserved caller/payload state, and integration of native
request helpers with the portable adapter. Sender/failure/context callbacks
remain mocks. The mock URL parser is not a retail-parser emulator.

Passed:

```sh
python3 -m unittest discover -s tests -p 'test_sdk_http*.py' -v
ISAC_ADAPTER_SANITIZE=1 python3 -m unittest discover -s tests -p 'test_sdk_http*.py' -v
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -Werror -pedantic -fsyntax-only \
  src/uplay_probe/sdk_http_adapter.c src/uplay_probe/sdk_http_native_request.c \
  tests/sdk_http_adapter_smoke.c tests/sdk_http_native_request_smoke.c
python3 tools/verify-sdk-http-request-abi.py
```

Address/undefined-behavior/leak checks required an approved run outside the
tracing sandbox, as before. MinGW validation is compile-time, not a Wine run.
The new read-only verifier checks the exact runtime-text SHA-256, static-data
header, request tables, method stubs, assignment calls/port copy, clone edges
and string-layout anchors. It prints a capability reference, not an executable
live binding table, and performs no writes/network/game calls.

Live installation remains disabled. No new game capture, launch options, DLL
build/install, backend change or world-loading claim accompanies this change.
