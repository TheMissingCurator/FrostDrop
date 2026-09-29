# Finding 031: type-0x0003 login dispatcher path

Date: 2026-09-24

## Capture

```text
evidence/20260924-233753-bootstrap-type3-rearm-linux
```

The post-request thread refresh completed all 12 passes. Every pass armed 115
threads with zero conflicts or suspension errors. Pass 7 caught the initial
retail login response:

```text
type_id=0x0003
frame_length=835
absolute_cursor=4
local_cursor=4
reader_method_rva=0x6c0f0
```

No payload bytes were recorded.

## Reader path

The normalized call chain begins:

```text
0x6c12c -> 0x994bd -> 0x185f49e -> ...
```

RVA `0x6c0f0` is the shared reader wrapper and calls the common virtual-reader
helper at `0x9a7c0`. Its immediate caller identifies the login-specific
dispatcher at RVA `0x99490`. This is distinct from the early control dispatcher
at `0x99e00`, which explicitly handles only response types `0x0002` and
`0x0006`.

The unwind entry for `0x99490` ends at `0x994c5`, immediately after its first
virtual reader call, while its conditional branches continue through later
adjacent unwind regions. The 53-byte exact capture therefore proves the path
but does not yet include the type switch or schema call.

## Next target

The type-`0x0003` probe now captures a direct 4,096-byte forward window from
RVA `0x99490` during startup. This should include the remainder of the login
dispatcher and expose its decoder/schema targets without recording the
835-byte response body.
