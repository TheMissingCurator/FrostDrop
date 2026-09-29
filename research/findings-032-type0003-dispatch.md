# Finding 032: type-0x0003 decoder dispatch

Date: 2026-09-25

## Capture

```text
evidence/20260925-000214-type3-dispatcher-window-linux
```

The capture reached the main menu and observed the retail login response once:

```text
type_id=0x0003
frame_length=835
absolute_cursor=4
local_cursor=4
reader_method_rva=0x6c0f0
```

All 12 post-request thread-refresh passes completed without an unarmed thread,
breakpoint conflict, or probe error. No response payload bytes were recorded.

## Dispatcher

The direct forward window from RVA `0x99490` contains the complete message-type
switch. After reading a 16-bit type at `0x994d1`, the dispatcher subtracts one,
bounds the result to `0..10`, and indexes an 11-entry jump table at `0x99580`.
Only the odd wire IDs have dedicated handlers:

| Type | Case RVA | Handler RVA |
| ---: | ---: | ---: |
| `0x0001` | `0x994eb` | `0xae7e0` |
| `0x0003` | `0x994fa` | `0xb8160` |
| `0x0005` | `0x99509` | `0xb8c00` |
| `0x0007` | `0x99518` | `0x8c750` |
| `0x0009` | `0x99527` | `0x8c440` |
| `0x000b` | `0x99536` | `0xb31a0` |

Unsupported IDs take the reader's virtual method at vtable offset `0x28`.
After a supported handler returns, the dispatcher reads the next envelope and
continues until no record remains.

## Next target

RVA `0xb8160` is the first unambiguous type-`0x0003`-specific decoder entry.
The focused type-`0x0003` mode now captures a direct 4,096-byte forward window
from both `0x99490` and `0xb8160`. The next main-menu capture should expose the
generated schema reader or the immediate field-reading helpers called by that
decoder, while leaving the 835-byte response body disabled.
