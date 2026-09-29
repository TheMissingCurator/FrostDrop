# Finding 033: type-0x0003 generated schema boundary

Date: 2026-09-25

## Capture

```text
evidence/20260925-000808-type3-decoder-window-linux
```

The focused capture reached the main menu, observed one 835-byte type-`0x0003`
response, and recovered the requested 4,096-byte forward window from RVA
`0xb8160`. The probe reported no errors or capacity limits. The response body
remained disabled.

## Decoder structure

RVA `0xb8160` is an application-level login-response handler rather than the
generated field reader itself. It has two principal paths:

- When the session object's member at offset `0x28` is null, it constructs and
  publishes the required account/session state, then returns false so a later
  response can be processed against that state.
- With that state present, it initializes a large temporary response object at
  stack offset `rbp+0x50` and calls RVA `0x22551b0`, passing the temporary
  object and the message reader. A false return follows the error/reporting
  path; a true return consumes the decoded object and updates live state.

The decisive call is:

```text
0xb84de  initialize temporary response object via 0x27490
0xb84e7  load temporary object as argument 1
0xb84eb  load message reader as argument 2
0xb84ee  call 0x22551b0
0xb84f3  test decoder result
```

This shape matches the generated schema readers already recovered for control
types `0x0002` and `0x0006`: destination object in `rcx`, reader/envelope in
`rdx`, and a Boolean success result in `al`.

## Next target

The focused type-`0x0003` mode now captures a direct 4,096-byte forward window
from RVA `0x22551b0` in addition to the dispatcher and application handler.
That window should reveal the ordered field readers, object offsets, expected
wire tags, and any nested-schema calls needed to begin expressing the login
response schema.
