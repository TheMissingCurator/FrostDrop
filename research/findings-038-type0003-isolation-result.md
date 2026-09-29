# Finding 038: the minimal type-0x0003 lacks account/login semantics

Date: 2026-09-25

## Capture

```text
evidence/20260925-004821-type3-retail-isolation-linux
```

The local 23-byte type-`0x0003` frame was appended and notified successfully.
The probe then suppressed the complete 837-byte retail type-`0x0003` replies
on readers 1 and 2. The game entered an account-login loading loop and
eventually returned to the outer Start/Exit menu.

The user selected Start again about 63 seconds after the initial request. That
produced another 3,328-byte type-`0x0002` request on channel 2 and a complete
retail type-`0x0003` reply on reader 3. Reader 3 was intentionally outside the
bounded isolation scope, so the reply was delivered. Only after that event did
the client create the remaining bootstrap channels and restore the user's
normal account session.

## Conclusion

Framing, reader selection, append, notification, and selective retail
suppression are all proven. The zero-valued type-`0x0003` is structurally
decodable but does not establish the required account/session state. The next
unknown is field semantics rather than another transport boundary.

## Next probe

`ISAC_LOCAL_BACKEND_CAPTURE_TYPE3=1` is a separately gated, observe-only mode.
It captures one complete reader-1 retail login frame to
`project-isac-type0003-private.bin`, which the normal evidence collector does
not copy. Logs retain only lengths and types. The private inspector reports
field lengths, flags, integers, and hashes without displaying byte values and
can explicitly create a mode-`0600` replay profile. Two independent summaries
will distinguish stable identity/profile values from likely expiring session
material.
