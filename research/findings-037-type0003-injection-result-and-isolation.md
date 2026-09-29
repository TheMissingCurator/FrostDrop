# Finding 037: type-0x0003 injection succeeded; retail acceptance was ambiguous

Date: 2026-09-25

## Capture

```text
evidence/20260925-003402-type3-injection-first-linux
```

The first mutation run reached the game and completed without a probe error.
The bridge selected the outbound channel-0 type-`0x0002` request, received the
local 23-byte type-`0x0003` frame, verified reader 1, appended all 23 bytes,
and notified the reader:

```text
LOCAL_BRIDGE_RX ... length=23 ... first_type=0x0003
LOCAL_BRIDGE_INJECTION_READER_READY ... reader-id=1
LOCAL_BRIDGE_INJECTED ... length=23,appended=23,status=notified
```

This proves the recovered lock/append/notify/unlock injection boundary. It
does not prove client acceptance. The genuine 837-byte type-`0x0003` delivery
on reader 1 followed 188 milliseconds later. A second channel-1 type-`0x0002`
request and matching reader-2 type-`0x0003` reply occurred about ten seconds
later. Either retail response could have supplied the state needed to advance.

## Causal isolation mode

`ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1` now provides the next bounded experiment.
It requires bridge and injection mode. Only after a successful local append,
it recognizes a complete standalone type-`0x0003` by framing metadata and
suppresses its transport-delivery call on login readers 1 and 2. It verifies
the recovered caller return RVA `0x00982a0` before emulating the void return.
Setup deliveries, other types, other readers, and ordinary bridge runs are
unchanged.

The result is intentionally diagnostic. Successful progression proves the
local type-`0x0003` is causally sufficient at this boundary. Failure means the
minimal zero-valued profile is insufficient or reader 2 needs its own local
reply; the suppression log and subsequent request chronology determine which
experiment follows.
