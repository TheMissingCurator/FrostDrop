# Finding 019: outbound bootstrap request paths

Date: 2026-09-23

Evidence: `evidence/20260923-233432-outbound-control-path-linux`

## Result

The code-only outbound bootstrap probe captured four target envelopes without
probe errors or capacity limits:

| Type | Channel | Envelope length | Producer family |
| --- | ---: | ---: | --- |
| `0x0002` | `0x00` | 3328 | startup/main-thread transport |
| `0x0005` | `0x0a` | 448 | startup/main-thread transport |
| `0x0002` | `0x09` | 52 | outbound queue-submit |
| `0x0005` | `0x09` | 262 | outbound queue-submit |

The probe captured 27 complete executable functions. Both startup envelopes
share the same twelve-frame final-send path, and both channel-`0x09` envelopes
share the same fifteen-frame path. The latter contains the previously
identified outbound queue-submit function at RVA `0x00d3920`; all four end at
the serialized-writer boundary in function RVA `0x00d6b65`.

This proves that the final writer hook is downstream of request-specific
serialization: its stack distinguishes transport/queue families but not the
`0x0002` and `0x0005` schemas. The captured path is still useful for placing a
tighter producer hook, but unwinding it further will not by itself reveal the
response correlation field.

## Next validation

The response codecs established that inbound `0x0002` and `0x0006` begin with
a request ID encoded as an unsigned varint. The next probe therefore derives
only the first unsigned varint following the type ID for outbound `0x0002` and
`0x0005`, and for inbound `0x0002` and `0x0006`. It records the numeric value
and encoded width as `CONTROL_CORRELATION`, while continuing to redact all
source bytes and remaining fields.

Matching values for the `0x0002` request/response and `0x0005`/`0x0006` pair
will be sufficient to implement correlation-ID extraction in the local
bootstrap state machine without decoding authentication-bearing payloads.

## Correlation result

Evidence: `evidence/20260923-234007-control-correlation-linux`

The bootstrap channel-`0x0a` type-`0x0005` request carried leading unsigned
varint zero. The type-`0x0006` response arrived 489 milliseconds later and
also carried request ID zero. This validates the leading request correlation
field for that bootstrap exchange. A later channel-`0x09` type-`0x0005`
carried value 224 and belongs to the world-session path, proving that the
channel must be included in the selector.

The initial outbound type-`0x0002` leading value was 3305, while subsequent
inbound type-`0x0002` values were 955632, 955642, 955652, and later increasing
values. They do not correlate. Those inbound messages also recur roughly
every ten seconds, so type `0x0002` must not be treated generically as a
request/response pair solely because its numeric type matches in both
directions.

`BootstrapStateMachine` now restricts the control transition to channel
`0x0a`, decodes the leading request varint, and replaces the configured
type-`0x0006` template's request ID dynamically.
