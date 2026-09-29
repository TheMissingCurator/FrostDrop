# Full frontend handoff record output

Date: 2026-09-26

Capture `20260926-153459-offline-login-handoff-sweep-on-linux` confirms the
zero-debug-register resume path works in the game: frontend checkpoint
exceptions continue execution, local certificate/directory/latency exchanges
complete, and the services poll records an async object present in numeric
state 1. No main-backend 55001 connection is recorded.

Frontend state records are missing for a separate output bug. Their detail
buffer is 768 bytes, but `log_status` used a 384-byte complete-line buffer.
Even single-digit values produce about 386 bytes including the observed event,
time, process and thread envelope. The logger discarded oversized records;
the producer had already updated its deduplication cache. No ticket-presence
conclusion can be drawn from those missing records, and the omitted values
cannot be recovered from that capture's stack log.

The complete-line buffer is now 1024 bytes, enough for this producer's full
767-byte detail plus envelope. Formatting/size failures emit a fixed
`STACK_PROBE_LOG_ERROR` marker rather than a partial record or silent omission.
The handoff analyzer warns on this marker. The change does not alter checkpoint
locations, resume behavior, deduplication, sweep mode, backend replies or routing.

The native Wine test writes two actual frontend records to a file, including
signed 32-bit extrema, unknown predicates and maximum byte flags. It verifies
the full line through the trailing manager-state field, CRLF termination and
deduplication. A 767-byte detail must survive intact; an oversized detail must
produce the error marker without partial output. The test runner then feeds
the emitted file into the normal analyzer and verifies both frontend records
and their trailing fields. This supplements the earlier in-memory state tests,
which did not detect the dropped output.

192 Python tests, the native Wine log round-trip suite, shell syntax checks and
the full-loader transport smoke test passed. Installed loader matches tested
build SHA-256 `0b2b019b17f146b0e4c3438c9570a662fd584100a4fd79ecf90cd15a8ba5287d`.
The original loader backup is retained.

Use the unchanged sweep-on capture command and Steam option, with networking
off. One loading attempt is enough. The next capture should supply the missing
frontend services/auth states and ticket predicates; this logging repair does
not itself implement login or world loading.
