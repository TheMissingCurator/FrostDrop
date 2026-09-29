# Profile-client list request and empty-list experiment

Date: 2026-09-27

## Evidence and distinction from the auth reply

Latest local capture: `evidence/20260927-034501-825797-sdk-adapter-linux`.
Decoded both `backend-0002-{client,server}-root.bin` privately. The only inner
server reply is auth type 3. The client subsequently declares that reply's
first token at root type 8 and sends the identical token in seven service
connect messages. Two registrations are explicitly named `profile_client`,
on channels 3 and 7, and target advertised local profile-client IDs.

Both profile channels send inner type 0 with a 244-byte body, then type 1
with a two-byte body. The new decoders consume these fully:

- type 0: 240-byte token, remaining lifetime 8640 and 8626 respectively;
- type 1: request ID 0, filter count 0 on each channel.

The second type-1 field is a collection count, not a boolean. The two channels
are separate registrations; their repeated request IDs are not global IDs.
The auth channel closes before all service setup has completed. Service-token
ownership must therefore survive auth-channel close within the same transport.

Retail comparisons: `private/type0003-retail-profile.json` and finding 039
provide auth shape, not character data. Capture
`20260924-231459-bridge-reader-correlation-fixed-linux` observes post-auth
retail replies but lacks reliable service-name bindings and full payloads for
these replies. Reader 2/7 type-2 records must not be asserted to be profile
lists solely by allocation order or size. The recent retail type-5 capture
establishes service advertisements/gate inputs, not the profile-list payload.

## Static producer, reader and consumer

All RVAs refer to the saved runtime text SHA-256
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.
Static strings come from `private/startup-leads-jcoCPbG7/static-rdata.bin`.
LEA candidates were checked with x86-64 disassembly, not treated as a call graph.

- `0x92580` selects the literal `profile_client`. At `0x925ed` its connection
  path calls `0x225cae0`, which writes delimiter 0 and invokes `0xe0200`.
  That helper writes a bounded byte string (capacity 0x8000), computes remaining
  lifetime from object+0x420, and writes uint64. There is no request ID here.
- `profile_client.get_profile_list` at `0x6d9f0` builds pending state at
  client+0x28: +4 request ID, +8 callback, +0x10 filter collection.
  The send path at `0xb4995` loads that request ID and copies the collection,
  then calls writer `0x225cc50` at `0xb49fa`.
- Writer `0x225cc50` writes delimiter 1, uint32 request ID, uint32 collection
  count, then identifiers via `0x223f4d0`. The implementation intentionally
  refuses nonempty filters until their reference-table context is supported.
- Named assertion `PROFILE_CLIENT_GET_PROFILE_LIST_RSP` at static RVA
  `0x348ccc0` belongs to reader `0x2257f90`; the reader checks delimiter 2.
- Consumer `0x9b72b` calls this reader. At `0x9ba5d` it matches the decoded
  request ID against pending+4. At `0x9ba8c` it branches on success. Zero
  entries reaches callback dispatch at `0x9bd02` without entering the profile
  conversion loop. This supports an empty-list experiment, not proof that the
  frontend will reach its menu or accept the chosen metadata values.

### Reply header and list layout

| Decoded object offset | Wire field | Evidence |
| --- | --- | --- |
| +0 | uint32 request ID | call `0x2257fc4`; consumer comparison |
| +4 | success flag | call `0x2257fdd`; consumer branch |
| +0x128, +0x129 | two flags, semantics unknown | calls `0x2257ff0`, `0x2258003` |
| +8 | uint32, semantics unknown | call `0x2258013` |
| +0x130 | length-prefixed byte string, length <64 | `0x225802c` -> `0x217f0` |
| temporary count / +0x10 collection | uint32 profile count and entries | `0x2258045`, loop `0x2258070` |

The nonempty entry loop has additional identifier, integer, string, flag and
blob fields; no character record is synthesized or replayed in this change.
The wire header order differs from object-offset order. Integer readers are
the established unsigned-varint helpers, not fixed-width integers.

## Implemented scope

`--experimental-profiles` requires `--experimental-auth`; the existing isolated
custom service bundle enables both. Auth reply generation and all SDK,
certificate, directory, settings and advertisement responses are unchanged.
No game DLL, executable, memory, constructor or registration gate is modified.

Only exact `(profile_client, advertised local profile-client target)` bindings
are handled. Inner type 0 validates the actual issued token against per-transport
auth state, its server-side expiry, and the still-valid SDK session. Other
auth reply tokens and tokens from another transport are refused. No inner
connect acknowledgement is invented. Inner type 1 must follow an authenticated
connect; its unfiltered request receives type 2 on that channel with its ID.

Experimental response choices are **success=true, other flags=false, numeric
metadata=0, string empty, zero characters**. These are explicit test values,
not recovered retail metadata. This is not persistence, profile creation,
inventory, entitlement, or world-session implementation. Other services remain
observe-only; empty lists may still leave the game waiting on those services.

Duplicates are suppressed per channel/request ID; close clears profile-channel
state. Total profile attempts are bounded at 128 per transport. Token records
are bounded by the existing eight auth-attempt limit and die with the transport.
Logs report stages and sizes, not tokens, account IDs or payload contents.

## Verification and next run

- Six profile tests and six auth tests pass: exact bytes, truncation, bounds,
  nonempty-filter refusal, wrong bindings, forged/expired/revoked tokens,
  auth-channel close, connection scope, duplicate/conflict handling and limits.
- Six backend-server tests and nine adapter-transport tests pass outside the
  socket-restricted sandbox. The latter includes an actual isolated synthetic
  SDK -> TLS/compression -> auth -> profile-list exchange, fragmented input,
  request-ID correlation, duplicate suppression and revoked-session refusal.
- Both real captured local profile requests decode fully. No live game run
  has tested the new response yet; synthetic tests do not prove game acceptance.

Use the same custom Steam launch option with desktop networking on. No rebuild
or installation is needed. Expected public marker:
`stage=profile-empty-list-reply-sent response=0x0002`.
That proves emission only. Next evidence must establish what the client does
afterward and which remaining services it requires; do not call it world-ready.
