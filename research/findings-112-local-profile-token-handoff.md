# Local character-selection token handoff

Date: 2026-09-27. Builds on findings 110/111; no new retail capture required.

## Confirmed local progression and immediate blocker

`evidence/20260927-045052-691532-sdk-adapter-linux` contains one transport with
15 inner requests. Profile channel 7 received an issued local auth token,
requested an empty list, sent type 5, received type 6, requested a refreshed
list, and then sent **type 7 with a 17-byte body**. Decoding the private root
streams shows ID 0 followed by the same 16-byte character identifier returned
by creation and listed by the server. The unsupported type-7 request, not the
absence of a tutorial flag, is the first confirmed post-creation blocker.
The subsequent channel closes do not prove anything about world readiness.

## Static wire schema and status meaning

Verified text hash:
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.
Writer 0x225ccf0 emits delimiter 7, uint32 varint request ID, and raw identifier
storage via 0x223f200. It does not prefix a length/reference-table selector.
The local experiment supports precisely 16 raw bytes, corroborated by capture.

Reader 0x2258240 checks delimiter 8 and consumes these fields in order:

| Object field | Wire representation |
| --- | --- |
| +0 | uint32 varint request ID |
| +4 | uint32 varint status |
| +0x4f8 timed blob | uint64 varint byte length, bytes (maximum 32768), uint64 remaining lifetime |
| +8 | bounded string, length <64, instance type |
| +0x60 | bounded string, length <64, instance name |
| +0xb8 | boolean; if true, identity via 0x64b50 and another timed blob at +0xd0 |
| +0x920 | boolean; if true, uint32 +0x924, timed blob +0x928, identifier +0xd50, compound via 0x65260 at +0xd60 |

Timed-blob reader 0x64cb0 adds the received remaining lifetime to the client
clock and stores deadline at timed object+0x420. It is not a wire epoch timestamp.
The normal two-false optional branch consumes no optional compound data.
Other branches are deliberately refused by the narrow local codec.

Consumer 0x9ccda matches the response ID against client+0x40 pending request+4.
At 0x9ccf6 status 1 selects the locked-profile path (string 0x2926e38), status
2 selects the **success** path (string `get profile token success`, 0x2926f88),
and sets callback result 4 at 0x9d3ca. This establishes the previously unknown
meaning of retail status 2; creation's status 0 is a different enum and must
not be reused here. Callback dispatch is at 0x9d5cf.

Frontend callback 0x1845190, result-4 branch 0x184534d, copies the timed token,
deadline and strings into persistent frontend state; it also copies optional
session fields and transitions its internal state to 14 at 0x18454f9. Its
instance-type handling at 0x1845499 calls 0x1678190, with empty-instance fallback
at 0x18454b8. This is a client handoff, not an implemented game server.

Retail `20260927-042155-retail-profile-n1d8p3nh` has one token-handoff metadata
record: ID 0, status 2, strings `default_start_zone`/empty, both optional flags
false. Those are metadata only; opaque token bytes/length/lifetime were not
captured and must not be claimed reconstructed. No retail bearer is replayed.

## Implemented bounded experiment

`profile_messages.py` now has raw-ID type-7 and normal-success type-8 codecs.
`ProfileSession` requires an exact advertised profile-client binding, a valid
issued local auth token, and a stored character owned by that SDK account.
Only the known normal unfinished character is admitted: default start zone,
empty instance name, not locked/customized/survival. It receives status 2,
two false optional flags, and a freshly random printable `isac-character-`
bearer. Its encoding and size are **local choices**, not a recovered retail
token format; actual client acceptance is still untested.

Lifetime is bounded to **900 seconds** and the earlier of SDK session expiry
and the issued parent auth-token deadline. This 900-second cap is local policy,
not an interpretation of profile-list metadata 1800. A fingerprint-indexed,
per-transport in-memory registry binds bearer -> account, character, expiry,
parent auth token. Resolution revalidates SDK revocation and character ownership.
It survives profile-channel close, not transport/server restart. Renewal retires
the previous bearer for that account/character. Capacity is bounded at 32;
existing opcode/channel/request-ID duplicate protection and 128-attempt cap stay.

No token is written to the character database, sent to retail services, logged
publicly or granted to foreign/unknown IDs. Private encrypted-transport root
captures necessarily retain the reply for analysis. Unknown optional/session
shapes and failures receive no invented ACK or success/error packet.

Auth response contents, stored character state, ads, SDK routes, TLS admission,
DLLs/hooks and network isolation are unchanged. No world/group handler is added.
The local resolver is available for a future handler; it is not claimed to
implement that handler now. Public inner-message logs additionally include a
catalog-whitelisted service category (unknown names redacted), to identify the
next actual world/group requests without dumping IDs or payloads.

## Verification and next run

Nine new tests cover exact golden bytes, truncation and bounds, optional-branch
refusal, correlation, ownership, unknown/foreign IDs, storage failures, expired
parent/character sessions, SDK revocation, renewal and channel/transport scope.
The isolated synthetic TLS/compression exchange now runs local SDK/auth ->
list -> creation -> refreshed list -> fragmented character selection/type-8
reply, with duplicate, unknown-character, redaction and post-revocation refusal
checks. Existing character, profile and auth tests pass. Production character
data is not modified by tests.

Use the unchanged custom Steam option with desktop networking on, no rebuild,
no installation and no separate server. The previous run's local character is
retained. **Update (finding 113):** the next run instead requested type-3
cleanup of an unfinished profile before selection. That cleanup is now handled
with recoverable archival and type-4 acknowledgement; another creation may
therefore precede selection. Expected
marker: `service=profile_client ... stage=profile-character-token-reply-sent
response=0x0008`. This proves emission only. Stop at the first stable menu/error
and inspect the next client requests; neither tutorial nor world loading is
guaranteed. The previous run's game/Ubisoft processes had exited at handoff.
