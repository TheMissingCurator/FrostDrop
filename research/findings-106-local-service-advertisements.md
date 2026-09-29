# Retail producer evidence and local type-5 startup catalog

Date: 2026-09-27

## Successful retail observation

Capture: `evidence/20260927-031319-retail-type5-beb7dyfu/`, corrected observer
hash `cebbd0d0769ff8c7fd85b8593f2b22d20d2c074ee5bb068ae195bba6a209abe1`.
The user confirms the game ran. Actual game stream `type5-1192.jsonl` reports
400 hits, 152 records, zero pending observations/resume failures and 16 verified
debug-context refreshes. Coverage reached 158 threads with one unspecified
thread-coverage failure. Observation ends at the gate-record budget; this is
not an exhaustive session census. The launcher PID stream has no fields.

24 advertisements have complete captured fields, successful parser/consumer
results, observed record assignment and equal copied names. The same owner
registry grows from 0 to 24. All wire attribute counts are two: ordered keys
`type`, then `process_guid`. The separate parsed-collection count getter was
unavailable (`-1`); do not claim it independently confirmed these counts.
Names/process GUIDs are distinct 35-byte strings in 8-4-4-16 hex layout, with
24 distinct values in each set and each name different from its process GUID.
Exact retail values remain in the private capture, not the source catalog.

120 initial gate observations are empty with registry count zero. After the
advertisements, eight observed gates are nonempty with registry count 24.
Their bytes match previously copied advertised names: auth, push_message,
profile_cache_front, profile_client (two instances), user_logs (three checks).
Byte equality on the same observed owner supports the producer-to-gate chain;
the limited observer does not prove every selection branch or lifetime.

This supplies the missing successful-session comparison from findings-100.
The ordinary nonempty producer is the main-backend advertisement consumer,
not a hardcoded service type name or SDK HTTP configuration value.

## Implementation

User explicitly authorized local responses after the successful comparison.
`service_advertisement.py` encodes/decodes outer application type 5: bounded
length-prefixed name, unsigned attribute count (at most 24), then ordered
length-prefixed key/value byte pairs. Name/key lengths are below 64, values
below 512. The outer transport owns delimiter 5; it is not repeated in the body.
The codec preserves duplicate keys, embedded NULs and empty fields. The local
catalog itself emits nonempty ASCII identifiers/types with no NULs.

`isac_backend/services.py` mirrors the captured 24 service-type instances and
order, deriving stable local UUID-based service/process identifiers. These
are local logical service identities, not retail identifiers or OS processes.
IDs remain stable across reconnects to this experimental catalog. There is no
runtime dependence on private capture files, retail servers or account data.

`run-tctd-backend-server.py --channel-setup --service-advertisements` sends:
protocol version -> existing settings -> 24 advertisements, through the
existing compression/TLS path, before waiting for client requests. This is a
candidate local startup ordering, not a claim to have captured retail wire
ordering relative to version/settings. The custom launcher bundle opts in;
omitting the new flag retains the old response behavior. The flag is refused
without main-2056 channel setup. Private server-root capture includes the new
frames; public logs contain a count and an explicit unconfirmed-acceptance tag.

No client gate/hooks, SDK HTTP responses, endpoint directory, certificate
handling, channel acknowledgement semantics or inner application responses
were changed. The four previously frozen SDK/channel/directory/echo source
hashes still match findings-105. The main server response freeze is lifted
only for this requested advertisement addition.

## Verification and next test

- Four codec/catalog tests: independent literal wire vector, all bounds,
  malformed/truncated frames, duplicate/NUL preservation, catalog uniqueness
  and multiplicity, one-byte-at-a-time transport decoding.
- Ten unchanged main-channel/latency tests pass.
- Six backend tests pass, including real TLS/compression startup delivery,
  exact private outbound capture, registration acknowledgement/heartbeats,
  and the old no-advertisement control behavior. A synthetic client uses a
  local auth instance ID; that does not prove retail registration-field roles.
- Nine adapter-transport tests pass with isolated integration enabled: the
  actual listener bundle delivers all 24 records in a fresh private network,
  continues registration/heartbeats, and shuts down its listeners.

Next real test uses the existing isolated custom mode/name-lineage trace, not
the online retail probe. The registration gate must become nonempty normally,
followed by an actual channel registration request. This change alone does
not implement auth, profile or world services. Inner requests are still
captured without speculative replies. See `docs/sdk-adapter-test.md`.

Preparation completed with approval: the on-disk loader was restored to the
verified original hash `df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8`.
The backup and working retail-observer build are retained; no prefix/login
data was reset. Eleven existing name-lineage tests also pass. Real custom-mode
acceptance of the local advertisements remains pending.
