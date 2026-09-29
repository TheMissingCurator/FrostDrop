# Prepared name: exact field, writes, normal producer, and missing baseline

Date: 2026-09-26

## Freeze and confirmed starting point

Server response implementations were hashed before investigation and remain
byte-identical afterward. No SDK JSON, endpoint directory, main settings,
registration acknowledgments, transport version, compression or server-first
ordering was changed. Synthetic sessions still generate new IDs/tickets as
before; "freeze" means the current response contracts, not reusing credentials.
No game file, gate result or constructor outcome is patched by this work.

Capture `evidence/20260926-233932-947969-sdk-adapter-linux` records four changed
route decisions covering 409 completed channel attempts. All have selected
port 55001/kind 0, a present transport passing its validity check, empty prepared
name, no registration, rejected channel state 2/error 1 and false/null result.
Settings eventually change waiting_settings from 1 to 0 without changing that
name failure. END reports 410 entries, 409 results, one pending pair, zero
ignored/unpaired hits; the observer retired at its stop limit. The listener
received only four heartbeat frames. These results prove pre-registration
name rejection, not rejection of a login response or proof that the persistent
registry itself was empty. The previous trace did not read that registry.

## Exact gate input and temporary lifetime

At `0x5fe3e`, RCX = preparation-frame RSP+0x50. `0x5fe43` calls the empty-string
predicate `0x14c20`; `0x5fe48` checks its returned AL. The predicate calls the
input object's vtable+0x10 getter, then compares the returned buffer's first
byte to zero. The temporary uses vtable RVA 0x2910bb8, whose +0x10 entry is
getter `0x12920` (`mov rax,[rcx+0x48]; ret`). Thus the exact gate input is:

```
temporary = preparation RSP + 0x50
buffer pointer = *(temporary + 0x48) = *(RSP + 0x98)
empty predicate reads buffer[0]
initial inline buffer = RSP + 0x58
```

`0x5fbd0..0x5fc16` creates this per-call temporary, sets its capacity to 0x40,
points +0x48 to the inline buffer and zeroes that buffer. Initialization is
client-local and deliberately empty. The subsequent selection/copy may be
skipped; the gate does not directly read a persistent SDK resource descriptor.
The temporary is cleaned up on function exit. Its heap-capable backing pointer
may change during assignment; watching only the initial buffer or an address
after return would miss pointer replacement or mistake stack reuse for history.

Two assignment sites normally replace the empty value:

- Preferred-target path: `0x5fccc` calls string assignment `0x1d7c0` with
  RCX=temporary and RDX=the chosen record name's getter result.
- Automatic-selection path: `0x5fe1c` calls the same assignment with exactly
  those destination/source roles.

`0x1d7c0` determines source length, calls the destination's resize/accessor
methods and copies bytes. Neither name pointer nor copied value should be
overridden to force a nonempty predicate.

## Persistent source field and selection lineage

Both paths read the selected service record's string object at **record+0x358**.
Its vtable RVA 0x2915588 has +0x10 getter `0x69160`, which returns
`*(string+0x30)`. Therefore its backing pointer is record+0x388 and its initial
inline buffer is record+0x360. Constructor `0x306b0` initializes this field
empty, capacity 0x28, backing pointer to inline storage. It is a different
string layout from the temporary; +0x48 must not be used for this field.

Records live in the main ProxyClient/linked owner's collection at **owner+0xb8**,
not in the endpoint-selector manager's collection at manager+0xc8. The verified
count method `0x5b9d0` reads collection+8, hence owner+0xc0. Main-owner constructor
`0x2f500` initializes that record collection empty. Endpoint selection can
create a valid owner/transport without creating any advertised service records.

Automatic path `0x5fcf3..0x5fe1c` scans that collection, uses `0x7fbd0` to match
request attributes, collects matching indices, chooses one, and copies its
record+0x358 name. An empty collection or zero matches leaves the temporary's
initial empty value untouched. Preferred selection instead uses owner+0x5d0
and +0x600 lookup structures before reading the same record field; lookup/parse
failures also leave the temporary empty. Whether this particular runtime call
takes automatic or preferred selection was not established by the old trace.

The auth caller at `0x90bef..0x90c29` builds a query containing key `type`
(static string RVA 0x291cea8) and value **`auth`** (RVA 0x2918380), then asks for
kind 0/parameter 0x1001. This is an attribute selector, **not proof that the
expected copied record name is literally `auth`**. A normal eligible record
must satisfy that query and supply its own nonempty advertised name.

## Normal producer: main-channel advertised metadata

The direct write to record+0x358 comes from consumer `0x8b590`:

```
main root application type 5
  -> dispatch 0x9a0c8 / call 0x9a0d0
  -> consumer 0x8b590
  -> parser 0x2258430: verifies delimiter 5
       reads name string with bound 0x40 via 0x217f0
       reads attributes into the adjacent parsed object via 0x65480
  -> allocate 0x3a0 record / constructor 0x306b0
  -> 0x8b6d1: assign parsed name to record+0x358
  -> 0x8b6e2: copy parsed attributes into record
  -> 0x8b70c: build auxiliary type/attribute lookups
  -> 0x8b71e: insert record into owner+0xb8
  -> 0x8b740: index it in owner+0x600
  -> later selection copies that record's name into the temporary
```

The type-5 consumer first checks existing names; a duplicate returns without
constructing a new record. Main root type 6, dispatched to `0xb2fd0`, reads a
name, removes its lookup entries, destroys that record and erases it from the
collection. Therefore the source record has an advertised lifetime and can be
replaced by remove/add, not a permanent one-time SDK configuration string.
The new trace observes assignment, not every deletion; object identifiers can
reuse allocation addresses and must not be treated as permanent server IDs.

This normal producer is **main-backend service/server advertisement metadata**.
It is distinct from SDK HTTP application configuration and from port-51000's
host/port/kind endpoint directory. Client-local initialization supplies empty
containers and string buffers, not the normal nonempty source value. Static
inspection follows the exact field and its consumer, not unrelated +0x358
members across the executable. Type 5 here means outer protocol 2056, not a
similarly numbered inner gameplay message.

The current local backend does not send type 5. That is consistent with the
failure but does not substitute for measuring this owner's registry and query
branch. No advertisement is synthesized until the name and producer contract
have appropriate evidence; the full attribute schema is not claimed decoded.

## Retail comparison: unavailable, not silently inferred

The reviewed connected startup metadata captures do not record record+0x358,
this assignment's name bytes, or a successful producer-to-temporary pair.
The known connected port-27015 baseline preserves prefaces and ECDHE-encrypted
application records, not this main-channel name's plaintext. Historical inner
world snapshots/bootstrap responses are not evidence of a protocol-2056 type-5
advertisement. No matching retail value or equality comparison is claimed.

We can establish `type=auth` from attested client code, and the normal source
from its writer. We **cannot yet establish the actual nonempty retail record
name**. The new frozen-response isolated run can establish the failing local
lineage, but cannot manufacture that missing successful-session value. Any
later retail comparison requires appropriately captured exact field/name
evidence, not guessed strings or reusing an account/ticket as a service name.

## Narrow assignment-path observer

New opt-in mode: `transport-name-lineage`. Existing modes, server contracts,
network isolation, adapter/certificate breakpoints and Steam options are unchanged.

- Slot A observes the first main-owner constructor completion (`0x2f765`), then
  the exact temporary initialization (`0x5fc1b`), automatic collection/match
  counts or preferred lookup results, the selected record, one of the two
  assignment call sites, and the existing empty-name verdict. It captures the
  channel parameter when readable; no register/result is edited.
- Slot B starts at the normal record-name assignment (`0x8b6d1`) from launch,
  pairs it with `0x8b6d6`, and verifies destination/source equality after copying.
  It requires the consumer's saved record pointer to equal RCX-0x358. This
  follows the targeted producer rather than hooking a general string function.
- Each rotating path requires matching thread and exact function-frame RSP.
  Other calls do not advance it. Interleaved calls are not exhaustive, and a
  path exiting abnormally before its final checkpoint remains pending in END.
  The first constructor observation is not a census of later owner allocations.
- All 13 sites and 8 auxiliary getter/prologue/type-reader signatures are
  attested before arming. Only two diagnostic hardware slots are used.
- Names are read only through verified layouts or the identified assignment
  source, bounded to 63 bytes plus NUL. Unreadable/unknown/truncated values are
  unknown, never fabricated as empty or saved as a partial identifier.
- Public logs contain name lengths/hashes, object IDs, counts, branch results
  and copy-equality predicates. Complete nonempty names can be retained exactly
  under `transport-private/service-names/<sha256>.bin`, with directory 0700/file
  0600, exclusive creation, no symlink following and bounded artifact checks.
  No ticket, SDK response, arbitrary memory or general message payload capture
  is added. No raw name bytes appear in the debugger log.
- Repeated identical completed temporary lineages are suppressed. END counts
  calls/results/producer writes/ignored hits/pending paths. Default bounds are
  4096 diagnostic stops, 128 events and 90 seconds checked on stops. Missing or
  pending END limits absence claims; retirement affects only diagnostic slots.

Instrumenting the identified assignment paths was selected over a fixed data
watchpoint because the temporary is reconstructed on each call and its backing
pointer may change. The producer is now located before its first potential
write, rather than beginning observation at the already-empty gate.

## Verification and next run

All 91 SDK tests passed with real GDB fixtures and isolated listener tests
enabled. A new real-debugger fixture exercises the two diagnostic slots plus
adapter/certificate hooks, five empty-registry attempts, the exact producer
assignment, then a matching temporary copy and nonempty verdict. Fixture memory
and results remain unchanged by the observer; raw name bytes are absent from
public output. Unit tests also cover preferred selection, zero matches,
unknown layouts, cross-thread/frame refusal, signature refusal, strict bounds,
private artifacts and limits. All 21 static signatures match the attested text.

Run with the unchanged Steam SDK-wrapper options and desktop networking on;
game/backend remain loopback-isolated. Wait for ready, launch, observe loading
about 30 seconds or an error, exit the game, then press Enter. No reinstall or
live-server connection is needed for this failing-lineage confirmation.

Frozen implementation SHA-256 values (identical before/after this work):

```
1705d2840ac00a2a47713b1bbea8dff61153f3712a71841a552302781cca5d6b  src/isac_backend/sdk_services.py
c0b24ec96a6bd193a1dbe7bae5b276610ba1acf5562abbd18717acdbada86313  src/isac_backend/channels.py
4548a3e108e52a5b5754413eb43195c36a281b3b2a1a735d9e78cb23a61abce3  src/isac_protocol/service_directory.py
89f19ef02e0a19a62b5e8559d6caf6c6551b402a237d326cd6ccca48a8d02095  tools/run-tctd-backend-server.py
bdd19cc4c7e1b1ddea148d0bf65f0cd4cc9e9fbefd0431046f30e237d9e8fec5  tools/run-tctd-echo-server.py
```
