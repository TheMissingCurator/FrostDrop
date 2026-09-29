# Targeted retail profile reference capture

Date: 2026-09-27

## Trigger

Local capture `20260927-040530-415581-sdk-adapter-linux` progressed beyond the
empty profile list to a three-byte type-5 request on profile channel 7, recorded
as `profile-unsupported-message`. It subsequently retried auth/profile setup.
This identifies a create-profile lead, not confirmed tutorial/world loading.

Static pending-state lineage: create_profile populates client+0x30 at 0x5de59,
with ID at pending+4, callback+8, flags+0x10/+0x11. The poller reads the same
state at 0xb4897 and calls writer 0x225cb10 at 0xb48cd. That writer emits type 5,
uint32 ID, then flags from writer object+5 and +4. The named
PROFILE_CLIENT_CREATE_PROFILE_RSP reader 0x2257d30 checks type 6, reads uint32 ID
and status, and only for status zero reads the 16-byte identifier at object+8.

## Four fixed observation sites

| Site RVA | Object | Meaning |
| --- | --- | --- |
| 0x225cb10 | RCX | create request before serialization |
| 0x2257db8 | RDI; reader RBX | successfully decoded create reply |
| 0x2258222 | RDI; reader RBX | successfully decoded profile-list reply |
| 0x22583a1 | RDI; reader RBX | successfully decoded profile-token reply |

The reply sites are reader success paths, not consumer acceptance checkpoints.
The reader delimiter is checked independently. Code signatures and PE metadata
must match before arming. Static evidence uses the same runtime-text hash as
finding 109. This captures decoded semantics, not original wire bytes.

For list data: vtable 0x2917998 uses count getter 0x5b950 (+8) and element-pointer
storage +0x10; the list is at decoded object+0x10. Entry layout follows reader
0x2257f90: 16-byte identifier; uint32+0x10; flag+0x14; uint64+0x18/+0x20;
strings+0x80/+0x28; flags+0xd8..+0xdb and +0x300; blob+0xe0. String vtable
0x2910bb8 uses data+0x48, bounded to a terminator before 64 bytes. Blob vtable
0x2917838 uses data+0x208 and length+0x210, as confirmed by constructor
0x2253de0 and getter 0x68bf0; reader 0x21500 accepts at most 10,000 bytes.
Unknown layouts, inaccessible storage and oversized fields mark the record
incomplete. No getters or other game functions are called by the observer.

Token handoff records are explicitly a separate metadata encoding. They omit
the token blobs and optional compound data, so must not be decoded as a full
type-8 message or claimed to establish world-session replication.

## Implementation and limits

`--retail-profile` builds a separate retail-forwarding DLL. It specializes the
existing tested type-5 VEH engine with a new pure read-callback core and fixed
four-slot site selection. Existing type-5 behavior remains separately selectable.
The Proton first-trap real-thread-handle debug-register refresh, strict ownership
checks, foreign-slot refusal, retained handles and cleanup are preserved. No
instruction bytes, game registers (except owned debug state/RF), response values,
constructors, API results or network routes are changed.

Core snapshots and queues are preallocated, never on game-thread stacks. No
file IO, allocation or game calls occur in the VEH. A worker drains at most 64
records, each bounded to 98,304 bytes. Up to eight character entries per list;
20-minute observation window, 100 ms thread sampling. Coverage is not exhaustive.
File permissions, exact launch options and restore procedure are in
`docs/retail-profile-capture.md`. Normal forwarding still runs without capture
flags; old local bridge/SDK flags are stripped by the launcher and not compiled
into this retail-only binary.

## Verification

Native tests exercise reconstructed create/list/handoff fields and malformed
pointers, oversized lists/blobs and wrong vtables. Python tests verify private
capture directories, unmodified argv/direct exec, offline-flag removal, redacted
summaries and the observation signatures against the saved runtime snapshot.
The new four-path VEH fixture passes under the installed Steam Runtime/Proton,
including a late thread, two first-trap context refreshes and clean disarm. The
existing type-5 fixture also passes under that runtime. These are synthetic
tests; the actual retail character-creation capture remains to be performed.
