# Version-8 starting record and persistent local creation

Date: 2026-09-27. Retail evidence:
`evidence/20260927-042155-retail-profile-n1d8p3nh/profile-private/profile-1228.jsonl`.
Seven complete target events; no end record. These are canonical bodies rebuilt
from reader objects, not original network packets. No capture is loaded by the
backend; no retail account, character, inventory IDs or session tokens imported.

## Observed creation sequence

The retail profile service received type 5: request ID 0, flags true/false.
Type 6 answered ID 0, status 0, a new 16-byte identifier. The next type-2 list
grew from one to two entries and included exactly that ID. The new entry's blob
was 161 bytes; later it was 1261. The pre-existing 1953-byte entry did not change.
The handoff metadata observation had status 2; that status is not interpreted
as successful world admission and does not establish a token response schema.

List metadata: success true, both flags false, numeric field 1800 (meaning
unknown), string `default_start_zone`. This string is also present in static
rdata at RVA 0x2e4b350; it is not an account name. New entries use the same
instance type. The existing character uses static literal `main_zone` (0x2e4b368).

## Outer field semantics and reader lineage

Verified runtime text hash remains
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.
Profile-list reader 0x2257f90 -> consumer 0x9bac0 copies each decoded entry into
a client profile object, including blob +0xe0 -> +0xe8 at 0x9bba1.
Frontend callback 0x1844e00 logs fields with static format string 0x31b0550.
Disassembly argument order establishes:

| Reader entry | Meaning |
| --- | --- |
| +0x10 / +0x14 | level / is male |
| +0x18 / +0x20 | last used / time played |
| +0x80 / +0x28 | instance name / instance type |
| +0xd8 / +0xd9 | is locked / can unlock |
| +0xda / +0xdb / +0x300 | is customized / is joinable / is survival |

The new character is level 1, male true, no instance name, time played zero,
and all five final flags false. Later it is male false, customized true, with
a nonempty instance name. Last-used is consistent with Unix seconds.

Callback calls 0x185e5e0. Customized entries take 0x185e824 -> 0x18d1b40;
the latter passes blob +0xe8 to 0xcc6800 at 0x18d1be2. Uncustomized entries
instead enter the identifier-only pending collection (0x185e861 onward).
Do not mark the initial record customized just to make it appear in that list.

## Fully consumed 161-byte layout

Reader 0xcc6800 explicitly requires version 8. Helpers 0x1a920/0x1a960 read
unsigned varints, 0x1a620 reads one-byte boolean, 0x1a780 reads float32 raw bits,
0x1a8b0 reads eight raw bytes, and 0x1a8a0/0x1a790 read four raw bytes.
The blob is mixed varint/fixed-width, not JSON and not uniformly varint encoded.

| Blob offset (decimal) | Read | Initial value |
| --- | --- | --- |
| 0 | varuint32 version | 8 |
| 1 | byte flag -> output +0x450 | true |
| 2 | varuint32 node count | 0 |
| 3 | varuint32 float count | 27 |
| 4–111 | 27 little-endian float32s -> collection +0x458 | all +0.0 |
| 112 | varuint32 pair count -> collection +0x4d8 | 0 |
| 113–144 | four fixed 64-bit words -> +0x510..+0x528 | zero |
| 145–156 | three fixed 32-bit words -> +0x530..+0x538 | 0, 1, 1 |
| 157–160 | fixed 32-bit scalar -> +0x53c | zero |

Exactly **five nonzero bytes** occur, at 0, 1, 3, 149 and 153. Field types and
boundaries are established; semantic names for most internal scalars and float
slots are not. Raw bits are preserved, including NaNs and signed zero.

Node reader 0xcc6610 uses: two uint64 bit patterns, two bytes, two uint64 bit
patterns, one 32-bit scalar, two bytes, a **fixed uint32** child count, recursive
nodes, then two uint64 bit patterns. Node identifiers/scalars remain opaque.
The codec limits blobs to 10000 bytes, collections/total nodes to 256, depth 8.

All distinct captured blobs decode completely and encode byte-for-byte:

| Bytes | Top-level nodes | Float slots | Pairs |
| --- | --- | --- | --- |
| 161 | 0 | 27 | 0 |
| 1261 | 18 | 32 | 0 |
| 1953 | 21 | 32 | 2 |

Final return at 0xcc6b58 requires both node and float collections nonempty.
The starting record is structurally decodable but is **not completed customized
data**. It is not a complete inventory, mission, position, or world save.

## Implementation and deliberate bounds

`character_record.py` synthesizes the initial record from typed defaults, with
no private data dependency. `profile_messages.py` adds full list and creation
codecs. `profile_store.py` stores a fresh UUID character ID and starting entry
under the validated local SDK account UUID, independent of ephemeral sessions.
The custom bundle uses `private/local-profiles/characters.sqlite3` (mode 0600).
SQLite transactions serialize threads/processes and commit before status 0.
The same database is shared across backend connections and persists on restart.

For now there is **one unfinished slot per account**. New requests/reconnects
reuse it; this is explicit local policy, not a claim of retail idempotency.
Only the observed true/false create mode is supported. Alternate modes, delete,
customization finalization, filtered-list requests, token handoff and world
services remain unsupported. Failures emit no speculative success/error enum.

Handlers require exact profile-service registration plus a live, issued local
auth token. Duplicate correlation is channel/opcode/request-ID scoped; create
invalidates cached list requests so the client can refresh using list ID 0.
Unknown messages remain in private transport captures. Public stages include
`profile-character-created response=0x0006`, `profile-unfinished-character-reused`,
and `profile-character-list-reply-sent response=0x0002`. They prove emission,
not game acceptance. Auth, SDK, ads, directory, TLS and game hooks are unchanged.

## Verification and next game test

Nine new tests cover byte layout, recursion, truncation, full list/create codecs,
account isolation, fresh IDs, reopen persistence, concurrent duplicate creation,
private file permissions, malformed store refusal, auth and storage failures.
Existing auth/profile/channel tests pass. The real isolated synthetic exchange
passes SDK login -> encrypted/fragmented auth -> empty list -> create -> refreshed
nonempty list, followed by duplicate and revocation checks. Tests use temporary
databases, not the production character store. No real game run of this change yet.

The retail observer was removed from the active loader location using the
verified original backup; original hash is restored and the backup retained.
Custom Steam option remains `steam-isac-mode.sh custom -- %command%`, desktop
networking on, no extra backend terminal or Enter prompt. No DLL rebuild needed.
Stop at the first stable menu/error. An unfinished character may advance to
customization or expose the next handoff request; world loading is not promised.

## Immediate-launch refusal and recovery repair

Attempts at 04:44:54 and 04:45:03 never launched the game or backend. Steam's
console reported `Cannot verify previous adapter-session lifetime; refusing
recovery`, caused by the retained 04:05 session record and ptrace-denied
namespace links for same-user systemd/KDE desktop tasks. Their readable
`/proc/PID/net/dev` showed host Ethernet/Wi-Fi interfaces, not loopback only.

Recovery now falls back to a bounded, validated interface listing with process
start-time checks. Positive non-loopback evidence excludes these tasks;
loopback-only, malformed, unreadable or PID-reused cases still refuse. No
process-name whitelist, blanket permission-error skipping or process killing.

A real smoke test also caught Linux reusing the dead namespace inode for the
new test namespace. SDK recovery therefore runs in the host view, under the
existing exclusive supervisor lock, **before** namespace allocation. The inner
check stays as a safeguard. The verified stale record was archived under
`private/sdk-session-stale-78ezrh1b/`, not deleted. The real game-free isolated
smoke test then passed with external IPv4/IPv6 still blocked. Character/backend
responses and Steam launch options are unchanged; game acceptance needs retry.
