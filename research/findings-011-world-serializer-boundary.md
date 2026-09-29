# Finding 011: world serializer boundary and outbound envelope

Date: 2026-09-22

Evidence: `evidence/20260922-161345-serialized-weapon-swaps-linux`

## Serializer boundary

The observed world-send stack reaches function RVA `0x00d6a80`. This function
builds a large local writer, appends the linked outbound queue records, and
passes the completed writer to a transport object's virtual method. The call
instruction is at RVA `0x00d6bbf`.

The writer layout is supported directly by the captured field-writing code:

- offset `0x4090` is the current byte-buffer pointer;
- offset `0x4098` is the used byte count; and
- offset `0x409c` is the buffer capacity.

A hardware execution breakpoint at `0x00d6bbf` can therefore copy the
serialized bytes before the private transport layer receives them. The first
controlled run captured 512 records totaling 35,156 bytes, with no signature,
metadata, or readable-window errors. The 512-record bound was reached about
23 seconds after the inbound world gate activated.

## Outer record envelope

All 512 records matched the same structural envelope:

1. one-byte marker, observed as `0x03`;
2. one-byte channel;
3. an unsigned base-128 variable-length body size; and
4. one or more nested frames, each prefixed by a ZigZag-encoded byte length.

The decoded body and nested-frame sizes exactly account for every captured
record. This is application serialization rather than TLS ciphertext. Each
nested payload begins with another unsigned variable-length value, but its
protocol meaning is not yet established.

`tools/analyze-plaintext-probe.py --families` summarizes these fields without
printing payload contents. `--timeline` adds elapsed time for action
correlation.

## Initial action correlation

The user walked first and then performed approximately twenty weapon-switch
inputs. A 70-byte nested-frame family with leading value `0x0f` appeared at
roughly 10 Hz only during the early two-second walking interval, making it a
strong movement-state candidate.

After walking stopped, channel-zero records with the following nested shapes
repeated at the weapon-change cadence:

- 52-byte frame with leading value `0x11`;
- 55-byte frame with leading value `0x11`; and
- larger frames with leading value `0x88` and slot-dependent sizes.

The subsequent stationary run shows a 55-byte frame first, a larger
equipment-state frame, and then one or two 52-byte frames for each accepted
change. The larger frame rotated through stable 314-, 110-, and 382-byte
forms, strongly indicating three equipped-slot states. The current evidence
does not yet assign a human-readable slot name to each form.

A later high-volume switching run captured twelve outbound type `0x0088`
frames. Each aligned with local `0x0088` dispatch at the same millisecond and
with additional `0x0088` dispatch approximately 88--137 milliseconds later.
This provides a strong request/replication-response correlation, although the
world dispatcher may also process locally submitted objects and therefore is
not by itself a direction oracle.

The outbound queue-submit object's slot-three method resolved to one shared
wrapper at RVA `0x223d520`, not the constant type getter used by inbound
message classes. The payload's nested leading value remains the useful
outbound type identifier. The unused breakpoint was consequently repurposed
temporarily to test the candidate inbound buffer handler at RVA `0x2016850`.

That candidate is now rejected. In capture
`20260922-210842-inbound-buffer-candidate-linux`, all 429 outbound records
decoded as the known application envelope, while none of the 512 inbound
candidate records did. Each inbound candidate began with a valid TLS
application-data record header (`17 03 03` and a two-byte length), and some
buffers concatenated multiple such records. RVA `0x2016850` is therefore an
encrypted TLS-record accumulator before decryption rather than the inbound
application-plaintext boundary. Its payload capture has been disabled.

The next probe records only the world dispatcher's direct return RVA, paired
with the already decoded message type. This should identify the parser or
deserializer caller after TLS processing without collecting another buffer.

Capture `20260922-211957-dispatch-caller-linux` recorded 90 unique type/return
pairs without dispatch errors or limits. Four direct return sites appeared:

- RVA `0x186040e` handled 70 observed message types, including `0x0012` and
  `0x0088`;
- RVA `0x0fc3f1e` handled 12 types, including `0x000f`, `0x0011`, and
  `0x0088`;
- RVA `0x162cd4e` handled seven types; and
- RVA `0x0c140af` appeared only for type `0x0048`.

The two `0x0088` caller sites separate the local and remote paths. Each of the
eleven outbound `0x0088` envelopes aligned within one millisecond with a world
dispatch; the first such dispatch identified return RVA `0x0fc3f1e`. A second
pair of `0x0088` dispatches followed 66--154 milliseconds later, with the first
observed response identifying return RVA `0x186040e`. Thus `0x0fc3f1e` is the
local submission/echo path, while `0x186040e` is the strongest inbound
server-response candidate and the primary next target.

The on-disk executable cannot supply these bytes because its active code is
packed into a runtime-only image. The follow-up probe therefore captures one
bounded executable-code window around each unique return RVA; it still does
not read message or stack payload data.

Capture `20260922-212649-dispatch-caller-code-linux` obtained runtime windows
for the three relevant recurring callers without errors or limits. The primary
inbound candidate is a complete function at RVA `0x18602b0`. Its `RDX`
argument is a pointer/count pair for a vector of message-object pointers. The
function iterates those objects, invokes virtual predicates, performs a small
per-object-ID deduplication check, and calls the world dispatcher at RVA
`0x1860409`. This places it after message construction/deserialization.

The next probe breaks at the entry to `0x18602b0`, records only its direct
return RVA, and captures the caller's bounded executable-code window. That
continues upstream toward the function that populates the deserialized-message
batch without inspecting the vector or its objects.

Capture `20260922-213330-inbound-batch-caller-linux` found a single direct
caller at return RVA `0x18144ab`. Its containing function begins at RVA
`0x1814360` and is a timed queue consumer rather than a deserializer. The
object's `+0x18` member points to an array descriptor; each 24-byte array entry
contains the message-vector descriptor consumed by `0x18602b0` plus a
32-bit delivery timestamp at entry offset `+0x10`. The function dispatches all
due entries and then removes the consumed prefix through RVA `0x188fd70`.

Following `0x1814360`'s caller will identify the owning update/session routine.
That context is needed before instrumenting the queue's producer side, since
the direct path seen here only consumes and removes entries.

The next revision broadens the search instead of continuing one caller at a
time. On the first scheduler hit it converts the fourth execution breakpoint
into a four-byte hardware write watchpoint on the live queue-count field and
records it on that scheduler thread. For every unique writer it
records the writer RVA, a bounded set of game-image return-address candidates
from the interrupted stack, and bounded executable-code windows. This should
capture both the known consumer and the unknown enqueue/producer path without
reading the queue entries themselves.

The first wide capture, `20260922-215122-inbound-queue-writers-linux`, reached
the main menu and produced usable evidence before Division terminated. The
local watch caught the known consumer write at instruction RVA `0x188feca`
(post-instruction RIP `0x188fece`), with immediate return RVA `0x18144cd` and
ten additional bounded stack candidates. Fifty-three milliseconds later the
experimental helper reported that it had propagated the watch to 122 threads;
no subsequent game events were logged. The global propagation is therefore
the leading crash cause and has been removed. The revised probe keeps the
watch local to threads that actually execute the scheduler.

Capture `20260922-215805-inbound-queue-writers-local-linux` remained stable
through world traversal, combat, looting, and a side mission. Eighty-eight of
its 90 unique queue-write signatures came from the known consumer/removal path
at post-instruction RVAs `0x188febe` or `0x188fece`. The two exceptions were
`0x0f843c7` and `0x0f843e2`. Their runtime code window shows a producer that
increments the descriptor count, allocates or selects a 24-byte slot, stores a
delivery timestamp at slot `+0x10`, and moves a two-qword message-vector
descriptor into the slot. One producer hit was followed in the same
millisecond by inbound types `0x0012`, `0x0023`, `0x006c`, `0x000f`, and
`0x014d`, confirming that it queues a decoded message batch.

The next revision reuses the rejected TLS-candidate breakpoint for the rare
producer-only branch at RVA `0x0f843b6`. On a hit it records the branch type,
queue count/capacity, exact containing function range, and caller RVAs derived
with `RtlVirtualUnwind`. It captures the bounded runtime function body once.
The local count watch remains active independently on scheduler threads.

Capture `20260922-221944-inbound-queue-producer-unwind-linux` resolved the
producer's exact runtime function as RVA range `0x0f84280`–`0x0f84591` and its
immediate return RVA as `0x01a03bb`. All 256 bounded producer events used type
`0x0102` and the same unwind chain; the event cap filled after 17.682 seconds
without a probe error or game crash. The function is the inbound application
message parsing loop: it initializes a temporary decode context, asks a reader
to fill it, reads the 16-bit message type, constructs and deserializes ordinary
message objects, and appends them to a vector. Type `0x0102` transfers that
vector into the timed 24-byte-entry queue, so it is a batch/flush control type
rather than an ordinary gameplay message.

The direct reader helper at RVA `0x111d640` runs immediately before the parser
observes the decoded type. The next code-only snapshot captures that helper and
the context initializer at `0x22378c0`, using their unwind metadata and without
reading the source object or its application data.

Capture `20260922-231425-inbound-reader-code-linux` showed that the first
unwind region at `0x111d640` ends after only 74 bytes, before the routine's
record-selection path completes. The visible prefix establishes reader object
fields: available-count boundary at `+0x120`, signed current index at `+0x128`,
exhaustion status `4` written at `+0x140`, and state flags at `+0x170` and
`+0x172`. `0x22378c0` has no unwind entry. The next snapshot therefore uses
fixed, version-guarded 1,024-byte forward code windows for both targets.

Capture `20260922-232100-inbound-reader-forward-code-linux` recovered the
complete selection path. Reader `+0x118` points to an array of record pointers;
the signed index at `+0x128` selects a record. A due record stores its
application-data pointer at record `+0x08` and 32-bit length at `+0x10`.
RVA `0x111d78a` loads those fields and passes them to `0x2237650`, which creates
the buffer wrapper subsequently attached to the temporary decode context.
This is after transport decryption and before type-specific deserialization.
The next revision replaces the completed producer breakpoint with this
version-checked boundary in plaintext mode and records the same bounded format
already used by `PLAINTEXT_OUT` as `PLAINTEXT_IN`.

Capture `20260922-232725-full-duplex-plaintext-verify-linux` produced 451
outbound records, all of which decoded as the known application envelope, but
zero inbound records. It reported no invalid window, oversize skip, or probe
error. Therefore the post-world parser is not using the direct `0x111d640`
reader implementation. The parser's alternative branch loads the reader from
parser object `+0x48` and calls vtable slot `+0x18`. The next address-only run
targets that branch at `0x0f84315`, records the concrete virtual target once,
and captures its bounded forward code window.

Capture `20260922-233330-virtual-inbound-reader-code-linux` resolved that
vtable method to RVA `0x0006c0f0`. The method wraps ownership and cleanup around
a direct call to RVA `0x0009a7c0`, passing the live reader in `RCX`, the
destination decode context in `RDX`, and a temporary record/result holder in
`R8`. The next one-shot code snapshot includes `0x9a7c0`, where the live record
must be converted into the decode context.

Capture `20260922-233746-virtual-reader-helper-code-linux` recovered the full
363-byte helper at RVA range `0x0009a7c0`–`0x0009a92b`. Its active handoff is
unambiguous: RVA `0x0009a839` loads the current source object from reader
`+0x70`, passes the destination context and source to RVA `0x223ebb0`, and
returns at RVA `0x0009a845` before running context validation. The next probe
breaks at that return site, snapshots both 96-byte objects, performs a bounded
one-level search for pointer/length and pointer/end spans, and captures the
context-copy routine. Candidate spans remain separately labelled until their
layout is verified; they are not yet treated as authoritative inbound records.

Capture `20260922-235015-virtual-reader-handoff-linux` reached the 64-event
handoff cap without a probe error. Every one of the 56 readable source
`+0x48` objects used vtable `0x1434863c0` and reference count 2. The object
stores its 32-bit payload length at `+0x0c` and its inline payload at `+0x10`.
Fifty-four ordinary cases also matched the outer length at source `+0x50`; two
edge cases differed, establishing that the inner length is authoritative. The
copy helper at `0x223ebb0` only clears destination state and stores the source
pointer at destination `+0`, so it performs no payload transformation. The
next build records `buffer+0x10` for `buffer+0x0c` bytes as `PLAINTEXT_IN`.

Capture `20260922-235711-inbound-plaintext-verify-linux` produced 64 direct
records, all of which exactly matched the inline buffer length and payload
prefix. Repeated 1,000-byte records showed they were backing blocks rather
than individual messages. Source `+0x50` advances as the block-local byte
cursor and source `+0x40` advances by the same delta as an absolute stream
position. For 54 consecutive same-block pairs, the bytes between adjacent
cursors decoded exactly as one even-ZigZag length-prefixed frame. Their
leading varuints were message types `0x014d` and `0x00e6`. Three additional
frames crossed block boundaries: the old block's tail plus exactly the number
of initial bytes indicated by the next block's cursor reconstructed the
declared frame length. The recorder now extracts at the cursor and maintains a
single bounded reassembly buffer for these two-block frames.

Capture `20260923-000856-inbound-frame-verify-linux` validated the completed
extractor at volume: all 512 captured inbound records decoded as one exact
length-prefixed frame, none were malformed, and the analyzer identified 28
length/type families. The dominant leading types were `0x0012` (254 frames),
`0x0102` (129), `0x000f` (64), `0x01b6` (16), and `0x014d` (17). A single
source three milliseconds after gate activation had a null `+0x48` pointer;
its stable object layout identifies a no-frame control variant, not corrupt
payload state. Null-buffer sources are now ignored. The post-world inbound
plaintext boundary, frame length, message-type field, cursor semantics, and
cross-block reassembly are therefore considered verified.

The next phase moves from boundary discovery to schema recovery. In the
verified parser, RVA `0x0f8447e` precedes the virtual call through message
vtable slot `+0x38`. At that point `RDI` holds the constructed message object,
stack `+0x90` retains its 16-bit type, and stack `+0x20` contains the decode
context. The schema-map probe uses the completed queue-watch hardware slot to
record this type/deserializer association, its input cursor, and one bounded
runtime code snapshot per unique pair. Static call analysis of those methods
will identify shared primitive field readers; controlled gameplay captures
will then supply semantic field names.

Capture `20260923-003918-schema-map-linux` reached the 4,096-event schema cap
with zero schema errors and discovered 45 unique type/deserializer pairs. All
45 code windows were complete within the 4,096-byte bound and every recorded
event included cursor metadata. Type `0x0012` dominated the bounded timeline
with 3,293 events, followed by `0x000f` with 314 and `0x014d` with 103. The
captured methods repeatedly call a compact primitive-reader family around
RVAs `0x223d530`–`0x223dcc0`, plus common readers at `0x0f7f5f0` and
`0x0f841e0`. Static call sites already expose destination offsets and several
compound layouts; for example, `0x000f` contains nested-object reads, numeric
and vector fields, an explicitly quantized signed 16-bit value, a 32-bit
value, and a packed 16-bit flag field.

The next opt-in schema-field stage uses the schema boundary as hardware
breakpoint 0 and rotates breakpoints 1-3 across each type's direct primitive
reader calls. A helper-entry breakpoint is temporarily replaced with that
call's return address. This records cursor-before/cursor-after, exact consumed
wire bytes, destination offset, bounded before/after destination snapshots,
reader arguments, and return status. Rotation is per type, so repeated
messages cover methods with more than three primitive readers without a probe
build per field. The stage is bounded to 128 reads per type and 16,384 total
records and is enabled only by `ISAC_SCHEMA_FIELD_PROBE=1`.

Capture `20260923-112147-schema-fields-linux` produced 1,164 completed field
records across 24 message types and 14 shared readers, with no field error,
failed helper return, or cursor regression. All but one record retained the
entire consumed wire span; the exception was an expected fixed 36-byte block
larger than the 32-byte preview. The results distinguish ZigZag signed 32- and
64-bit integers, unsigned varints, byte and Boolean reads, fixed 32- and
64-bit values, UUIDs, vectors, compressed directions, and the stateful compact
reference reader. They also show that type `0x019d` is a signed integer plus a
compact reference and that `0x0088` has an item/equipment-like composition.

The remaining ambiguity is field order when one deserializer calls the same
primitive helper more than once. The next revision therefore records the
exact return RVA for every completed helper call and groups fields by that
callsite. It also resolves object-adjusting tail thunks before scanning or
capturing a deserializer—type `0x0088` moves from its wrapper at `0x00eb6900`
to the implementation at `0x00eb5710`—and snapshots the shared helper
implementations so their decoding behavior can be recovered without another
probe build.

## Privacy and use boundary

The serialized records contain stable character/object identifiers and must
remain private. The probe stays world-gated, size-limited, and record-limited;
inbound discovery records are additionally depth- and candidate-limited. It is
intended only for controlled solo research, never live co-op, PvP, or
competitive play.
