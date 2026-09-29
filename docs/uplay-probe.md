# Uplay API forwarding probe

## Purpose

The probe records which Uplay API exports Division calls during startup. In
its default mode it does not inspect function arguments or return values.
Every call is forwarded to the user's original Ubisoft loader. A separately
opt-in, metadata-only ABI mode is documented below.

The probe logs only the first call to each function in each game process,
preventing `UPLAY_Update` from producing an unbounded log. Each record includes
a process ID, thread ID, and monotonic millisecond timestamp so it can be
correlated with a Proton trace.

## Build

```bash
./tools/build-uplay-probe.sh
```

The artifact is written to:

```text
dist/uplay_probe/uplay_r1_loader64.dll
```

## Optional address-only stack probe

On Linux/Proton, the same DLL can also record game-code return addresses for
send and receive calls on established TCP connections whose peer port is
55000. Enable it for one controlled run by adding this environment variable
to the game's Steam launch options:

```text
ISAC_STACK_PROBE=1
```

The resulting `project-isac-stack-probe.log` contains normalized RVAs into
the main game executable, direction, process/thread IDs, monotonic time, and
the Wine socket handle. It never reads or records packet buffers, payloads,
credentials, tickets, account identifiers, or remote IP addresses. Duplicate
call stacks are suppressed and the log is capped at 256 unique stacks.

This is a deliberately version-checked Proton/Wine probe. It recognizes only
the two Winsock implementations tested by this project and refuses to install
its in-memory hooks if their instruction signatures differ. A
`STACK_PROBE_READY` record means both hooks were installed; any
`STACK_PROBE_ERROR` means the stack results from that run should not be used.
Remove `ISAC_STACK_PROBE=1` after the controlled capture. Do not use the probe
in co-op, PvP, or other competitive/live multiplayer play.

Summarize a captured stack log with:

```bash
./tools/analyze-stack-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-stack-probe.log
```

### Bounded runtime code snapshot

After a stack capture has identified candidate game RVAs, this build can take
a separate, version-locked code snapshot with:

```text
ISAC_STACK_PROBE=1 ISAC_CODE_PROBE=1
```

For the currently verified Division executable, the current snapshot captures
14 fixed parser/serializer code windows: the inbound consumer, the original
outbound candidates, the world dispatcher, three field-writing helpers, and
seven frames from the observed world-send chain. The largest window is 512
bytes and the total upper bound is 6,144 bytes. Windows are
captured only after their filtered port-55000 path is observed. It does not
scan or dump sections, packet buffers, heap data, credentials, keys, or session
material. Both the executable PE timestamp and image size are verified from
the on-disk `thedivision.exe`; otherwise it writes `CODE_PROBE_SKIPPED` and
captures no bytes. The guard intentionally does not rely on the packed game's
mutable in-memory PE header.

The capture helper stores this run's appended records as
`project-isac-code-probe.log`. Disassemble the captured forward windows with:

```bash
./tools/analyze-code-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-code-probe.log
```

### Dispatch target and bounded code probe

The next opt-in stage records the game-relative addresses of virtual methods
that the previously captured code invokes: the inbound stream handler and
each observed inbound or outbound message object's type method. For every new target it also
copies a bounded executable-image window: 256 bytes for an inbound handler and
32 bytes for a message-type method. Enable it only together with the stack
probe:

```text
ISAC_STACK_PROBE=1 ISAC_CODE_PROBE=1 ISAC_DISPATCH_PROBE=1
```

Per-thread hardware execution breakpoints are armed lazily after traffic to
peer port 55000 proves the relevant runtime path is active. This avoids writing
to Division's protected executable image. Both the executable build and the
exact bytes at each observed function must match. The resulting
`project-isac-dispatch-probe.log` contains normalized method RVAs, bounded
machine-code windows, process/thread IDs, and monotonic time. When a type method
exactly matches `movzx eax, word ptr [rip+disp32]; ret`, the probe additionally
reads that referenced two-byte value from inside the verified game image and
records its source RVA and numeric type ID. It does not call the type method,
inspect packet or message buffers, or log object addresses. Outbound message
objects are observed at the verified queue-submit function at RVA `0x00d3920`.
Other method shapes are left undecoded. Duplicate targets are suppressed and
the log is capped at 256 unique targets.

Summarize the targets, captured type IDs, and statically recognized getters with:

```bash
./tools/analyze-dispatch-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log
```

Add `--disassemble` to print complete disassembly of the bounded windows, or
use `--kind inbound-handler` to restrict the output.

### Bounded dispatch-event timeline

After numeric type IDs have been verified, an additional opt-in stage records
each occurrence at the world dispatcher. Enable it with the other dispatch
settings:

```text
ISAC_STACK_PROBE=1 ISAC_CODE_PROBE=1 ISAC_DISPATCH_PROBE=1 ISAC_DISPATCH_EVENT_PROBE=1
```

Each `DISPATCH_EVENT` contains only a sequence number, monotonic timestamp,
direction, process/thread IDs, method RVA, and the decoded 16-bit type ID. It records no
message object, fields, payload bytes, account data, endpoints, or keys. The
timeline is capped at 32,768 events and reports `DISPATCH_EVENT_LIMIT` if the
cap is reached. The event log handle stays open during the capture to avoid a
file-open operation on every dispatch.

The probe also records one `DISPATCH_CALLER` for each unique world-message
type and direct return RVA. This is an address-only breadcrumb for locating the
game's parser/deserializer path. It reads the return address already on the
interrupted thread's stack and records no stack contents or message payload.
For each unique return RVA, it also records one 768-byte executable-code
window centered around that address. This is required because the retail
executable's active code is unpacked at runtime and the corresponding on-disk
sections do not contain disassemblable bytes.

The current revision uses the fourth hardware register to find the producer of
the timed inbound queue. It begins as an execute breakpoint at the version-
checked scheduler RVA `0x1814360`. Once that function reveals its live array
descriptor, the register becomes a four-byte write watchpoint on the queue's
count field for that scheduler thread. Other threads retain the guarded
scheduler-entry breakpoint and opt into the same watch only if they execute
that scheduler themselves. The earlier global propagation experiment was
removed after it destabilized Proton during world loading.

Each unique `INBOUND_QUEUE_WRITE` contains only the writer instruction RVA and
up to 16 candidate game-code return RVAs found in a bounded 128-slot scan of
the interrupted stack. `INBOUND_QUEUE_CODE` stores at most 128 executable-code
windows around unique writer/stack anchors. Stack contents, heap addresses,
queue entries, message objects, and payload data are not logged. Use
`--disassemble-queue` with the dispatch analyzer to inspect these windows.

The first hardware register now targets the version-checked producer branch at
RVA `0x0f843b6`, replacing the rejected transport candidate at `0x2016740`.
That branch runs only when the parser selects the special timed-batch path.
Each bounded `INBOUND_QUEUE_PRODUCER` event records the 16-bit type value,
queue count/capacity, containing function range obtained from Windows unwind
metadata, and up to 16 unwound game-code caller RVAs. The first hit also emits
one capped `INBOUND_QUEUE_PRODUCER_CODE` window for the containing function.
No queue entries, message objects, heap addresses, or payload bytes are read.

After the producer function identified the direct reader calls, the probe also
captures two code-only runtime functions on the first producer hit:
`read-next` at RVA `0x111d640` and the temporary decode-context initializer at
RVA `0x22378c0`. These `INBOUND_READER_CODE` records use unwind metadata for
exact function bounds and are capped at 2,048 bytes each. They inspect no
reader object, decode context, application bytes, or message fields.

Because the reader uses split unwind regions and the context initializer is a
leaf without unwind metadata, the same first hit also records guarded
1,024-byte `INBOUND_READER_FORWARD_CODE` windows beginning at both known
targets. These forward windows are executable-image code only and allow the
reader continuation to be analyzed without treating unwind-region ends as
function ends.

The recovered reader selects an inbound record from the array at reader
`+0x118`. Immediately before RVA `0x111d78a`, the selected record stores its
application-data pointer at `+0x08` and 32-bit byte length at `+0x10`. When
plaintext mode is enabled, the first hardware register now targets that
version-checked instruction instead of the completed producer probe and passes
the verified span to the existing bounded `PLAINTEXT_IN` logger. Inbound and
outbound directions are independently limited to 512 records of at most 1,000
bytes, and the existing world-type `0x0012` gate remains in force.

If the live parser selects its alternative reader, the plaintext-mode first
breakpoint targets the version-checked branch at RVA `0x0f84315`. It resolves
the reader at parser `+0x48`, vtable slot `+0x18`, records only that method's
game-image RVA, and emits one 1,024-byte `virtual-read-next` code window. This
temporary discovery stage is required because the direct `0x111d640` reader
was not active after the world gate in the verification capture.

The resolved alternative reader is RVA `0x0006c0f0`. Its direct helper at RVA
`0x0009a7c0` receives the reader, destination decode context, and temporary
record owner. The discovery snapshot therefore also emits exact-unwind and
1,024-byte `virtual-read-helper` windows for that helper.

The complete helper recovered the active context handoff. At RVA `0x0009a839`
it loads the current source object from reader `+0x70`, passes that object and
the destination decode context to RVA `0x223ebb0`, and returns to RVA
`0x0009a845`. Plaintext mode now places its first breakpoint at that return
site. After the copy it records bounded 96-byte snapshots of the source and
destination objects, follows at most six non-image object pointers from each,
and tests those objects for pointer/length and pointer/end span layouts. It
emits at most 12 `INBOUND_SPAN_CANDIDATE` records for each of 64 handoffs, with
each candidate capped at 1,000 bytes. The first hit also captures the context
copy routine as `virtual-context-copy`. This is a discovery corpus: candidates
are deliberately kept distinct from verified `PLAINTEXT_IN` records until the
copy routine and repeated object layouts identify the authoritative span.

Capture `20260922-235015-virtual-reader-handoff-linux` verified the buffer
layout. Source `+0x48` points to a ref-counted buffer object whose payload
length is the 32-bit value at `+0x0c` and whose payload begins inline at
`+0x10`. All 56 readable buffer objects used the same vtable and reference
layout. The handoff probe now passes this exact inner span to `PLAINTEXT_IN`;
the exploratory object/candidate records remain enabled for one verification
run so the direct record can be compared against its source structure.

Capture `20260922-235711-inbound-plaintext-verify-linux` matched all 64 direct
records against their buffer objects. It also established that source `+0x50`
is the byte cursor within the backing block, while source `+0x40` is the
absolute stream position. Starting at that cursor, each inbound message uses
the same even-ZigZag length prefix already observed around outbound nested
frames. The probe now records one complete length-prefixed inbound frame per
handoff. A bounded pending buffer rejoins frames split across two 1,000-byte
backing blocks; the next block's initial cursor is the exact continuation
length. `analyze-plaintext-probe.py` reports these as inbound frame families
and treats their leading varuint as the message type.

Capture `20260923-000856-inbound-frame-verify-linux` filled the 512-record
inbound cap. All 512 records decoded as exactly one frame, with zero malformed
or inconsistent lengths and 28 distinct length/type families. The one initial
null-buffer source was a valid no-frame control variant immediately after the
world gate; it is now ignored rather than reported as an invalid buffer. This
completes discovery and validation of the post-world inbound plaintext
boundary and framing.

### Inbound schema map

With inbound framing verified, plaintext mode also maps message types to their
message-specific deserializers. Hardware breakpoint 3 now targets the guarded
parser call site at RVA `0x0f8447e` instead of the completed queue-count watch.
At that boundary, `RDI` is the constructed message object, stack `+0x90` is
the 16-bit type, stack `+0x20` is the decode context, and vtable slot `+0x38`
is the deserializer about to run. The probe records up to 4,096
`SCHEMA_EVENT` entries with normalized RVAs and cursor metadata. It records up
to 256 unique type/deserializer pairs and one version-checked code window of at
most 4,096 bytes for each pair. No message-object fields or additional payload
bytes are copied by this stage, and it remains inactive until the existing
world gate opens.

Summarize the type-to-deserializer map with:

```bash
./tools/analyze-schema-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log
```

Add `--calls` to list direct helper-call targets recovered from each captured
method, `--disassemble` for complete disassembly, `--type 0x014d` to select one
message type, or `--timeline` for cursor-correlated schema events. Deserializer
tail thunks are followed before code capture; `SCHEMA_RESOLUTION` records retain
the original target, resolved implementation RVA, and message-object adjustment.
The schema-field mode also captures the bounded implementations of the shared
primitive readers once per process. Add `--helpers` (and optionally
`--disassemble` or `--calls`) to inspect those `SCHEMA_HELPER_CODE` records.

### Inbound schema field trace

Set `ISAC_SCHEMA_FIELD_PROBE=1` together with the plaintext probe to resolve
the wire encoding used by the mapped deserializers. Once the world gate has
opened and the first schema boundary is reached, breakpoint 0 remains on the
schema boundary and breakpoints 1-3 rotate across that message type's direct
primitive reader calls. Each helper entry is temporarily replaced by its
return address, allowing one `SCHEMA_FIELD` record to contain the absolute
cursor before and after the call, the exact consumed wire bytes when they fit
within the 32-byte window, the precise return/callsite RVA inside the resolved
deserializer, the destination offset, reader arguments, return value, and
bounded destination snapshots before and after the read. Grouping by callsite
keeps repeated calls to the same primitive reader as distinct schema fields.

Rotation is per message type. Repeated instances therefore cover methods with
more than three primitive helpers in one gameplay capture. Logging is bounded
to 128 completed reads per type and 32,768 records overall. This mode
repurposes the plaintext and dispatcher breakpoint slots after schema tracing
starts, so use it for schema work rather than for a simultaneous full
plaintext corpus.

Set `ISAC_SCHEMA_FIELD_TYPE` to one 16-bit message type (for example,
`ISAC_SCHEMA_FIELD_TYPE=0x0088`) for a focused run. Nonmatching messages keep
the schema-boundary breakpoint but do not arm primitive-reader breakpoints.
The selected type receives up to 2,048 completed field reads instead of the
128-read general limit, within a 32,768-record global bound. Focused type
`0x0088` runs also snapshot the unpacked nested parser rooted at RVA
`0x0c47de0` and up to 24 direct callee functions as `SCHEMA_NESTED_CODE`.
Because that logical parser spans several adjacent Windows unwind ranges, the
probe additionally records a fixed 2,048-byte window beginning at the root as
`SCHEMA_NESTED_FORWARD_CODE`. This forward snapshot is static executable code;
it does not record message payloads or heap data.

Summarize the resulting field shapes with:

```bash
./tools/analyze-schema-fields.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log
```

Use `--type 0x000f` to isolate a message schema, `--examples 0` to suppress
wire examples, or `--timeline` for action correlation. A successful run has
`SCHEMA_FIELD_PROBE_READY`, one or more `SCHEMA_FIELD` records, and no
`SCHEMA_FIELD_ERROR` records.

Inspect resolved primitive-reader implementations and the focused nested
parser graph with:

```bash
./tools/analyze-schema-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log \
  --helpers --nested --calls
```

Add `--disassemble` when the full captured assembly is needed. Primitive
reader entry thunks are followed before their code is recorded; the original
and resolved RVAs remain in each helper summary.

For a focused `0x0088` field capture, validate the complete structural codec
against every reconstructed body with:

```bash
./tools/validate-type0088.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log
```

The validator reports only aggregate lengths, counts, and round-trip results;
it does not print reference identifiers or body bytes. The completed schema is
recorded in `research/findings-012-type0088-schema.md`.

### Broad schema miner

Set `ISAC_SCHEMA_MINER=1` instead of a type filter to survey all inbound
message types in one longer gameplay run. Miner mode implies the schema-field
probe, raises the per-type field sample allowance to 512, and temporarily
replaces the schema-boundary breakpoint with the guarded return at RVA
`0x0f8448c` while each deserializer executes. The return record contains the
complete message body after its already-consumed type value, plus the entry
and exit stream positions needed to correlate every primitive read.

```text
ISAC_STACK_PROBE=1 ISAC_CODE_PROBE=1 ISAC_DISPATCH_PROBE=1 ISAC_DISPATCH_EVENT_PROBE=1 ISAC_PLAINTEXT_PROBE=1 ISAC_SCHEMA_MINER=1 %command%
```

`SCHEMA_MESSAGE` records are limited to 8,192 messages and 2,048 bytes per
body. Bodies crossing one backing-buffer boundary are reassembled. Larger or
more fragmented bodies remain recorded as incomplete and are excluded from
full-coverage ranking. The field log retains its 32,768-record global bound.

Analyze a run without displaying body contents:

```bash
./tools/analyze-schema-miner.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log
```

Use `--type 0x0088` for a provisional callsite-level field map or `--timeline`
to correlate types with a controlled sequence of gameplay actions. The report
ranks types by byte coverage, reports structural-shape and body-length
families, and identifies unexplained byte ranges. A valid run contains
`SCHEMA_MINER_READY`, `SCHEMA_MESSAGE`, and `SCHEMA_FIELD` records without a
`SCHEMA_MESSAGE_ERROR` or `SCHEMA_FIELD_ERROR`.

Unlike the ordinary address-only modes, miner evidence contains application
message bodies. Keep its dispatch log private and do not commit it or share
raw reference identifiers.

Validate the stable simple codecs promoted from a miner run with:

```bash
./tools/validate-simple-schemas.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log
```

The initial validated broad result is recorded in
`research/findings-013-broad-schema-miner.md`.

Summarize event counts by type with:

```bash
./tools/analyze-dispatch-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log \
  --events summary
```

Use `--events timeline` only when the complete bounded sequence is needed.
Use `--disassemble-callers` to disassemble the runtime caller-code windows.
`DISPATCH_EVENT_READY` confirms that the event log was opened successfully;
any `DISPATCH_EVENT_ERROR` invalidates the event portion of that run.

### Redacted bootstrap timeline

Set `ISAC_BOOTSTRAP_PROBE=1` with the stack and dispatch probes to install the
already verified application-boundary breakpoints immediately, rather than on
the first observed port-55000 call:

```text
ISAC_STACK_PROBE=1 ISAC_DISPATCH_PROBE=1 ISAC_DISPATCH_EVENT_PROBE=1 ISAC_BOOTSTRAP_PROBE=1 %command%
```

Bootstrap mode implies the plaintext boundary probe. Before the existing
world-type `0x0012` gate, it deliberately does **not** write application bytes.
It records `BOOTSTRAP_SOCKET` events with bounded process-local socket IDs and
`BOOTSTRAP_RECORD` events with direction, process-local stream ID, total
length, envelope marker/channel, nested frame lengths, and leading message
type IDs. Unknown and over-size startup records retain only their length and
framing status. `SCHEMA_EVENT` and `SCHEMA_TARGET` metadata may also be
collected before the gate, but schema-field and complete-body capture remain
disabled there even when schema-miner variables are present.

When inbound type `0x0012` reaches the world dispatcher,
`BOOTSTRAP_PHASE detail=phase=world,...` marks the transition and the existing
bounded gameplay plaintext behavior takes over. Run the structural analyzer
without exposing payload bytes:

```bash
./tools/analyze-bootstrap-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-plaintext-probe.log --timeline
```

For the intended capture, start with Ubisoft Connect fully closed, launch
normally through Steam, continue through the main menu and character
selection, wait until the world finishes loading, move briefly, and then exit
cleanly. Do not use bootstrap mode in co-op, PvP, or other live multiplayer.

### Early-control path probe

The redacted bootstrap capture showed that inbound types `0x0002` and
`0x0006` use the generic decrypted-frame handoff but do not reach the known
world deserializer boundary. Set `ISAC_CONTROL_PROBE=1` to target only those
two early response types:

```text
ISAC_STACK_PROBE=1 ISAC_DISPATCH_PROBE=1 ISAC_CONTROL_PROBE=1 %command%
```

Control mode implies bootstrap mode and immediate breakpoint installation. At
the verified inbound handoff it peeks only at the length prefix and leading
type ID. For `0x0002` or `0x0006`, it records a bounded `CONTROL_PATH` unwind
of normalized game RVAs and one `CONTROL_CODE` snapshot for each unique caller
function. It never writes either response body. Code capture is limited to 32
unique functions and 4,096 bytes per function; path capture is limited to 32
events.

The first control-path capture identified the dedicated control dispatcher at
RVA `0x0099e00`. That dispatcher routes type `0x0002` to RVA `0x00aeed0` and
type `0x0006` to RVA `0x009ad00`. Because the executable stores these routines
in unpacked runtime memory rather than readable on-disk `.text`, control mode
now snapshots both decoder functions directly during probe setup. Consequently
both decoder bodies are available even when a short startup run receives only
one of the two response types. These are code-only snapshots and do not change
the payload-redaction rule.

The type-`0x0002` wrapper delegates wire decoding to RVA `0x2257cc0`, so a
fixed 4,096-byte forward window captures that generated schema routine and its
nearby code. The type-`0x0006` decoder uses adjacent Windows unwind regions:
its first nominal region is only the 19-byte function prologue. Control mode
therefore also captures a fixed 4,096-byte forward code window from
`0x009ad00` rather than treating that first unwind region as the whole
function.

Static analysis of those windows shows that the type-`0x0002` generated
reader consumes a variable-length 32-bit integer and delegates its remaining
nested object to RVA `0x00651d0`. The type-`0x0006` handler delegates its
response object to RVA `0x2257c10`. Both targets are captured as additional
4,096-byte forward windows in the same run, keeping schema discovery code-only
and independent of whether type `0x0006` is received live.

The `0x00651d0` reader first decodes a shared base object at `0x0064e50`, then
a variable-length flags word. Flag bit 0 adds an object rooted at `0x0065370`;
flag bit 1 adds an object rooted at `0x0064800`. Two additional forward code
windows start at `0x00632f0` and `0x0064800`. Together they cover the unresolved
`0x00632f0`, `0x0063860`, `0x0064800`, and `0x0064e50` callees without recording
any message body bytes.

That closure revealed one further nested reader at `0x0064760` and fixed-width
reader calls in the `0x00216d0` region. Control mode captures both as forward
windows as well. The latter single window includes RVAs `0x00216d0`,
`0x0021760`, and `0x00217f0`.

The same revision inspects bootstrap envelopes up to 16,384 bytes for framing
metadata, while continuing to omit their body bytes. This allows the large
startup requests previously labelled `oversize` to expose only their channel,
frame lengths, and type IDs.

Summarize the result with:

```bash
./tools/analyze-control-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log
```

Add `--disassemble` only for local inspection of the captured executable code.
For a focused direct-decoder run, reaching the main menu is sufficient once
the log contains `CONTROL_PROBE_READY` and `CONTROL_CODE` records for function
RVAs `0xaeed0`, `0x216d0`, `0x632f0`, `0x64760`, `0x64800`, `0x651d0`,
`0x9ad00`, `0x2257c10`, and `0x2257cc0`; entering the world is unnecessary.

### Outbound bootstrap request path probe

The local bootstrap server still needs to derive response correlation IDs from
the client's requests. Enable the code-only outbound control probe to identify
the producer paths for request types `0x0002` and `0x0005`:

```text
ISAC_STACK_PROBE=1 ISAC_DISPATCH_PROBE=1 ISAC_OUTBOUND_CONTROL_PROBE=1 %command%
```

This mode implies redacted bootstrap capture and immediate breakpoint
installation. When the verified outbound application boundary sees an
envelope containing either target type, it records `OUTBOUND_CONTROL_PATH`
with normalized game RVAs and bounded `OUTBOUND_CONTROL_CODE` snapshots for
the boundary function and its callers. It records framing metadata but never
writes request bodies, credentials, tickets, account identifiers, or session
material. Path capture is limited to 32 events and code capture to 32 unique
functions of at most 4,096 bytes each. When this mode is used by itself, the
probe remains metadata-only after the world gate as well, so accidentally
loading into the world does not enable gameplay-payload logging.

The probe also decodes only the first unsigned varint following the type ID
for outbound `0x0002`/`0x0005` and inbound `0x0002`/`0x0006`. It writes the
numeric value and its encoded width as `CONTROL_CORRELATION`, never the source
bytes or the rest of the frame. Matching request and response values tests the
correlation-ID hypothesis directly; this derived-field log is capped at 64
events.

For the intended capture, fully exit Ubisoft Connect, launch through Steam,
and stop after the main menu has stabilized. Entering the world is not needed.
Summarize the result with:

```bash
./tools/analyze-outbound-control-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log --disassemble
```

### Inbound reader setup probe

The prospective local transport bridge needs a safe way to place synthetic
server frames into the client's existing decrypted-record path. Enable this
code-only probe to locate the code that constructs and populates the active
reader:

```text
ISAC_STACK_PROBE=1 ISAC_DISPATCH_PROBE=1 ISAC_INBOUND_SOURCE_PROBE=1 %command%
```

At the first verified handoff, the probe records the live reader vtable as a
module-relative RVA and the first 16 module-relative method RVAs. It recognizes
up to eight distinct reader vtables, then scans only committed executable pages
for RIP-relative references to each exact vtable and captures bounded code
around up to 32 references per vtable. These
`INBOUND_SOURCE_VTABLE_XREF` sites are constructor/setup candidates; their code
windows are labelled `reader-vtable-xref`.

The September 24 xref capture resolved the reader vtable to RVA `0x291da38`
and found exactly three references. RVAs `0x002f790` and `0x002f900` are two
constructor variants; both allocate an `0x80`-byte object, initialize it via
RVA `0x2237e90`, and assign it to `reader+0x70`. RVA `0x003b580` is the
destructor. The current probe additionally snapshots both constructors, the
source-object constructor, and reader setup routines `0x005fb10` and
`0x005fed0` as bounded `INBOUND_READER_CODE` and
`INBOUND_READER_FORWARD_CODE` records.

Those setup routines converge on shared routine `0x000af360`. The current
probe snapshots that routine as `reader-register`. It also inventories the
vtable of the persistent source object exposed at `reader+0x70` and captures a
bounded `vtable-method` code window for each in-image method in both the reader
and source vtables. This combines registration-path and source-method discovery
in one run.

The resulting capture showed that `0x000af360` allocates a `0x98`-byte
registration object, initializes it through RVA `0x00034450`, attaches the
resolved transport handle, and inserts it into the reader-owned table at
`reader+0x570`. The current probe uses a code breakpoint at the constructor's
return site `0x000af439`; it scans only the new object's pointer-sized fields
for in-image vtables, logs their offsets and module-relative RVAs, and subjects
each discovered interface to the same bounded vtable/xref/method-code capture.
The registration object's bytes and heap address are not logged.

The interface capture classified the subobjects at `+0x18` and `+0x50` as
collection adapters rather than direct transport callbacks. The current probe
therefore also classifies the three external registration values still capable
of carrying the delivery edge: the transport reference attached at `+0x00`,
the original registration input copied into the second collection, and the
resolved context stored at `+0x90`. It logs only each role, whether the value
is a valid in-image polymorphic object, its module-relative vtable RVA, and the
same bounded vtable/xref/method-code inventory. Pointer values and payloads
remain disabled.

The handle capture resolved `transport-reference` to the reader's secondary
interface at object offset `+0x08`. Its slot 3, RVA `0x00084bd0`, walks
refcounted receive chunks and forwards each `chunk+0x10` byte span with its
length from `chunk+0x0c` to the persistent source at reader offset `+0x70`.
The destination is source vtable slot `+0x30`, a thunk at `0x223f180` that
jumps to `0x223d140`. The current mode uses its two freed hardware-breakpoint
slots to observe both wrapper and direct source entries. It records only chunk
counts, byte lengths, readable-window status, and module-relative call stacks,
capped at 128 events per entry; contents and pointer values are never logged.

The validation run confirmed same-tick, equal-length wrapper/direct pairs and
showed that `0x223d140` copies arbitrary input into refcounted 1,000-byte
source chunks while maintaining the source's own lock and total-byte count.
Because this append primitive is shared by other engine buffers, a future
bridge must retain the exact object at reader `+0x70`. The current capture also
records complete bounded code for the wrapper's outer lock, reader notification,
and unlock helpers at RVAs `0x0000b7e0`, `0x0001e0a0`, and `0x0000c6c0`.

The helper capture established the complete calling contract. The lock helper
takes an eight-byte guard and the lock object at primary-reader offset `+0x18`,
saves the lock pointer in the guard, and acquires it. The notification helper
takes the address of the notification field at primary-reader offset `+0x68`.
The unlock helper takes the same guard and releases its saved lock pointer.
An injected application-plaintext span must therefore run, in order: outer
lock, `0x223d140(source, bytes, length)`, reader notification, and outer unlock.
The captured run observed 27 complete transport deliveries from 3 through
4,096 bytes with no helper-capture error.

An observe-only loopback bridge is now gated by
`ISAC_LOCAL_BACKEND_BRIDGE=1`. It assigns its four hardware breakpoints to the
transport-delivery wrapper, world gate, outbound plaintext writer boundary,
and reader-registration function. It pins only the plaintext writer whose
first valid envelope contains bootstrap type `0x0002`, forwards that ordered
stream to `127.0.0.1:55000`, and records response lengths. The bridge also
retains the exact reader/source after a real transport delivery. Response
injection remains disabled in this stage, and the retail path is untouched.
The later mutation stages are separately gated by
`ISAC_LOCAL_BACKEND_INJECT=1` and
`ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1`; see `docs/local-bootstrap.md` for their
guards, launch options, and stop conditions. Neither is implied by ordinary
observe-only bridge mode.

The probe also retains the completed diagnostic of the branch at RVA
`0x0009a851`: reader vtable slot `+0x38` resolves to RVA `0x00078db0`, which
only tests whether state `reader+0x90` equals `2`. An eight-byte watch on
`reader+0x70` produced no writes during a full gameplay capture, so this is a
finished/closed check rather than a source-advance method. Object addresses,
source pointers, record contents, and payload bytes are never logged.

The earlier September 24 implementation watched the selected source object's
backing-buffer pointer at `source+0x48`. Its 64 hits all came from the generic
refcounted assignment helper at RVA `0x0223cd58`; disassembly showed both the
early `0x00021500` caller and later world callers were schema/cursor readers,
not a transport producer. That downstream watchpoint has been retired.

For the intended capture, a normal connected launch through world entry is
sufficient; combat is not required. Inspect paths with
`rg '^INBOUND_SOURCE_'` and disassemble the bounded functions with:

```bash
./tools/analyze-dispatch-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-dispatch-probe.log \
  --disassemble-queue
```

### World-gated serialized data

The payload stage is separately opt-in because its output may contain gameplay
or character identifiers. It captures outbound data after the world-send path
has assembled its application writer and immediately before that writer is
handed to the transport object at RVA `0x00d6bbf`. The verified writer stores
its byte pointer at offset `0x4090` and its byte count at offset `0x4098`.
This is application plaintext in the cryptographic sense, but it is expected
to be a compact binary protocol rather than readable text.

An earlier inbound candidate at RVA `0x2016850` has been disabled. The
September 22 capture showed that every candidate buffer used TLS application-
data framing (`17 03 03` plus a two-byte record length), sometimes with several
TLS records concatenated. The address is therefore an encrypted-record
accumulator before decryption, not an inbound application-plaintext boundary.

Enable it only with the guarded dispatch probe:

```text
ISAC_STACK_PROBE=1 ISAC_CODE_PROBE=1 ISAC_DISPATCH_PROBE=1 ISAC_PLAINTEXT_PROBE=1
```

Without bootstrap mode, the capture remains inactive until the world
dispatcher observes type ID `0x0012`, preventing collection during the earlier
allocation and control startup. In bootstrap mode, only the redacted
structural metadata described above is written before that same gate. The
exact outbound call-site signature must also match. Each complete outbound
record is limited to 1,000 bytes, with a limit of 512 records.
`PLAINTEXT_PROBE_ACTIVE` confirms that the world gate opened; any
`PLAINTEXT_PROBE_ERROR` invalidates the run.

The separate `project-isac-plaintext-probe.log` should remain private. Show
only structural statistics by default with:

```bash
./tools/analyze-plaintext-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-plaintext-probe.log
```

Add `--families` to group records by their decoded envelope marker, channel,
and nested-frame shapes. Each frame is shown as its byte length and leading
unsigned variable-length value; that leading value remains structurally named
until its protocol meaning is established. Add `--timeline` to correlate the
same fields with elapsed capture time without printing payload bytes.

Pass `--hex-limit 32` when local inspection of a bounded prefix is required.

`DISPATCH_PROBE_ARMED` means the build guard passed;
`DISPATCH_PROBE_READY` means the required breakpoint addresses were armed on
the existing threads. Treat any `DISPATCH_PROBE_ERROR` as invalidating that run.
The breakpoint state is intrusive even though it does not alter game code, so
use this stage only in solo play and remove `ISAC_DISPATCH_PROBE=1` after the
controlled capture. Never use it in co-op, PvP, or other live multiplayer.

## Metadata-only Uplay ABI probe

The standalone local Uplay compatibility layer needs the calling and return
contracts of the small export set used during startup. Enable the bounded ABI
probe for one normal connected launch with:

```text
ISAC_UPLAY_ABI_PROBE=1 %command%
```

Do not combine this capture with the gameplay, schema, or world-replay probes.
Reach the normal character menu, wait briefly, and exit cleanly. The wrapper
continues calling the original Ubisoft DLL and preserves the incoming stack,
register arguments, integer/floating-point return registers, and original
return address.

Only the exports already observed during menu startup, plus lifecycle/error
helpers, are sampled. Each function is capped at 16 call/return pairs. The
separate `project-isac-uplay-abi-probe.log` records:

- the export name and normalized main-image caller RVA;
- whether each of four register and four possible stack arguments looks null,
  scalar, readable, writable, or like a UTF-8 string;
- scalar return values and pointer/string return shapes;
- whether the first machine word behind a readable argument changed; and
- direct or one-level-indirect UTF-8 lengths when recognizable.

The first call from each unique game call site also records a bounded window
of executable bytes around its normalized return RVA. At most 128 windows are
captured. When Windows unwind metadata identifies the enclosing function and
the call occurs within its first 512 bytes, the window starts at that exact
instruction boundary; otherwise it is limited to the preceding 256 bytes.
This distinguishes actual argument setup and return handling from unrelated
values left in volatile registers.

It never writes raw pointers, argument buffers, string bytes, tickets, account
IDs, names, credentials, or pointed-to structure contents. Non-small scalar
arguments are redacted. Any `UPLAY_ABI_ERROR` invalidates the capture.

Summarize the result with:

```bash
./tools/analyze-uplay-abi-probe.py \
  evidence/CAPTURE_DIRECTORY/project-isac-uplay-abi-probe.log
```

Disassemble caller windows, optionally limiting output to one export:

```bash
./tools/analyze-uplay-abi-callers.py \
  evidence/CAPTURE_DIRECTORY/project-isac-uplay-abi-probe.log \
  --function UPLAY_USER_IsOwned
```

## Guarded installation

Close Division and Ubisoft Connect first. Check the current state:

```bash
./tools/manage-uplay-probe.sh status "/path/to/The Division"
```

Install the probe:

```bash
./tools/manage-uplay-probe.sh install "/path/to/The Division"
```

The tool verifies the exact retail hash analyzed for this project, retains the
original as `uplay_r1_loader64_isac_original.dll`, and refuses to proceed if
Division or Ubisoft Connect is still running. It never deletes the backup.

When loaded, the probe creates `project-isac-uplay-probe.log` in the game
directory.

If optional probes are enabled, they separately create stack, code, dispatch,
plaintext, and Uplay ABI log files. The Linux capture helper copies only the
bytes appended to each persistent log during the current run.

Use the probe first during a normal connected launch. If the game behaves
differently, restore the original immediately and do not use that capture.

## Restoration

Close Division and Ubisoft Connect, then run:

```bash
./tools/manage-uplay-probe.sh restore "/path/to/The Division"
```

The verified original is copied back into place and its backup is retained.
Steam file verification is an additional restoration method, but may replace
other local changes too.

## Privacy

The default log contains event labels, monotonic timestamps, process/thread
IDs, and API function names only. It does not record API arguments, return
values, Ubisoft account values, or ticket contents. The separately opt-in ABI
log records only the bounded value shapes, scalar returns, mutation flags, and
string lengths described above; it never records string or buffer contents.

The optional stack log is address-only. The dispatch log additionally contains
the bounded executable code, type IDs, and—when explicitly enabled after the
world gate—schema-field or message bodies described above. Bootstrap records
before the gate contain metadata only. Treat raw packet captures and
`project-isac-plaintext-probe.log` separately: gameplay records after the gate
may contain opaque identifiers or session material and should remain private.
