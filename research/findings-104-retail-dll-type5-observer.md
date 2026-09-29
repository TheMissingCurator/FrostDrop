# Type-5 field observer ported to the retail forwarding DLL

Date: 2026-09-27

Follow-up: this initial build crashed in retail. Findings-105 documents the
Proton first-trap reproduction and correction; system Wine success below was
not sufficient validation of the installed Proton runtime.

The forwarding-only baseline reached the retail main menu (user confirmation,
new RETAIL_FORWARD_ONLY startup markers, normal Ubisoft export calls and Quit).
This change adds the requested bounded type-5 observation without returning
to whole-launch GDB tracing or network isolation.

## Implementation and evidence boundary

`retail_type5.h` ports the parser field state machine from
`service_name_producer_trace.py`. It checks root type, stack/frame, reader,
collection/getter layouts, lengths/counts and attribute indices. It preserves
wire name bytes, ordered duplicate key/value pairs and embedded NUL bytes.
Unknown data stays null/-1/incomplete. Parser success is AL; consumer acceptance
is BL. Paired producer-copy/written sites link the parser source to record+0x358
and read the normal assignment result (C-string-prefix equality).

`retail_type5_win.c` supplies bounded ReadProcessMemory, four per-thread rotating
execution slots, a VEH, preallocated thread/result state and a writer/sweep
worker. The fourth slot observes the prepared name directly at the gate.
Unlike the full GDB name-lineage trace it does **not** trace every selection
branch. A matching gate value is supporting field evidence, not independent
proof of selected-record identity. Pointer-derived opaque owner IDs can be
reused if an address is recycled; they are not permanent backend identifiers.

All 10 sites and 13 auxiliary signatures match the Python observer definitions
and retained `dc921cc2...eefb74` runtime text. Production requires the expected
AMD64 PE timestamp/image size and all signatures before arming. A compile-time
synthetic-address override exists only in the test EXE, not the DLL build.

The shared offline stack implementation is not linked. No gate, constructor,
profile, URL, certificate or server response is changed. The original retail
loader remains responsible for normal Ubisoft behavior. Clearing launch options
leaves forwarding but does not enable the type-5 worker; pure retail restoration
still uses the loader manager as documented.

## Bounds, safety and output

See `docs/retail-forward-probe.md` for exact limits and artifacts. Thread
coverage is sampled every 100 ms (at most 256 distinct threads); existing
debug-register users are refused, not overwritten. Every suspension is paired
with a resume attempt and failures are counted. No allocations, file writes or
observer locks while a peer is suspended; the VEH only reads bounded fields
and publishes preallocated records. The worker writes private JSONL, disarms
verified owned slots, and retains pinned handler code for cleanup failures.
Only debug-register state and RF are adjusted; no IP/GPR/TF or game-memory
writes. Gates and fields are not patched. Unwound/missed/reentrant paths and
exit before drain limit coverage; a missing end/partial JSON line is incomplete.

Private launch directory mode 0700, metadata and Wine JSONL mode 0600 via
umask 077. Metadata has no environment dump. Exact bounded service fields stay
under producer-private, with no ticket/account/raw-stream reads. Startup and
coverage diagnostics reveal no raw service strings or process pointers.

## Validation and deployment

- Six retail tests pass with Wine enabled: forwarding, environment cleanup,
  direct opaque exec, privacy, nine native core edge scenarios, and Windows
  VEH integration within the Wine smoke test.
- The Wine fixture executes parser/assignment/gate checkpoints on its initial
  thread and a newly created thread; both yield exact fields and copy equality.
  Foreign slots/exception handling remain intact and owned slots are removed.
- Nine existing Python producer/archive tests still pass.
- Runtime signature comparison: 23/23 match the retained snapshot.
- Frozen response implementation hashes unchanged from findings-100.

Installed with approval: retail-only DLL SHA-256
`a1ca491326ef4ae1423760db951d193df1e2348631c1e5443ee3eaf5cd4d4b56`.
Verified original Ubisoft loader backup remains
`df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8`.
Builds now archive predecessor probe binaries; the manager accepts verified
archived versions or the known initial forwarding baseline for upgrades, while
still refusing arbitrary active DLLs. No Proton prefix or login data changed.

Next: a real online retail startup capture, menu then brief writer drain and
quit. No gameplay/backend terminal/Enter required. Synthetic success is not
a claim that the game's thread coverage or missing service name is captured.
