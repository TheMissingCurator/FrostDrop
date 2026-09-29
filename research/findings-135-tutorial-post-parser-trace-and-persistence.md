# Finding 135: tutorial decoder result and targeted consumer probe

Date: 2026-09-28. Local experimental backend, analyzed build only.

The 2026-09-28 00:42 local run logged the authenticated `0x000c` submission
and a completed `sendall` of a response containing the experimental five-row
`0x00e6`. The read-only client trace reached the `0x00e6` reader twice:
the no-row update and the five-row update both completed with parser success.
The player still did not see the tutorial start. This establishes syntax-level
decoding, **not** retention or gameplay application. The backend still observes
world-message types it does not implement, and the local five-row update is
sent immediately after the no-row update rather than after the roughly
three-second retail transition with intervening client traffic.

The next opt-in tutorial run replaces the two reader execute breakpoints with
a thread-scoped hardware read-watchpoint on the decoded five-row object's
bounded row-count field. It records distinct post-parser code RVAs only, without
payloads, identities or addresses. A read is a candidate consumer access; it
does not prove the activity was applied, and absence of reads does not rule out
consumption on another thread or through a different field. The watched object
must retain its expected vtable and five-row count, or observation ends.

Tutorial mode now selects `private/local-profiles/tutorial-characters.sqlite3`
instead of a new capture-private database on each run. It is separate from
the ordinary `characters.sqlite3`. The dedicated database was seeded once
from the latest completed tutorial capture, preserving the existing source
database. Both original capture databases remain available. The stable local
account ID used by the SDK service makes cross-launch lookup possible; the
next game run must verify resumed-character presentation. Current deletion
handling archives only unfinished characters; completed-character deletion
has not been implemented or tested.

Because a resumed character may not resend the creation-time `0x000c`, an
explicit `--fresh-tutorial-profile` launch option retains the original
capture-private behavior for a new-character consumer trace. This does not
read, replace or delete the dedicated persistent tutorial database. Default
`--tutorial-start` still uses the persistent database.

The 2026-09-28 12:34 fresh-profile run again recorded successful zero-row and
five-row decoding. The row-count read-watchpoint armed on the decoding thread,
but no read site was logged before the game-side trace ended; the backend later
recorded a peer-closed summary. This cannot distinguish cross-thread delivery,
use of a different field, and non-retention. A player reported possibly seeing
a brief UI element, which is not independently confirmed by the logs. The
next trace therefore also records the five-row parser's caller return RVA at
a thread-scoped hardware breakpoint, to identify the immediate dispatch seam
without assuming which field the consumer reads.

That run reached return RVA `0xf8448c` with parser result 1. Static inspection
of the attested runtime text shows the following path in the generic receiver:
the parser result is tested; a virtual acceptance predicate is called (the
`0x00e6` implementation returns true); then the decoded object pointer is
stored in the vector at receiver `+0x20`, and the vector count at `+0x28` is
incremented. The parser-return trace alone does not prove execution reached
the store, however.

The next probe uses thread-scoped hardware execute breakpoints only. After a
five-row decode it follows the parser return, then stops immediately after the
generic vector append at RVA `0xf844ef`. It validates the object identity,
five-row count, stored slot, and incremented queue count without recording raw
addresses or payloads. If confirmed, it reads the receiver function's caller
return from its stack frame and stops there to identify the first upstream
handoff for subsequent consumer analysis. It does not modify responses or the
game and does not claim that a gameplay consumer applied the tutorial.

The 2026-09-28 13:02 fresh-profile capture confirmed the queue append. The
client observed a successful five-row parse, return through `0xf8448c`, and
then a validated store of the same decoded object in the generic receive
vector with its count incremented. The receiver returned through RVA
`0x1a03bb`. Static disassembly places that return in a generic scheduled-job
callback thunk: it calls an indirect function from job state at `+0x40` and
then tail-jumps to scheduler completion code at `0x13dc70`. Consequently this
return identifies the producer's scheduling context, not the downstream
tutorial handler. The local backend still sent `0x00e6` after authenticated
`0x000c` and received no explicit application acknowledgement. The result
narrows the missing step to queue drain/dispatch or later activity-state
application; no gameplay consumer or tutorial start is yet confirmed.

The player confirmed that no tutorial prompt appeared. Reviewing the marked
retail capture's frame order identified a concrete batch-boundary mismatch:
the 129-byte five-row `0x00e6` is followed by 12 other inbound frames and
then an empty `0x0102` in the same capture tick. In the local experiment,
the agent response ended in `0x0102`, but the extra five-row `0x00e6` was
appended *after* it, with no following flush. The observed client code at
`0xf843b6`/`0xf8441e` rotates the accumulated receive vector into a batch
when it sees the special control type. This is consistent with a parsed and
queued, but untransferred, tutorial update; it is not yet proof that adding
the flush starts the tutorial.

The experimental tutorial-only response now adds an empty `0x0102` after
the five-row frame. The trace also watches the vector transfer at `0xf84422`
and checks whether it contains that exact decoded object. This leaves the
normal world-startup and retail paths unchanged and provides a direct test
of the batch-boundary hypothesis on the next local run.

The 2026-09-28 13:17 fresh-profile run confirmed the exact five-row object
left the generic receive queue at the control-message vector transfer
(`ISAC_TUTORIAL_TRACE_FLUSH transferred=1 batch_count=1`). The player observed
the mission appearing, but no objective list or progression. This supports
the batch-boundary diagnosis for mission visibility, while leaving activity
progression unsolved. The local backend still sends only the all-zero five-row
state; it does not implement later world requests or emit the retail follow-up
state in which row 1 becomes active.

In the marked retail trace, that follow-up arrives about 5.014 seconds after
the all-zero five-row state and has a different 145-byte shape (not merely a
one-byte state flip). Two 23-byte outbound `0x014a` requests occur about 1.1
seconds before it. Neither appeared in this local backend log. Their timing is
correlation, not proof that they trigger activation. The immediate research
target is the first row-active `0x00e6` schema and the client/world condition
that causes it; do not replay it on a timer or mark objectives complete.
