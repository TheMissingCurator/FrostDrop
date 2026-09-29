# Combined endpoint-selection and resolver probe

Date: 2026-09-26

## Baseline comparison

Both `20260926-015048-offline-tctd-main-channels-linux` (network on) and
`20260926-015244-offline-tctd-main-channels-linux` (network off) establish:

- Local certificate bootstrap and accepted directory parsing.
- Constructor version 556 on 55002 and all three local ping/pong pairs,
  followed by the client's final timing summary.
- No observed constructor/connect/listener exchange on 55001.

The connected run has an external established HTTPS connection attributed to
the game and multiple HTTP connection attempts. The disconnected run's
physical interfaces are down at capture end, unrelated resolver calls fail,
and the connection snapshot contains only loopback sockets. The packet filter
only covers TCP 27015/51000/55001/55002; it is not an all-egress audit.

Therefore the latency responder works without live-service assistance, but
the main-channel responder is still untested by the game. External HTTP
requests may be prerequisites or unrelated services; failure correlation does
not establish causation.

## Static selector evidence

Runtime text SHA-256 remains
`dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74`.

The sole direct call to main constructor 0x2f500 is at 0x9c58f, within selector
0x9c3e0. That constructor calls transport constructor 0x22412c0 with protocol
2056 at 0x2f756.

Selector 0x9c3e0:

- Calls the manager's candidate collection count method at 0x9c440. At the
  following instruction 0x9c443, EAX is the total count, R12D the requested
  selector kind, and R13 the manager. **This count precedes filtering.**
- Filters candidate+0x5c against the requested kind, calls 0x58c20 to reject
  some candidates, and either reuses a connection or collects eligible entries
  for randomized choice.
- At 0x9c5e1, RBX is the chosen entry or null. A readable chosen entry supplies
  port at +0x58, selector kind at +0x5c, and connection pointer at +0x60.
  A non-null connection pointer is not proof that TCP/TLS/login succeeded.
- The original caller return address is at RSP+0xb8 at both checkpoints.
  The manager's +0x38 state is recorded numerically without inventing names.
  Existing callers gate selector calls on state 2 in several paths.

Direct callers include 0x5c14d, 0x5c350, 0x5c5b8, 0x699ea, 0x69e62, 0x933e4.
Selector kinds must not automatically be equated to directory entry kinds.

## Implementation

The new `tctd-leads` mode retains the exact combined local backend from
findings 063. It changes only the observational probe:

- DR1: existing transport constructor, now reports all ports/versions and
  the immediate caller RVA instead of filtering only our expected ports.
- DR2: selector candidate count, requested kind and manager state.
- DR3: selector result, chosen port/kind and presence of a connection object.
- DR0 remains reserved for the existing local certificate acceptance hook.

The two old directory parser checkpoints are replaced, not added to the
hardware-slot set. All selected instruction signatures must match before
enabling the probe. The new checkpoints are read-only, check memory ranges,
preserve last-error state and resume execution with RF. Each site has a
64-record public-log limit. Old wrappers retain the old checkpoint set.

Both existing ANSI and wide resolver hooks additionally record bounded
hostname/service strings, API, attempt ID, result, redirect flag, thread and
tick to `private/startup-leads-XXXXXXXX/resolvers.tsv`. This correlates with
the existing public `TRANSPORT_RESOLVE` attempt IDs and caller RVAs. The
wrapper creates a fresh 0700 directory and empty 0600 file; native code only
opens that existing file, refuses to overwrite a nonempty capture, and limits
it to 128 records of less than 384 bytes. Public logs never contain the names.

Names must be printable hostname-like ASCII shorter than 128 bytes; null,
long, unreadable, non-ASCII or URL-like values are represented as `-`. These
records are captured after the resolver returns. They identify destinations,
not HTTP paths, response bodies, completion status or application semantics.
No additional endpoints are redirected or contacted by the probe.

## Run and interpretation

Use `tools/run-offline-startup-leads.sh GAME_DIRECTORY COMPATDATA_DIRECTORY`
and Steam options:

```text
"/path/to/ProjectISAC/tools/steam-startup-leads-wrapper.sh" %command%
```

Networking off; start capture with Enter before launching, attempt loading
once, stop at a stable menu/error and finish capture. The script does not print
launch-option reminders. Public evidence includes `STARTUP_LEADS_*` in the
stack log and `tctd-echo-checkpoints.txt`; private resolver files stay private.

Interpret the same run in this order:

1. `STARTUP_LEADS_READY` confirms the new signatures and private sink worked.
2. Selector count/result logs distinguish no candidates, no eligible choice,
   or an actual selection. A constructor log then checks the requested port
   and protocol. If selector checkpoints never fire, focus upstream rather
   than changing a response the client never requested.
3. Match private resolver attempt IDs to public caller RVAs to identify the
   parallel startup destinations. Do not assume they block selection merely
   because DNS fails offline.

No new login/world behavior or HTTP emulation is enabled in this test.

## Verification

173 Python backend regression tests pass. The Wine synthetic checkpoint test
passes for signature rejection, old/new slot configurations, DR0 preservation,
selected/null/unreadable entries, constructor coverage beyond expected ports,
resume/last-error state, ANSI/wide resolver hooks, private output initialization,
URL/newline rejection and the record cap. Four allocation analyzer tests also
pass. Shell syntax checks and the full-loader Wine transport startup smoke
test pass. Retail acceptance requires the next capture.
