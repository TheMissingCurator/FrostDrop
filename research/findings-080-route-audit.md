# Independent, prefix-scoped route inventory

Date: 2026-09-26. Implements the user's request to discover unreplaced routes
after dropping automatic network isolation.

## Why independent observation

The SDK guard currently stops the game before the in-DLL socket hooks are
installed. Expanding only those hooks would miss this startup period. The new
`tools/audit-game-routes.py` observer operates independently from the DLL and
starts before the capture script prompts for game launch. It changes no page
protections, game code, socket calls, routing, interfaces or firewall rules.
It requires neither sudo, ptrace nor a DLL reinstall.

## Scope and attribution

Only same-user candidate Wine/Windows/Proton-runtime processes are inspected.
Their Wine prefix is checked against the selected compatdata `pfx` using the
directory's device/inode, resolving aliases through `/proc/PID/root`. The
process environment is bounded and used only to select WINEPREFIX or
STEAM_COMPAT_DATA_PATH; no environment contents or command lines are logged.
Unrelated prefixes (including the separate Vinegar Studio installation) are
excluded. Unknown/unreadable prefixes are counted as inspection errors rather
than guessed to belong to Division.

The observer reads TCP/TCP6/UDP/UDP6 socket tables and attributes rows by the
socket inodes actually held in that process's file descriptors. This matters
because `/proc/PID/net` is namespace-wide, not a list owned exclusively by PID;
see the [Linux proc_pid_net manual](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)
and [kernel TCP-table documentation](https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt).
Reading a namespace-wide table alone would incorrectly include unrelated apps.

Poll interval is 100 ms. New peer/state observations are deduplicated by PID,
process start time, socket inode, protocol, destination, port and state. PID
reuse and transitions such as SYN-SENT to ESTABLISHED are distinguishable.
Logging is bounded to 4096 events, with an explicit limit record/status. These
observations are not syscall invocation counts or proof of successful game auth.

## Classification and files

- `local-backend-port`: loopback peer on 27015/51000/55000/55001/55002/55003.
  This is a port classification, not proof the service accepted a protocol.
- `local-steam-ipc-port`: loopback peer on 57343, not an ownership revalidation.
- `other-loopback`: another local peer.
- `non-loopback-candidate`: LAN, link-local or other non-loopback peer. These
  are candidates to investigate, not established Ubisoft service identities.

IPv4, IPv6 and IPv4-mapped IPv6 are supported. Listening TCP sockets and
unspecified/zero-port peers are excluded. Metadata includes observation time,
PID, sanitized process name, destination IP/port, protocol and observed state.
There are no payloads, headers, URLs, tickets, account IDs or TLS interception.
The observer opens no network sockets and performs no DNS/reverse-DNS queries.

Files in each SDK capture:

- `route-audit.jsonl`: readiness, new socket/state observations, limit status
  and finished marker.
- `route-audit-summary.json`: grouped endpoints, observed states/processes,
  event/sample counts, inspection-error counters and limitations.
- `route-audit-summary.txt`: human-readable inventory.
- `route-audit-errors.log`: generic helper startup/runtime error types.

`run-offline-integration.sh ... sdk-local` enables the observer automatically.
Other capture modes can opt in with `ISAC_ROUTE_AUDIT=1` and a compatdata path.
SDK packet capture remains off. Normal completion and early capture failure
stop/wait for the observer; summary files are retained. If it cannot start,
capture continues with a warning, not a new network-launch gate. Summary.txt
states whether the audit summary is available.

## Coverage limits

This is an inventory of sampled, attributable peer sockets, **not** all network
attempts or API calls. Short-lived/instant-failure sockets may be missed.
Unconnected UDP `sendto` traffic, raw sockets, delegated host Steam activity and
launcher activity outside the selected prefix are not covered. Prefix/fd
visibility restrictions can also hide sockets. Error counters and limit status
must be considered; an empty inventory does not prove there was no egress.
No hostnames or HTTP route schemas are reconstructed from IPs. An IP may be
shared among services; calling it a particular Ubisoft endpoint requires more
evidence. The audit discovers leads without claiming backend independence.

## Verification and next run

Thirteen targeted tests passed, covering namespace-table inode filtering,
unrelated app/prefix exclusion, alias/fallback prefix identity, IPv4/IPv6/mapped
IPv6 decoding, dedup/state changes/PID reuse, listener/unconnected-UDP exclusion,
event limits, no networking/DNS calls, absence of seeded secrets in outputs,
unidentified prefixes, CLI termination, and empty-report wording. The actual
capture shell/helper lifecycle is tested in a disposable project on both normal
completion and EOF failure. A real local-only socket subprocess confirms
attribution through the kernel's /proc tables without launching Division.
Shell syntax checks and Python compilation pass.
Full Python regression: 236 discovered, 231 passed, five opt-in tests skipped.

Run the same `sdk-local` command and unchanged Steam launch options, with Steam
and host networking on. Finish after the first error/exit. Inspect
`route-audit-summary.txt` alongside the SDK guard log. This feature does not fix
the current SDK memory-protection failure or implement more backend responses.
