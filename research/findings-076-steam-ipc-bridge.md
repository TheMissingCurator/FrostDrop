# Local Steam IPC bridge and capture-process fix

Date: 2026-09-26. Fixes following the 16:52:58 isolated startup attempt.

## Failure and verified endpoint

Steam's console recorded `ISAC_NETNS_JOINED`, and the process timeline saw
Division start. Proton then logged `steamclient_init_registry Failed to connect
to Steam`. Neither ISAC DLL log advanced. This was before the local SDK backend
response path, not evidence of a session-schema failure.

A small native diagnostic loaded the installed `linux64/steamclient.so` and
opened/released a Steam pipe. It observed a connection to **127.0.0.1:57343**;
the pipe succeeded on the host. The host socket table confirmed that listener
was owned by the user's `steam` process. No packet payloads or credentials were
logged. The diagnostic now also connects/releases the local Steam user handle
and prints only success booleans, not account identifiers or authentication data.

The original shared-network tests exercised the container and local sockets,
but not the actual Steam-client handshake. That distinction mattered here.

## Fixed, narrow relay

`tools/steam_ipc_relay.py` provides two halves:

1. Namespace-side TCP listener on 127.0.0.1:57343, forwarding to an owner-only
   filesystem Unix socket in the private isolation state directory.
2. Host-side Unix listener, connecting only to host 127.0.0.1:57343.

The host side validates Steam's PID, UID, executable name, process start time,
listener address/state and socket inode ownership. Ownership is checked again
for each new connection. Steam restarting or losing that listener refuses new
connections; restart the runner in that case. There is no client-selectable
destination, general TCP proxy, host route, veth or host firewall change.

The relay has a 16-connection bound and 64 KiB per-direction buffers, handles
half-closes and backpressure, and closes its endpoints during runner cleanup.
It does not interpret or log the relayed bytes. The fixed endpoint is enabled
by `isac-netns.py --steam-ipc run`; `sdk-local` now supplies this automatically.
Generic namespace runs and other capture modes do not gain this exception.

**Scope:** direct external IP connections from the game remain blocked. Steam
IPC is an intentional connection to the host Steam client, which can itself be
online. The relay does not filter Steam API methods and is not proof that no
Steam-mediated online activity is possible. This restores Steam integration;
it does not replace Steam or establish a completely air-gapped game.

## Separate proc/capture bug

The backend's private PID namespace was incorrectly paired with the host's
`/proc`. An empty-run check reproduced `fatal library error, lookup self`.
The supervisor now mounts matching `/proc` and keeps a separate read-only host
proc view under its private state directory for host PID identity and capture
metadata. `capture-process-list.py` reads that view for process snapshots.
The game still joins only the user/network namespaces, not the backend PID
namespace. This distinction is also reflected in the Steam handshake test.

Backend logs are retained when capture exits early. Missing client logs now
produce an explicit no-handoff-evidence message instead of a Python traceback.

## Verification

**219 tests passed**, with real namespace tests, Division-prefix guard tests,
installed SteamLinuxRuntime_4 checks and the new actual Steam handshake enabled.
The handshake used a separate `join-game` process, just like the Steam wrapper:
both pipe creation and local user connection succeeded through the installed
Steam runtime. Simultaneous controls verified that another host loopback
listener and external IPv4/IPv6 destinations remained unreachable.

Additional tests cover listener ownership/address rejection, changed Steam
process identity, a transfer larger than relay buffers, half-close/reverse
reply behavior, correct PID/proc mapping, and host process metadata parsing.

Automated empty captures `20260926-171042-offline-sdk-local-linux` and
`20260926-171247-offline-sdk-local-linux` launched **no game**. They are harness
tests, not new gameplay/login evidence. The latter verifies clean completion
and saved backend logs with no client instrumentation present.

No DLL build or installation changed. Use the same `sdk-local` runner command
and `--sdk-local` Steam launch options. Keep host networking on and Steam open.
The next user game launch still needs to establish actual Division startup and
local SDK session/configuration acceptance; the tests do not prove world loading.
