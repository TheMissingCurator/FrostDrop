# Shared loopback-only network isolation

Update: [findings-076](findings-076-steam-ipc-bridge.md) adds a verified,
fixed-endpoint Steam IPC exception and corrects the PID/proc mapping. The
original no-host-port configuration below could not complete Steam startup.

Date: 2026-09-26. Replaces the overly strict host-interface preflight in the
initial findings-074 implementation. Host Ethernet, Wi-Fi, Docker and libvirt
interfaces are not altered or required to be down.

## What changed

`tools/isac-netns.py` creates an unprivileged user/network namespace using
Bubblewrap. Only its own loopback interface exists; no veth, bridge attachment,
forwarder or outside route is created. Backend services run there, and
`steam-login-handoff-wrapper.sh --sdk-local` joins that same user/network
namespace before executing the Steam/Proton command. Both sides still use
127.0.0.1, now referring to private loopback rather than the host.

The backend supervisor also uses a private PID namespace so its remaining
descendants are removed if the supervisor exits unexpectedly. The game joins
only user/network namespaces; stopping the backend does not terminate the game
or move it back onto the host network. Exit the game before ending the capture.

This uses Linux's separate network stacks and namespace-join permissions;
see [network_namespaces(7)](https://www.man7.org/linux/man-pages/man7/network_namespaces.7.html)
and [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html).

## Fail-closed launch and scope

- State is kept in owner-only `private/network-isolation/`. One capture holds
  its lock; another cannot replace an active session. Missing/stale state fails.
- Joining opens both namespace handles before switching, validates their inode
  identities against the owner record, and checks the owner UID. No fallback to
  a normal launch if creating/joining/verifying isolation fails.
- Both sides verify loopback-only interfaces; IPv4 and IPv6 negative controls
  require unreachable-network errors for documentation-only external addresses.
- Launcher clears proxy environment settings and closes extra inherited file
  descriptors so inherited host sockets cannot supply an accidental IP path.
  Socket-based standard streams are refused.
- Game launches reject Wine/game processes using the **same prefix** outside the
  namespace. The initial all-Wine guard blocked Vinegar's StudioMCP at 16:48:08;
  it was corrected to compare directory device/inode identities. The launch
  target follows Proton's `STEAM_COMPAT_DATA_PATH/pfx` convention (falling back
  to an explicit WINEPREFIX for direct Wine). Running processes are identified
  through their WINEPREFIX and process filesystem root, including container
  paths and aliases. Positively identified unrelated prefixes are ignored.
  Unidentifiable prefixes still fail closed. No process is killed. Do not
  concurrently launch another Wine instance using the Division prefix.
- The environment markers merely control recursion: they cannot replace the
  actual namespace check. A forged marker outside the namespace still fails.
- The host remains online. Existing files, devices and desktop/Steam IPC remain
  accessible for Proton compatibility. This is **IP network isolation, not a
  sandbox against malicious code or a guarantee against a host IPC broker**.
  It is also not a read-only or separate copy of the game/prefix.
- Other capture modes retain their existing behavior. This automatic isolation
  is currently wired only into `sdk-local` plus its matching Steam wrapper.

## Usage

Keep the same runner command and launch options from findings-074, but **do not
disable host networking**. Close Division and processes using its Wine prefix
before the game launch; unrelated apps such as Vinegar/Studio can remain open.
No sudo or host firewall changes are needed.

```sh
./tools/run-offline-integration.sh \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  "/path/to/SteamLibrary/steamapps/compatdata/365590" \
  sdk-local
```

Steam launch options:

```text
"/path/to/ProjectISAC/tools/steam-login-handoff-wrapper.sh" --sdk-local %command%
```

Wait for `ISAC_NETNS_READY` and the services-ready prompt. Press Enter to begin
capture, then launch through Steam. Keep the runner alive while testing. Exit
the game at the first stable result and finish the capture prompt.

The SDK/client/backend logs remain captured. This mode skips the old
`sudo tcpdump` step, which is not appropriate inside this unprivileged namespace.
`offline-integration.txt` records the backend namespace and this capture limit.
Other modes' packet capture is unchanged. No launch-options reminder was added
to the runner. No new DLL build/install is required for this change.

## Verification and remaining test

Real-kernel tests established: private loopback client/server exchange across
separately launched processes; host loopback cannot reach the private listener;
the private peer cannot reach a host listener; external IPv4/IPv6 destinations
are unreachable; simultaneous-run refusal; host-side check refusal; stale-join
refusal; normal and terminated-supervisor cleanup.

The installed SteamLinuxRuntime_4 entry point was also exercised with a tiny
Python loopback client: it retained the namespace identity and reached the
isolated listener. This is stronger than a standalone namespace test, but is
not an actual Division/Proton game launch. That remains the next integration
test, together with the SDK session/config acceptance work from findings-074.

Final regression run: **208 tests passed**, including both real-kernel namespace
tests and the installed Steam-runtime check. Changed shell scripts passed
`bash -n`. The EOF smoke run exited at its unanswered prompt as expected and
removed its session record; no game was launched or left running by these tests.

Prefix-guard correction verification: **214 tests passed**, including the
real `join-game` path with Division's actual compatdata directory and a dummy
loopback client (no Wine/game launch or prefix modification). Unit coverage
includes unrelated prefixes, same-prefix conflicts, unreadable identities,
symlink aliases, process-root lookup and Proton/Wine environment precedence.

Tests are opt-in for actual kernel namespace creation:

```sh
ISAC_TEST_NETNS=1 python3 -m unittest discover -s tests
```

Set `ISAC_TEST_STEAM_RUNTIME` to an installed runtime `_v2-entry-point` to also
exercise Steam's container layer. Tests use temporary directories and no game
launch. The real `sdk-local` runner also reached all services-ready messages
inside isolation in an EOF-at-prompt smoke test, without starting a capture.
