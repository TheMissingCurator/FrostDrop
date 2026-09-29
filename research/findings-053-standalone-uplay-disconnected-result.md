# Finding 053: standalone Uplay launch succeeds disconnected

Date: 2026-09-25

Evidence: `evidence/20260925-040021-uplay-local-disconnected-linux`

The first real-game run with the standalone Project ISAC Uplay compatibility
DLL succeeded while every physical network interface was down. One
`thedivision.exe` process appeared and remained alive through the 59-second
capture. No `UbisoftGameLauncher.exe`, `UbisoftGameLauncher64.exe`, `upc.exe`,
or other Ubisoft/Uplay process appeared in any process snapshot.

This differs decisively from the earlier retail disconnected boundary. The
retail path stopped after `UPLAY_Start` and attempted a Ubisoft launcher
handoff; the local path continued in the same Division process through:

1. startup and offline-state initialization;
2. installer, party, and friends initialization;
3. entitlement and rewards queries;
4. connection and event-pump initialization;
5. local ticket, account-ID, and name retrieval;
6. avatar, friends-list, and party-state queries; and
7. presence publication.

Unsupported rewards, error/event, asynchronous, avatar, friends-list, and
party-state exports returned zero without terminating startup. This validates
the fail-closed behavior for the first standalone stage.

The only socket attributed to Division at capture end was an established
loopback connection from `127.0.0.1:32876` to `127.0.0.1:57343`. There were no
remote sockets, and `wlan0`, `wlan1`, and the wired interface were down. The
capture therefore proves infrastructure-independent Division startup for this
installation; it does not yet prove a complete local game-backend login or
world bootstrap.

The next integration test should retain the standalone Uplay DLL, start the
Project ISAC bootstrap server, and enable the existing loopback bridge while
remaining disconnected. Its expected purpose is to identify the first
Division-backend dependency that still assumes a genuine retail transport
delivery, especially the reader/source association currently used by world
replay.
