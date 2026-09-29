# Finding 001: Steam-to-Ubisoft launcher boundary

Date: 2026-09-21

## Environment

- Linux: CachyOS, kernel 7.2.3
- Steam AppID: 365590
- Ubisoft product ID observed in launcher log: 1835
- Client launch argument: `-uplay_steam_mode`

## Connected startup

Observed process progression:

1. Initial `thedivision.exe`
2. `UbisoftGameLauncher.exe`
3. `upc.exe` and Ubisoft services/web processes
4. `UbisoftGameLauncher64.exe`
5. Second/full `thedivision.exe`

The Ubisoft launcher reports a Steam ticket login and the game connects to the
local Ubisoft Connect API.

## Disconnected startup

Observed process progression:

1. Initial `thedivision.exe` starts for approximately one second
2. `UbisoftGameLauncher.exe` starts
3. `upc.exe`, `UbisoftGameLauncher64.exe`, and the second/full game process do
   not start

The Ubisoft `game_starter_log.txt` reports that it failed to receive the local
Steam response for the account with error code 3. The error explicitly reports
that this was not an I/O failure.

## Current interpretation

The first offline boundary is the Steam-to-Ubisoft account/ticket handoff in
the launcher bootstrap. It occurs before Division's own online authentication
and world/session services can be studied.

Ubisoft Connect's local `settings.yaml` currently contains `offline: false`.
The next controlled test is to enable this supported launcher preference,
close both launchers, disconnect networking, and repeat the capture.
