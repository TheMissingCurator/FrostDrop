# Finding 004: disconnected launch boundary

Date: 2026-09-21

Evidence: `evidence/20260921-234410-uplay-probe-disconnected-linux`

## Result

With all network interfaces disconnected, the initial Steam-launched game
process loaded the forwarding probe and made exactly one Uplay API call:

1. `UPLAY_Start`

It then launched `UbisoftGameLauncher.exe`. The following processes seen in a
connected launch never appeared:

- `upc.exe`
- `UbisoftGameLauncher64.exe`
- the second/full `thedivision.exe`

The Ubisoft game-starter log recorded that it failed to receive the local
Steam account response, with error code 3 and `IOFailure: false`. Ubisoft
Connect's main launcher log was not modified during the attempt. Its saved
configuration also still had offline mode disabled.

## Interpretation

This is a Steam-to-Ubisoft ownership/session handoff failure, before Division's
own online backend is contacted. It establishes what must eventually be
replaced for a completely infrastructure-independent launch, but it is not the
current offline-gameplay boundary.

Backend research can continue using the legitimate connected launcher as a
bootstrap. Launcher replacement is deferred until the Division-specific
session/world protocol is understood or the retail launch path blocks further
experiments.
