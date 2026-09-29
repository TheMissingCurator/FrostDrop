# Host-network launch without automatic isolation

Date: 2026-09-26. Requested by the user after the failed mapped-page candidate.

## Latest capture and scope

`evidence/20260926-174356-offline-sdk-local-linux` logged
`stage=protect-write,win32_error=5,memory_type=0x1000000,allocation_protect=0x80,write_protect=0x8,modified=0`.
This is `MEM_IMAGE`, original allocation `PAGE_EXECUTE_WRITECOPY`, currently
`PAGE_READONLY`. The copy-on-write attempt also failed before URL modification.
The guard deliberately terminated. The relationship between isolation and
this access-denied failure is not established.

The user explicitly requested dropping network isolation and the network check.
This change applies to launch orchestration, not to the DLL's SDK guard or
backend protocol/schema implementation.

## Changes

- `run-offline-integration.sh ... sdk-local` starts services normally on host
  loopback. No automatic `isac-netns.py run/check`, interface preflight, bwrap
  container or Steam IPC relay. Existing game-stopped, file/hash and port-conflict
  guards remain.
- `steam-login-handoff-wrapper.sh --sdk-local %command%` executes the Steam
  command normally, with the same local backend/SDK flags and Proton logging.
  No namespace joining/checking. It still clears inherited ISAC flags before
  setting the selected probe's flags.
- SDK capture stays log-only: dropping isolation does not enable sudo/tcpdump
  or plaintext SDK payload capture.
- Runner messages and `offline-integration.txt` explicitly record that external
  connections are not blocked and unreplaced routes may contact Ubisoft. They
  no longer claim a private loopback-only namespace or a Steam-only exception.
- Historical isolation tools/tests/evidence are retained, not deleted. They
  are no longer used automatically by this runner/wrapper.

The CLI and Steam launch option are unchanged:

```sh
./tools/run-offline-integration.sh \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  "/path/to/SteamLibrary/steamapps/compatdata/365590" \
  sdk-local
```

Steam launch option (provided here, not as a scripted launch reminder):

```text
"/path/to/ProjectISAC/tools/steam-login-handoff-wrapper.sh" --sdk-local %command%
```

Start a fresh runner in the normal desktop terminal with the game stopped.
Keep Steam and networking on. No DLL reinstall is needed for this script change.
A game run is still needed to determine whether the SDK protection failure
persists outside the earlier isolation path. It is not safe to interpret a
successful login/world load alone as evidence of independent local gameplay.

## Verification

Wrapper tests exercise SDK flags, sweep selection, quoted arguments, stale
namespace-marker clearing and launching despite a deliberately failing Python
helper in PATH. An actual child reports the same network namespace as its parent.
A runner test reaches the expected missing-game-file guard without invoking
the helper; it starts no services or game. Source assertions cover removal of
both launch-time network gates and obsolete isolation claims. Shell syntax
checks pass. No retail game launch is performed by these tests.
Full Python regression: 223 discovered, 218 passed, five opt-in tests skipped.
Installed DLL still matches the built candidate; no DLL changes were required.
