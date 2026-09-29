# Proposed architecture

## Principle

Do not reproduce the Ubisoft Connect UI or impersonate Ubisoft's online
identity service. Replace only the local interfaces required to launch a
legitimately installed client, and use project-local identities and tickets
for the replacement game server.

## Development order

During backend research, the original Steam and Ubisoft Connect launch path
may be used normally. The first implementation target is the Division game
backend after the full game process is running. The local Uplay compatibility
API and launcher become required only for the final zero-Ubisoft-infrastructure
target, or earlier if the retail launch path prevents backend experiments.

This distinguishes two meanings that were previously conflated:

- **Offline gameplay:** character, session, world, and simulation services run
  locally and do not depend on Ubisoft's Division servers.
- **Infrastructure-independent launch:** the game also starts without Ubisoft
  Connect or Ubisoft account services.

The first is the current priority. The second remains part of the preservation
design but is not on the critical path yet.

## Components

### 1. ISAC launcher

- Locates a user-supplied installation.
- Checks the known executable/DLL hashes for the selected game build.
- Optionally checks that Steam's AppID 365590 manifest exists.
- Starts the client with an isolated Project ISAC profile.
- Never stores Ubisoft credentials.

These checks establish that expected original files are present. They are not
cryptographic proof of ownership and should not be described as such.

### 2. Local Uplay compatibility API

A clean-room replacement for the game-directory `uplay_r1_loader64.dll` API.
The installed client currently exposes 89 relevant functions. Likely minimum
startup functions include:

- `UPLAY_Start`
- `UPLAY_Update`
- `UPLAY_Quit`
- `UPLAY_GetLastError`
- `UPLAY_GetNextEvent` / `UPLAY_PeekNextEvent`
- `UPLAY_USER_IsOwned`
- `UPLAY_USER_IsConnected`
- `UPLAY_USER_IsInOfflineMode`
- `UPLAY_USER_GetAccountIdUtf8`
- `UPLAY_USER_GetNameUtf8`
- `UPLAY_USER_GetTicketUtf8`
- installer/language initialization calls

Save, party, achievement, overlay, and store APIs can initially report that
their features are unavailable. The first standalone implementation now covers
the measured startup and identity contracts. Asynchronous result and event
structures still require measurement before those features can be implemented
safely; see `docs/uplay-local.md`.

### 3. Local identity issuer

- Creates a project-local UUID and display name.
- Issues a short-lived local session ticket.
- Does not reuse, forge, or transmit a Ubisoft authentication ticket.
- In co-op, the replacement server validates Project ISAC tickets.

Whether the retail client treats the ticket as opaque or validates its format
locally remains an open research question.

### 4. Division compatibility server

Implements the game's own authentication/session/world boundary after the
local Uplay API is satisfied. This is separate from Ubisoft Connect emulation.

## Ownership policy

An unofficial offline launcher cannot authoritatively prove ownership to
Ubisoft while disconnected. Project ISAC should instead:

- require users to provide their own installed assets;
- distribute no Ubisoft binaries, assets, credentials, or keys;
- validate supported retail file hashes and the local Steam manifest;
- clearly state that those checks discourage accidental misuse but are not
  secure DRM.

Adding a new always-online ownership server would undermine the preservation
goal and create an unnecessary credential/security service.

## Immediate research milestone

With the original launcher/account bridge still active, map the full game
process's DNS lookups, remote endpoints, connection order, and protocol
boundaries from menu through character selection and world entry. Separate
ordinary HTTP/CDN and Ubisoft Connect traffic from the dedicated Division
session/world services before attempting redirection or response emulation.
