# Finding 002: local Uplay API surface

Date: 2026-09-21

- Division ships `uplay_r1_loader64.dll` beside `thedivision.exe`.
- The loader exports 89 named `UPLAY_*` functions.
- Every one of those 89 functions is also exported by Ubisoft Connect's
  installed `uplay_r164.dll`.
- The installed API exports additional functions not required by this older
  game-facing loader.
- The loader imports only `KERNEL32.dll` and `ADVAPI32.dll`, consistent with a
  lightweight dynamic loader rather than a complete online client.
- Account-facing exports include ownership, account ID, display name, online
  and offline state, and an opaque UTF-8 ticket.

This supports implementing a minimal clean-room game-facing API rather than
recreating the Ubisoft Connect user interface.
