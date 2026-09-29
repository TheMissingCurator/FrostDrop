# Finding 051: first Uplay ABI capture result

Date: 2026-09-25

Evidence: `evidence/20260925-032443-uplay-abi-connected-linux`

The connected startup capture produced 89 matched ABI call/return records from
two Division processes and no `UPLAY_ABI_ERROR`. The game remained stable, so
the return trampoline preserves the original call path in this environment.

The capture establishes several useful compatibility-layer behaviors:

- `UPLAY_Start` is called from the same game RVA with product ID `0x72b`. The
  short-lived first process returned `2`; the full process returned `0`.
- `UPLAY_USER_IsOwned` received the expected product/content IDs and returned
  true for every sampled call.
- `UPLAY_USER_IsInOfflineMode` returned false during the connected reference
  run.
- `UPLAY_USER_GetTicketUtf8`, `UPLAY_USER_GetAccountIdUtf8`, and
  `UPLAY_USER_GetNameUtf8` returned UTF-8 pointers with lengths 599, 36, and 9
  respectively. The bytes themselves were intentionally not captured.
- `UPLAY_Update` returned true for all 16 bounded samples.
- `UPLAY_USER_SetGameSession` and `UPLAY_WIN_RefreshActions` appeared later in
  the ordinary export log and must be part of the standalone shim surface.

The apparent eight-slot argument records are deliberately not treated as
function signatures. Windows x64 volatile registers and caller stack slots can
contain unrelated residual values when an export has fewer arguments. Runtime
caller-code windows were added to the next probe revision to recover actual
argument setup and post-call handling at each unique game call site.
