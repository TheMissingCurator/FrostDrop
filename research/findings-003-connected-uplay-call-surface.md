# Finding 003: connected startup Uplay call surface

Date: 2026-09-21

Evidence: `evidence/20260921-233516-uplay-probe-connected-linux`

## Result

The forwarding probe did not alter observable startup behavior. Division
reached its normal connected menu while every call continued to Ubisoft's
original loader.

The game touched 21 of the loader's 89 exports during this capture. This is a
menu-reached call set, not yet proof that all 21 calls are required to start.

## Process split and first-call order

The initial Steam-launched process loaded the probe and called only:

1. `UPLAY_Start`

That process then handed control to Ubisoft Connect. The Proton trace shows:

1. Initial `thedivision.exe`
2. `UbisoftGameLauncher.exe`
3. `upc.exe`
4. `UbisoftGameLauncher64.exe`
5. Second, full `thedivision.exe`

The second game process called these functions in first-observed order:

1. `UPLAY_Start`
2. `UPLAY_USER_IsInOfflineMode`
3. `UPLAY_INSTALLER_Init`
4. `UPLAY_PARTY_Init`
5. `UPLAY_FRIENDS_Init`
6. `UPLAY_USER_IsOwned`
7. `UPLAY_WIN_GetRewards`
8. `UPLAY_Update`
9. `UPLAY_GetNextEvent`
10. `UPLAY_HasOverlappedOperationCompleted`
11. `UPLAY_USER_GetTicketUtf8`
12. `UPLAY_USER_IsConnected`
13. `UPLAY_USER_GetAccountIdUtf8`
14. `UPLAY_USER_GetNameUtf8`
15. `UPLAY_AVATAR_Get`
16. `UPLAY_GetOverlappedOperationResult`
17. `UPLAY_FRIENDS_GetFriendList`
18. `UPLAY_PARTY_IsInParty`
19. `UPLAY_AVATAR_Release`
20. `UPLAY_ACH_GetAchievements`
21. `UPLAY_PRESENCE_SetPresence`

## Functional groups

| Group | Observed functions |
| --- | --- |
| Lifecycle/event pump | `UPLAY_Start`, `UPLAY_Update`, `UPLAY_GetNextEvent` |
| Async operations | `UPLAY_HasOverlappedOperationCompleted`, `UPLAY_GetOverlappedOperationResult` |
| Local identity/session | offline mode, ownership, connection, ticket, account ID, name |
| Social | friends init/list, party init/state, presence, avatar get/release |
| Entitlements/progression | rewards and achievements reads |
| Installer | installer init only |

No Uplay save, overlay, store, metadata, CD-key, hardware-score, consumable, or
session-mutation function was observed. In particular, none of the eleven
`UPLAY_SAVE_*` exports appeared. This supports treating character/world state
as a separate game-service problem rather than a Uplay cloud-save dependency,
though a longer gameplay capture is needed before that is conclusive.

## Next discriminator

Run the same probe with network access removed. Comparing the two per-capture
call sets will show whether the first process stops inside `UPLAY_Start`, and
whether Ubisoft Connect ever launches the second game process. That comparison
comes before replacing any return behavior.
