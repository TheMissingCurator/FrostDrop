# Finding 052: Uplay caller contracts and first standalone shim

Date: 2026-09-25

Evidence: `evidence/20260925-033857-uplay-abi-callers-connected-linux`

The second connected ABI capture produced 90 matched call/return pairs, 38
unique caller-code windows, and no probe errors. Every code window began at an
exact runtime-unwind function boundary; no fallback window was needed.

The code windows resolve the important ambiguity in the earlier register-shape
capture:

- `UPLAY_Start` receives product ID `0x72b` in `ECX`, zero in `EDX`, and its
  32-bit status return is stored by the game. The full process observes status
  zero.
- ticket, account-ID, and name getters are called with no arguments and their
  returned UTF-8 pointers are copied immediately.
- `UPLAY_USER_IsOwned` receives one 32-bit content ID and its `EAX` Boolean is
  tested immediately.
- `UPLAY_USER_IsConnected` and `UPLAY_USER_IsInOfflineMode` take no arguments;
  the former is consumed as `AL`, the latter as `EAX`.
- `UPLAY_Update` takes no arguments and must return a positive 32-bit value.
- `UPLAY_USER_SetGameSession` consumes a stack descriptor in `RDX` and a
  32-bit value in `R8D`; its `EAX` result is retained.
- `UPLAY_WIN_RefreshActions` is called with no prepared arguments and its
  return value is ignored at the observed site.

These contracts were used to build `dist/uplay_local/uplay_r1_loader64.dll`,
the first clean standalone local Uplay compatibility layer. It exports all 89
retail names and ordinals, provides a Project ISAC identity, and never loads
the retained Ubisoft DLL. Unsupported operations return zero without writing
unknown output structures. The existing local-backend bridge is compiled into
the DLL so world-replay experiments remain available.

An isolated Wine smoke test passed with no retail forwarding DLL present. The
next validation is a real game launch with the standalone shim installed,
checking whether the initial Division process stays in-process rather than
handing control to Ubisoft Connect and recording the first unsupported export
or game-side failure boundary.
