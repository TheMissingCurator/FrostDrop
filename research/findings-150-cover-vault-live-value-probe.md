# Finding 150: a direct runtime value probe for `CoverVaultIsAllowed`

Date: 2026-09-29. This note describes instrumentation, **not a measured result**.
The value requires a fresh retail run. The probe is read-only and does not
alter game instructions, actor state, network requests, or server responses.

The verified client registers `CoverVaultIsAllowed` as an entry of
`RClient_GameActionStateEnum`. The registry ID is at descriptor RVA
`0x47cdb88 + 8`. The runtime action-state getter at RVA `0xf14000` executes
`movslq (%rdx), %rax; mov 0x4c(%rcx,%rax,4), %eax; ret`: `RDX` points to the
enum ID; `RCX` is the action-state owner; the 32-bit entry is the live value.
The `Client:RClient_SetTrackingGameActionState` evaluation at `0x19be5b0`
obtains a client-local owner and calls that getter at `0x19be5f5`. Its
post-owner-resolution site at `0x19be5e4` supplies a player-owner candidate.

The dedicated retail probe observes the getter and owner-resolution site. It
logs the registered index (event kind 10), direct reads of that index (11),
local owner candidate selection (12), snapshots at Numpad 8 vault markers
(13), and sampled changes to the local candidate (14). Owner addresses never
leave the process; the file contains only per-run owner ordinals, values,
bounded caller RVAs, timing, and markers. An invalid index or absent local
owner is reported, not silently treated as an allowed/blocked value. A
nonzero value must still be correlated with a successful vault before calling
it an eligibility boolean; the array entry's semantics are not assumed.

Build/install: `./tools/build-uplay-probe.sh --retail-vault-state` and
`./tools/manage-uplay-probe.sh install GAME_DIRECTORY --retail-vault-state`.
Steam launch option: `"/path/to/ProjectISAC/tools/steam-vault-state-probe.sh" -- %command%`.
This is a connected retail test. Enter the game, attempt a known vault, press
Numpad 8 at the attempt (Num Lock on), and quit normally. The new evidence
directory is named `retail-vault-state-*`, with a private JSONL file under
`vault-private/`. A complete run should have `index_valid:true`,
`local_owner_seen:true`, at least one `vault_attempt` marker, and `gaps:0`.
If those conditions are not met, it is not a valid measurement.
