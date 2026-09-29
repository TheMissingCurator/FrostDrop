# Finding 148: `CoverVaultIsAllowed` is a registered name, not yet a live flag

Date: 2026-09-28. Read-only inspection of the verified runtime text and rdata
snapshots. No game, backend, account, or probe behavior changed.

The analyzed rdata has the exact `CoverVaultIsAllowed` string at RVA
`0x32f6da8`, among `Dashing`, `InHighCover`, `CoverIsAvailable`, and
`CoverToCoverIsAllowed`. Text RVA `0x286d5f0` constructs its global descriptor
at `0x47cdb88`, with the shared vtable at `0x32b79e8`, and passes the string
to `0x319d80`. That function registers the name and writes its returned
registry index to descriptor offset `+0x08`. The accompanying initializer
at `0x28f23b0` also only registers and destroys that descriptor. These are
metadata operations, not a per-player eligibility write.

A bounded scan of direct RIP-relative text references to the name and
descriptor found only the registration/initializer cluster:

| Target | Direct text reference RVAs |
| --- | --- |
| name `0x32f6da8` | `0x286d607` |
| descriptor `0x47cdb88` | `0x286d5f4`, `0x286d60e`, `0x286d615`, `0x28f23bb`, `0x28f23f4`, `0x28f2407` |

This does not prove no runtime consumer exists. It means a later consumer may
hold an indirect reference or use the registry index through asset/script
code. Reading descriptor `+0x08` before and after Agent Activation would
measure its *registered index*, not whether the player can vault.

The rdata also contains an exact `Vault` string at `0x2ca66a8`. Code around
`0x14aae66`–`0x14aae8c` and `0x14ab0b6`–`0x14ab0dc` compares an incoming
name against `Climb` and `Vault`; these are candidate action/animation
classification paths, not proven player-eligibility predicates. A marker-only
network capture cannot recover the in-memory value.

## Required live observation before a value tracker

At a known retail obstacle, first locate an executed consumer that resolves
`CoverVaultIsAllowed` for the local player. On that same call, record only the
resolved boolean/result, the callsite RVA, and timing before and after the
Agent Activation close and Numpad-8 vault attempts. Capture the writer or
producer only after the reader is confirmed. A mere execution hit at the
registration function, or a change in registry index, is not a valid result.
The test must allow for the value to be recomputed on each action rather than
flipping once on tutorial completion.
