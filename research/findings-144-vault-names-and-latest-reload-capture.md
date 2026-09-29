# Finding 144: vault candidates and latest post-tutorial shooting traffic

Date: 2026-09-28. Sources: local capture
`20260928-204534-271428-sdk-adapter-linux`, verified client text/rdata
snapshots, and Ubisoft's Division glossary. Analysis and one opt-in dialogue
probe only; no vault or ammunition response was changed.

## Traversal

The local debugger observed `PreventRunningRefCount=1` after Agent
Activation closed, then logged its one-shot change to zero on the known
weapon-gate owner. The player could subsequently sprint and move cover to
cover, but still could not vault. This supports the running gate as a cause
of the first two restrictions, not the remaining vault restriction.

The client data names distinct `Vault`, `HighVault`, and `Climb` inputs, plus
`HasParkour`, `CoverVaultIsAllowed`, and `VaultBlocked`. `HasParkour` is looked
up and retained as a named property handle at client RVA `0x157d498` to
`0x157d521` (owner offset `+0x148`). `CoverVaultIsAllowed` is registered via
the static initializer at RVA `0x286d5f0`. `VaultBlocked` is a field name
used by serialization/deserialization functions around RVA `0xb0dc72` and
`0xb1f240` (field offset `+0x2c` in that object). These are different
owners/paths; no live value or causal read at the attempted obstacle was
captured. Clearing either would be premature. The next diagnostic is a
read-only sample of the actual vault-eligibility decision at an obstacle,
including action input and these candidate values.

Ubisoft's official glossary describes cover-to-cover movement as a distinct
action but does not define the vault predicate. The game data itself is the
stronger naming source for this build.

## Shooting after reload

The same local client capture contains 223 outbound world `0x006a` frames.
After the tutorial, zero-child frames with counter `32` and reserve-like
values `888`, `878`, `846`, `814`, and `782` recur. There are also many
ordinary shot-shaped reports after those frames, so the pause is transient,
not a permanent firing gate. The debugger observed `PreventReloadRefCount`
rise during reload and return to zero, while the sampled firing-prevention
count stayed zero. The backend still sends no post-tutorial `0x0094` resource
updates and treats later `0x006a` as an already-finalized tutorial sequence.
Retail answered comparable zero-child `0x006a` with `0x0094` triplets
(finding 142). This remains the best reconciliation lead, but causality and
the local reference mapping are not yet established. Do not alter firing or
reload prevention counts to paper over it.

The player clarified that firing resumes after waiting following reload.
This is consistent with the observed transient `PreventReloadRefCount` and
later shot traffic. The elapsed wait and normal retail reload interval have
not been measured, so missing `0x0094` remains a plausible backend cause,
not an established one.
