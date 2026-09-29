# Finding 133: opt-in local profile finalization experiment

Date: 2026-09-27. This is a local-backend implementation and synthetic test,
not a confirmed game-client success. No installed game or live Ubisoft profile
was modified. The existing local profile database was inspected but not edited
during implementation.

The marked retail tutorial capture has one 147-byte world-channel `0x000c`
appearance submission. A later retail profile list contains the same character
ID, marked customized, with a 1261-byte record. Its 32 appearance float bits
match the submission. This justifies an **experimental** local finalization
path, not a claim that `0x000c` is the only retail commit condition.

`tools/prepare-character-template.py` extracted the 18 node structures from
that customized record into owner-only `private/tutorial-character.isacchr`.
The artifact is normalized: 32 float slots are zero placeholders, pairs are
empty, scalar progress fields are the locally constructed starting defaults,
and the known retail character IDs, account ID, and display name are absent.
The node meanings remain unknown and capture-derived. Preparation is
reproducible byte-for-byte from the two existing private captures.

In the already opt-in `custom --world-startup` mode, the launcher freezes
this artifact alongside the world/agent artifacts. After authenticated
character admission, valid first-gate handoff, and a matching canonical
`0x000c`, the backend binds the submitted float bits to the normalized nodes.
It transactionally updates the existing account-owned local SQLite row to a
customized record **before** sending the existing one-shot agent response.
An identical retry is idempotent. A different retry, foreign ID, unfinished
flag, malformed submission, or store failure is refused without an ACK.
Subsequent profile lists are invalidated, and normal customized local slots
may be selected again. Completed slots cannot be deleted by the unfinished
cleanup path or overwritten by another create.

The legacy SQLite table name remains `unfinished_characters`; no schema
migration is needed because the complete encoded profile entry is stored in
that row. It is now a one-local-slot table. This does not implement multiple
characters, inventory/world saves, gameplay progression, or arbitrary
appearance editing.

The promoted entry deliberately retains the local starting-zone routing
fields and flags. In the observed retail completed entry, some profile flags
and instance-name fields differ; their full routing semantics are not yet
known, so they were not copied. A game run must establish whether the client
accepts this conservative local shape after restart. The success criteria are
the `instance-agent-profile-finalized` backend stage, a subsequent customized
profile list, and a clean second launch selecting the same character without
entering customization. Until that happens, this is not a verified durable
gameplay profile.
