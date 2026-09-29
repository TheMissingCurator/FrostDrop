# Finding 134: isolated first-tutorial activation test

Historical note (2026-09-28): this finding describes the original per-capture
profile isolation. Tutorial mode now uses a dedicated persistent local profile
store; see [finding 135](findings-135-tutorial-post-parser-trace-and-persistence.md).

Date: 2026-09-27. Local-backend experiment only; no game acceptance has been
observed yet. No installed game files or existing local profile database were
modified. The source retail capture and private identifiers remain private.

The first `0x00e6` activity update after tutorial character appearance
submission is a 52-byte no-row state for capture-local reference 1001. About
three seconds later, retail sends a 129-byte `0x00e6` for the same reference,
with five rows whose progress fields are all zero. This activation decodes
against the local backend's reference dictionary immediately after its
existing agent-response burst, even though two unrelated dictionary entries
are added in the intervening retail traffic. The artifact is one frame only;
it contains no known retail character/account/name value and does not include
the later 1/4 progress states.

`tools/prepare-tutorial-start.py` reproducibly extracts and validates that
frame into owner-only `private/tutorial-start.isactsa`. Its loader and `bind`
validator require an initial no-row activity in the existing agent batch,
the same resolved activity reference, header byte 7, exactly five zero-state
rows, no subrows, and no dictionary growth. The local backend appends this
one frame after its agent response only when a matching authenticated
`0x000c` causes local character finalization. There is no elapsed-time
replay or claimed action-trigger decoding. The hypothesis under test is
whether this state alone causes the tutorial UI/controls to initialize.

The new `custom --world-startup --tutorial-start` launch option isolates the
experiment from the existing world-startup behavior. It uses a fresh SQLite
profile database inside each new capture, so repeated character-creation
experiments do not consume or alter the normal persistent local slot. That
also means this mode does not test cross-launch profile persistence; the
existing `--world-startup` mode remains the persistence test.

Synthetic tests verify artifact reproducibility, dictionary binding,
one-shot delivery, profile finalization before response, launch flag routing,
and the fresh profile-store argument. They do not prove client acceptance,
objective progression, AI spawning, mission completion, or resumed-character
tutorial rehydration. An in-game result and backend trace are the next
required evidence.
