# Finding 133: first tutorial close to safe-house activity

Date: 2026-09-28. The sources are the marked retail tutorial capture
`20260927-064853-retail-tutorial-x3s3v01n` and local run
`20260928-183607-171182-sdk-adapter-linux`. Identifiers and raw payloads remain
in owner-only capture artifacts.

The local run displayed the first tutorial completion, but did not begin the
next mission. Its backend sent the final five-row `0x00e6` and 44-byte close;
the client remained connected and the backend did not send a subsequent
activity. `PreventSprintingRefCount` was observed as zero both before and
after the close at the weapon-gate breakpoint. This does not establish the
actual sprint-input decision or explain missing coordinator dialogue.

In retail, the first close follows a distinct preceding batch with one
`0x014d` entry and a nine-byte `0x0064` addressed to the retail character.
The close batch contains the 44-byte `0x00e6`, eight zero bytes in `0x01ae`,
and a flush. Roughly four seconds later, retail sends a two-entry `0x014d`,
a 128-byte four-row `0x00e6` with state vector `(1,0,0,0)`, another `0x01ae`,
and a flush. Only two references in this next activity are new: its activity
reference and the first row's subrow reference. The remaining references are
in the initial dictionary. The `0x0064` recipient must be rebound to the
local character. Its complete wire layout and repeated appearances around
other objective transitions are documented in
[finding 140](findings-140-tutorial-close-adjacent-messages.md); the
business meaning of its additional fields remains unresolved.

The first safe-house marker precedes several distinct outbound `0x014a`
interactions. The four-row activity advances through this period and closes
later. Afterward, four other distinct activity references appear in two nearby
batches: one one-row active state, then three no-row states. This is
consistent with the user's observation that a safe-house PC interaction
unlocks four side missions, but the capture does not prove which `0x014a`
targets the PC or identify those four references as side missions. Do not
spawn them automatically on safe-house entry or on the first tutorial close.

An attempted local close-companion batch in
`20260928-195612-684399-sdk-adapter-linux` was followed immediately by a
client disconnect, before the next activity batch was sent. The specific
offending companion has not been identified. The current default therefore
restores the earlier successful two-frame close (`0x00e6`, flush) and tests
the next four-row activity as a separate later batch (`0x014d`, `0x00e6`,
flush). This does not emulate that activity's progression, the PC interaction,
side-mission unlocks, voice cues, or persistent world progress. Those are
separate evidence/implementation milestones.
