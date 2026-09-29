# Tutorial client-presentation observations (experimental)

The first retail capture aligned incoming objective-state traffic with an
objective-notification node and a node mistakenly labeled `PostDialogueEvent`.
Static registration lineage now identifies that second site as
`PollDialogueRTPC`; its 94 hits cannot be used as evidence about dialogue
posting or playback. The current retail probe observes `ExecuteDialogueEvent`
and `ExecuteAgentDialogueEvent` instead. A node entry is still not proof that
a particular voice line played; the actual event and playback result are not
captured.
It also does **not** sample `CoverVaultIsAllowed`, `HasParkour`, or the live
vault decision. Numpad 8 can mark a vault attempt for later alignment, but a
marker alone cannot reveal the flag's value or where it is written. That
requires a separate retail/local read-only trace of a validated player
vault-eligibility consumer at the same obstacle.

The retail observer is read-only: it retains the existing bounded, selected
world-stream capture and logs zero-payload entries at the two corrected
dialogue-node methods. It does not change retail responses. The local mode
uses the experimental tutorial backend and movement-gate override through
Agent Activation, then observes the objective-notification node and the real
`PostDialogueEvent` method. The two modes therefore do **not** currently
observe identical node pairs. The local node phase is read-only, but the
entire local mode is **not** a read-only game run. The earlier guessed `0x015a`
dialogue send is deliberately disabled.

The sites are attested to the analyzed game build by startup signatures and
mapped through named registrations and vtables, not a confirmed tutorial call
stack. If a site is cold in retail, that is an inconclusive target selection,
not evidence that the client lacks dialogue presentation.

## Retail capture

Close the game and Ubisoft Connect before changing the installed loader. Use
the verified game directory and keep the internet connection **on** for this
retail run:

```bash
./tools/build-uplay-probe.sh --retail-presentation
./tools/manage-uplay-probe.sh install "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" --retail-presentation
```

Set Steam launch options to:

```text
"/path/to/ProjectISAC/tools/steam-presentation-probe.sh" -- %command%
```

Use a retail character that can perform Agent Activation and the safe-house
handoff. Do not delete a character merely for this capture. Press Numpad 1
when the world is loaded, Numpad 7 when coordinator speech starts, and Numpad
8 for a vault attempt if one is convenient. Play through the safe-house
handoff if available, then quit normally. Numpad 8 is only a time marker; this
probe does not read `CoverVaultIsAllowed`. The run creates an access-restricted
`evidence/*retail-presentation-*/presentation-private/` directory. Its binary
world stream may still contain personal game identifiers; do not publish it.

After the retail run exits, restore the verified original loader before using
the per-process custom overlay:

```bash
./tools/manage-uplay-probe.sh restore "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division"
```

## Local comparison

Set Steam launch options to:

```text
"/path/to/ProjectISAC/tools/steam-isac-mode.sh" custom --world-startup --tutorial-start --first-objective-test --cover-completion-test --stage-progression-test --weapon-gate-test --presentation-trace -- %command%
```

This uses the existing persistent local tutorial profile; add
`--fresh-tutorial-profile` only when a new local character is wanted. The
local mode retains its established process-level external-IP isolation, so
the desktop network need not be switched off. The trace starts only after the
existing running-gate override reports success. If it never prints
`ISAC_CLIENT_PRESENTATION_ARMED`, this run did **not** observe the client-node
handoff. Closing the game normally flushes the capture.

## Reading the result

```bash
python3 tools/inspect-retail-tutorial.py evidence/CAPTURE_DIRECTORY
```

Compare the retail dialogue-node entries with the Numpad 7 marker and nearby
world traffic. The local mode currently offers only a `PostDialogueEvent`
comparison and should not be treated as an Execute-node counterpart. If the
retail Execute nodes are cold at the coordinator cue, inspect global-dialogue,
subtitle, or lower-level playback paths next. Even matching node entries do
not establish which voice line played or whether the server supplied its
trigger. The objective-state consumer, teaching-tip action, audio event and
`CoverVaultIsAllowed` resolver still need separate validated runtime traces.
