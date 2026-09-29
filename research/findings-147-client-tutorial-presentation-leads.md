# Finding 147: client tutorial presentation is several distinct paths

Date: 2026-09-28. Read-only inspection of the verified game text/rdata
snapshots and existing retail/local tutorial findings. No game binary,
backend response, profile, or retail account was changed.

The client has native interfaces for mission/objective data and UI presentation:

| Client-side interface or field | Evidence in the analyzed build | What it establishes |
| --- | --- | --- |
| `Mission:ObjectiveDescription`, `ObjectiveBrief`, `ObjectiveComplete`, `ObjectiveActive`, `ObjectiveCurrentCount`, `ObjectiveCompleteCount` | rdata RVAs near `0x3011b20`–`0x3011d70`; `ObjectiveDescription` string is registered at text RVA `0x13b76bb` | UI scripts can read localized objective content and current progress from client mission objects. The registration site is not the runtime consumer. |
| `Mission:MissionObjectiveUpdateNew`, `MissionObjectiveUpdateCompleted`, `MissionObjectiveUpdateFailed` | neighboring client mission-node names | Objective transition presentation has its own client-facing state, separate from merely drawing a mission title. |
| `Notification:RClient_MissionObjectiveNotificationNode`, `RClient_MissionNotification`, `RClient_MissionNotificationPlayAudioNode` | rdata near `0x320ca98`–`0x320cb58`; notification node registration at text RVA `0x1868f2d` | Pop-ups and their audio are represented as separate client UI actions. Registration does not prove the tutorial invokes them. |
| `Mission:ObjectiveIntroAudio`, `ObjectiveMegaMapAudio`, `myIntroAudio`, `myObjectiveAudioSwitch` | mission names and fields near rdata `0x3012438` and `0x3009a28`; `myIntroAudio` participates in an asset-field serializer at text RVA `0x13e578c` | Mission/objective assets can supply audio selections. The serializer shows stored content, not when playback starts. |
| `myHintHeader`, `myHintDescription`, `myTeachLimit`, `myOnUseTrigger`, `myDisplayUntilActionIsPerformed` | rdata neighborhood containing `RClient_LoadingTipsManager.cpp` | A client tip/teaching system is a plausible source of the screenshot's left-side “Covers” panel. Its link to that particular panel is not confirmed. |
| `audio:PostDialogueEvent`, `audio:ExecuteDialogueEvent`, `UI/Localization/Current Subtitle Event` | native audio and subtitle node registrations | The client has local dialogue/subtitle presentation machinery. A specific coordinator-line trigger remains unidentified. |

The exact screenshot phrase “Take cover here” was not found in the executable
rdata snapshot. That is consistent with localized text living in game asset
archives, but does not establish its asset path or whether an event is missing.
The installed data is packaged under `rogue/sdf`; this investigation did not
extract or modify those archives.

The prior live `0x00e6` sequence correlates ordered objective-state changes
with tutorial steps. Earlier local traces prove that a five-row `0x00e6` can
decode, enter the generic receive queue, flush, and make the mission visible.
They do **not** prove that the corresponding client mission object has loaded
its objective text, activated a hint, or invoked a notification/audio node.
The first confirmed coordinator voice marker in the newer retail capture is
about six seconds after the safe-house activity starts, so a single immediate
network packet cannot be assigned as its trigger by proximity alone. A
standalone `0x015a` experiment previously caused session rejection; its
semantic interpretation as dialogue remains unsupported.

## Next discriminating read-only trace

Observe one retail and one local run at the same tutorial transition, without
changing server replies:

1. At a specific `0x00e6` row transition, verify the activity and objective
   client objects are retained and report the same active/completed state.
   This extends the existing parser/queue/flush trace to the application
   consumer, not another wire-payload probe.
2. Observe calls to the objective-description/active-state accessors and to
   the mission-objective notification action. Log only call counts, timing,
   activity/row indices, and whether the content handle is present—not text,
   payloads, or personal identifiers.
3. Separately observe tip activation and dialogue-post events at the marked
   cover prompt and coordinator-voice onset. Determine whether those events
   happen in retail but not local, or happen with missing asset/context.

This separates three possible failures: the network state never reaches the
client mission object; the object updates but the tutorial/UI script never
fires; or the script fires but lacks the asset/audio context. The static string
and registration RVAs above are starting anchors, not validated runtime hook
sites. No client flags or packet replies should be forced from them alone.
