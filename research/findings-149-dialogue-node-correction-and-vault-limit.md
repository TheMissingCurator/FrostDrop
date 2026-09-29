# Finding 149: dialogue probe correction and vault-state boundary

Date: 2026-09-29. Static inspection of the verified client text/rdata snapshots;
no retail account, backend response, or installed game file was changed.

## The previous `PostDialogueEvent` hit count was mislabeled

The 2026-09-28 presentation probe watched text RVA `0x632b20` and called it
`PostDialogueEvent`. The registration at RVA `0x687e70` binds vtable
`0x2a36778` to `audio:PollDialogueRTPC` (`0x2a3a9f8`); that vtable's
evaluation-method slot `+0xc0` is `0x632b20`. The 94 recorded entries are
therefore **PollDialogueRTPC evaluations**, not dialogue posts. The capture
remains useful for the independently observed objective-notification node and
world traffic, but its dialogue conclusion must be discarded.

The corrected registration/vtable lineage for the analyzed build is:

| Node name | Registration name RVA | Vtable RVA | Evaluation RVA |
| --- | ---: | ---: | ---: |
| `audio:ExecuteDialogueEvent` | `0x2a3a568` | `0x2a34c28` | `0x6316d0` |
| `audio:PostDialogueEvent` | `0x2a3a608` | `0x2a36a78` | `0x632dc0` |
| `audio:ExecuteAgentDialogueEvent` | `0x3126aa0` | `0x31689f8` | `0x15c00a0` |
| `audio:PollDialogueRTPC` | `0x2a3a9f8` | `0x2a36778` | `0x632b20` |

`ExecuteDialogueEvent` reads a node event field and conditionally calls an
audio-emitter virtual method (around `0x63185d`–`0x631867`). This makes it a
plausible execution path, not proof that it plays the tutorial coordinator.
The new retail presentation build observes this node and the agent-specific
Execute node in one run. The local presentation trace's `PostDialogueEvent`
site was corrected to `0x632dc0`, but the local and retail modes currently
watch different node pairs. No event IDs or audio payloads are logged.

## `CoverVaultIsAllowed` is not yet a measured player flag

The exact name appears with `Sprinting`, `CoverToCoverIsAllowed`, and similar
properties at rdata RVA `0x32f6da8`. Its constructor at `0x286d5f0` registers
the name and receives a registry index; it does not store a per-player
permission value. A previous direct-reference scan found only registration
and cleanup code. The `Vault` string comparison at `0x14aae7a` is an action
classification path, not a proven eligibility reader: it may not run when a
vault is denied. Watching either site alone would not tell us whether
`CoverVaultIsAllowed` is true or false.

Next, correlate the Numpad-8 retail/local vault attempts with an executed
player-eligibility resolver (or the final vault decision), identify its input
object and returned boolean, then trace the writer/producer. The marker and
static property name alone are insufficient to justify setting a value in the
backend.
