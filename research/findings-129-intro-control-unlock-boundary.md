# Finding 129: introductory control unlock is not yet a known wire flag

Date: 2026-09-27. Read-only investigation; no game installation, profile, or
backend response was changed. Private payloads and identifiers were not
published.

The player clarified the symptom: ordinary movement works locally, but
**sprinting and weapon switching remain locked** when the movement/shooting
intro tutorial has not completed. The player further observed that these
inputs are introduced as steps within that tutorial; completing its objective
sequence may enable them without any separate permanent unlock operation.
This is a working hypothesis, not yet a traced client condition. The existing
retail tutorial capture
`20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin`
contains six human-marked intro objective completions (markers 4, 6, 8, 10,
14, 16) before the first safe-house marker 17. Markers are approximate human
observations, not exact engine callbacks.

## What the capture rules out

- No inbound `0x002a` stat update occurs during those six intro steps. All 15
  `0x002a` messages occur later. An XP/stat delta is therefore not the direct
  observed unlock for this intro.
- The decoded inbound `0x0023` events recur on the same anonymized references
  before, during, and after the intro. Their frequent paired variants
  (`discriminator=2` and `0`) are not a unique completion signal.
- Inbound `0x0024` has the same observed small-byte fields throughout the
  phases (`byte_0=3`, `byte_1=0` in the examined messages) and changing
  references. Inbound `0x0020` has mainly value 1 and also appears before and
  after the intro. Neither yields an obvious persistent tutorial-complete
  transition from the decoded fields.
- The existing `0x006c` subset in the intro is predominantly a bit-2 vector
  update on one anonymized entity. Its new post-intro bit-35 boolean variants
  occur after the safe-house boundary, so their timing does not identify the
  earlier sprint/weapon unlock. Fourteen `0x006c` bodies use unsupported
  presence bits and are not decoded by the current subset codec.
- `0x0159` and `0x015a` share the same build-specific static reader RVA
  `0x178cd30`; their mere occurrence near objective markers is insufficient
  to label either as an unlock. This reader delegates to larger structure
  readers and has not been given a complete neutral codec.

Static client strings include `myCiceroTutorialTriggers`,
`IsMovementBlocked`, `PreventSprintingRefCount`, and the registered script
node `Skill Script/Weapon/Switch Weapon`. Their known LEA sites are property
or node registration paths, **not** demonstrated runtime writes to the
sprint/switch gate. In particular, the `PreventSprintingRefCount` site at
RVA `0xd088a1` registers a named property and stores the returned handle at
an object offset; it does not show this value changing during the tutorial.

## Concrete local implementation gap

In the current local backend, world `0x0009` receives a one-shot first-gate
burst and world `0x000c` receives a one-shot response window. Subsequent
world-channel messages return `instance-world-message-unimplemented`.
Retail, by contrast, keeps sending state and event messages throughout all
intro markers (notably high-frequency `0x0012` and `0x0102`). The local
backend thus does not yet run an objective/AI/world-state progression loop
that could normally complete the tutorial. A profile-only fix or a hardcoded
control unlock has no evidentiary basis at this point.

## Preferred implementation/research path

Recover the intro objective sequence and its activation conditions, then
implement the smallest local world/mission state machine that lets the client
perform those steps normally. Start by correlating the existing numbered
markers with objective presentation, client input/activity, and the persistent
world updates around each transition. Identify the first missing state after
local world entry before trying to reproduce the whole tutorial. Do not
fabricate a "tutorial complete" packet from timing alone or globally disable
input gates: either could hide the actual missing mission state.

## Fallback discriminating test

If the objective sequence cannot be recovered from existing evidence,
instrument the client's actual sprint-prevention and weapon-switch conditions
in a retail intro run, recording only timestamped old/new values and call-site
RVAs as each objective advances. Correlate those changes with world-message
dispatch. If a fresh retail intro run is unavailable, trace the registered
property handle's read/write consumers statically first. Do not patch the
control check or replay an arbitrary retail completion frame as a fix.
