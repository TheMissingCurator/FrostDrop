# Finding 141: safe-house handoff works; progression and traversal do not

Date: 2026-09-28. Read-only comparison of local capture
`20260928-200845-309424-sdk-adapter-linux`, marked retail tutorial capture
`20260927-064853-retail-tutorial-x3s3v01n`, current backend code, and the
verified static client snapshot. No backend reply or game file was changed.

## Confirmed local result

The backend sent the last known-working Agent Activation close as
`0x00e6,0x0102` and remained connected. It then sent the capture-derived
safe-house activity start as `0x014d,0x00e6,0x0102`; the client displayed
that mission. This validates the bounded handoff, not a playable safe-house
mission. The client kept sending world traffic afterward. The debugger
observed `PreventSprintingRefCount=0` at both the shooting and closed phases,
yet the player reports sprint still blocked. The local run also lacked vault
and cover-to-cover movement according to the player. Its GDB process reported
an internal assertion while handling shutdown SIGQUIT; that does not establish
a gameplay crash before the player exited.

## Safe-house progression boundary

The current backend sends only the next activity's opening four-row state
`(1,0,0,0)`. There is no safe-house objective handler in `server_list.py`,
and subsequent world messages generally return
`instance-world-message-unimplemented`. Therefore arriving at the marker
cannot advance the activity under the current backend, even if traversal is
restored. This is an implementation gap, not evidence for a missing generic
"mission complete" request.

In retail, that same activity (capture-local index 1081) progresses from
`(1,0,0,0)` at +127.289 seconds to `(4,1,0,0)` at +162.911 seconds, then
`(4,4,1,0)` at +180.087 seconds, `(4,4,4,1)` at +193.488 seconds, and a
no-row close at +201.673 seconds. Times are relative to the first inbound
world record. Many outbound `0x014a` frames occur before the first transition,
especially +149.651 to +160.290 seconds. The local post-handoff log contains
no `0x014a`; it does contain a 44-byte `0x0019`, empty `0x0016`, and 11-byte
`0x016a`, all currently observe-only. Temporal proximity does not prove that
`0x014a` causes the row transition or that any one local message is its
substitute. Local inability to vault may also prevent reaching the retail
trigger volume or interaction.

## Traversal and dialogue leads

The static client registers `PreventRunningRefCount` at owner offset
`+0x2b8`, `PreventCoverToCoverRefCount` at `+0x308`, `PreventCoverRefCount`
at `+0x320`, and `PreventExitCoverRefCount` at `+0x328`, on the same owner
type as the previously observed sprint/weapon properties. The movement path
at RVA `0x16742c5` checks the running-prevention getter `0xd16710`, then
checks the sprint-prevention getter `0xd172c0` at `0x16742e9`; the resulting
booleans feed `0x16765f0`. Thus a zero sprint count alone does not prove the
movement path is unblocked. These are static registration/control-flow facts,
**not** observed live running/cover values or proof that any count blocked the
player. The retail data also contains `HasParkour`, `VaultBlocked`, and
`CoverVaultIsAllowed` strings, but no validated vault gate or server field is
yet known. Because sprint's observed count is already zero, blindly clearing
more refcounts is not a justified fix.

No dedicated outbound coordinator-voice request is established at the
safe-house activity start. Retail first receives the four-row `0x00e6` with
`0x01ae` and a `0x006c` in the same capture tick; the next outbound world
`0x0003` follows 24 ms later, and the first nearby `0x014a` follows about
596 ms later. The local batch has `0x00e6` but omits these companions and
other ongoing world updates. The retail capture has no audio-playback marker,
so this comparison cannot identify which inbound event or local script
condition plays the coordinator lines. A voice cue may be server-pushed or
client-local; do not invent an audio request from proximity alone.

## Discriminating next pass

Keep the known-good close and next-activity startup unchanged. The existing
weapon-gate debugger stop sampled a running count of one during the shooting
phase in `20260928-202810-687709-sdk-adapter-linux`, with zero sprinting,
cover-to-cover, cover, and exit-cover counts. The run did not record a
post-close movement sample. An opt-in, one-shot diagnostic now clears an
exactly-one running count on the same weapon-gate owner only after the
activity-close marker and a subsequent weapon-gate check; the next run must
verify whether this changes sprint, vault, or cover-to-cover. Separately
trace the actual vault eligibility result
and the client-side dispatch of the safe-house activity. Compare to a retail
post-tutorial session if possible. For objective progress, identify the
first retail `(4,1,0,0)` producer/trigger and build a bounded handler for
that row, not a timer-driven replay of all four rows. For dialogue, trace
the inbound event or local audio-script consumer at the activity start.
