# Finding 137: bounded intro shot replies, not a proven weapon-unlock flag

Date: 2026-09-28. The player observed that the local tutorial displays the
weapon-switch objective while both the switch input and its UI remain disabled.
In retail, the UI/input becomes available during that tutorial step and remains
available after the secondary-weapon step. This suggests a client-side control
gate, but no `can_switch_weapon` field or gate writer has been identified.

The marked retail tutorial capture has three outbound `0x006a` shots with
header counters 31, 30, 29 and three corresponding compact inbound `0x006a`
messages. The shooting activity update `(0,4,4,1,0)` occurs between the
second and third replies. A later outbound `0x014a` occurs before the first
outbound `0x0088` switch request. The previous local stage experiment sent the
activity update but **no** `0x006a` replies; the switch UI stayed absent and
the client emitted no `0x0088` request.

For this opt-in test, `--stage-progression-test` now responds to the validated
31/30/29 intro sequence with compact `0x006a` replies and sends the existing
activity transition on the third shot. The reply codec preserves the observed
unnamed fields. In the three retail examples, one byte in a non-first child
changes `0x80 -> 0x00`; the experiment applies only that bounded pattern.
Its meaning is unknown and the local client has not yet been tested with these
new replies. This is not a general shot/hit decoder or a persistent unlock.
The mode remains opt-in and does not alter the default backend response path.

The first local run with echoes (`20260928-152647-068114`) remained on the
shooting objective. The backend logged only the first two shot replies, with
no shooting-stage update. Its client stream showed counters 31, 30, 29 with
child counts 2, 2, **5**; the initial parser admitted at most four children.
The third shot was therefore discarded before the stage update. The bounded
parser now admits up to 16 children, checks the exact raw-body length, and the
five-child capture is an end-to-end regression fixture. This fixes the proven
server-side omission; it does not yet establish client acceptance of the
five-child echo or the weapon-switch unlock.

Discriminating next observation: after the local shooting objective, determine
whether the weapon-switch UI appears and whether an outbound `0x0088` is
emitted. If neither occurs despite accepted `0x006a` replies, trace the
client-side switch-prevention condition or the still-missing post-shooting
`0x014a` path; do not invent a `can_switch_weapon` packet from the symptom.
