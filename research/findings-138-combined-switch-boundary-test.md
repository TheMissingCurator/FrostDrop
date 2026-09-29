# Finding 138: one-run shot-flush and switch-request boundary test

Date: 2026-09-28. This is an opt-in local backend experiment, not a general
weapon-state implementation.

The last local capture sent `0x006a`, `0x006a`, then
`0x00e6,0x006a,0x0102` for the first three shots. The first two replies had no
`0x0102` batch flush. In the marked retail intro capture, each of the three
nearby `0x006a` replies is followed by an `0x0102` at the same capture tick.
Earlier client tracing established that this control type transfers the
receive queue into a batch. The local backend now sends `0x006a,0x0102` for
each of the first two shots, leaving the third shot's existing state update
and flush in place. This is the sole wire-response change in the test.

The same `--stage-progression-test` run now uses a two-breakpoint, read-only
switch-path observer. Build-attested RVA `0x12f4860` is a candidate
`Client/Player/Request Weapon Switch` node implementation, reached by a
factory associated with that registered node name. It calls RVA `0x14cdec0`,
which updates a weapon-switch request object. The observer records bounded
hit counts and whether both sites fire on the same thread within two seconds.
It does not read payloads, write game memory, or assert that either site is
the keyboard handler. Absence at the node when the user presses the key
suggests a gate upstream of this candidate path; a node hit without a
downstream hit narrows the branch inside the node; both hits without outbound
`0x0088` narrow the remaining submission/equipment path. A `0x0088` outbound
request would establish the client passed this boundary.

The client also registers `PreventWeaponSwitchingRefCount` at RVA `0xd08a43`;
this is a property-name lookup that stores a descriptor handle at an object
offset, **not** a traced runtime count. The combined observer does not claim
to measure that value. If the switch request path remains silent, locating
the counter's actual runtime owner and reads is the next targeted static/dynamic
step. No global control patch or guessed unlock packet was added.
