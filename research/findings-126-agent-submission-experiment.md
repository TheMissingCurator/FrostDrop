# Finding 126: experimental tutorial agent submission response

Date: 2026-09-27

The local run `evidence/20260927-184756-614183-sdk-adapter-linux` reached the
character customizer. Its backend log recorded a 147-byte world-channel
`0x000c` request after the first-gate burst, but the server previously marked
that request `instance-world-message-unimplemented` and sent nothing.

The private retail tutorial capture
`evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin`
contains one 147-byte outbound `0x000c`, 65,826 ms after the first-gate
`0x0012`. It starts with the captured created-character ID and contains that
ID once. The retail world stream has 48 `0x014d` dictionary updates between
the first-gate flush and this request. The first 500 ms after the request has
142 inbound messages, including a 140-byte `0x0012` and a 28-byte `0x015a`.
Known captured character, account and display-name byte strings do not occur
in the 48 updates or 142-message response window. This does not prove all
opaque fields are identity-free or that every frame is causally a response.

`tools/prepare-world-agent.py` creates an owner-only bounded artifact from
that exact capture. The opt-in `--world-startup` mode now checks the 147-byte
request's leading ID against the authenticated local character, requires the
first world handoff, and sends the dictionary catch-up plus response window
once per admitted channel. The ordinary custom mode and retail mode are
unchanged. A bounded local request copy is checkpointed privately before
dispatch, so an unclean shutdown does not erase the comparison target.

This is deliberately a replay experiment, not a decoded authorization or
character-creation implementation. Success is not assumed until the game is
tested. There are no continuing world ticks, AI or mission state after the
window. The visual mirror/reflection defect remains a separate, unconfirmed
issue.
