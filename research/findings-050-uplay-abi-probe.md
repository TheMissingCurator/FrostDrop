# Finding 050: bounded Uplay ABI-return probe

Date: 2026-09-25

The forwarding proxy previously tail-jumped to Ubisoft's original exports. It
could identify the 21 menu-startup functions but could not observe their
return conventions or output-parameter behavior, which made a standalone
compatibility DLL unsafe to implement by guesswork.

An opt-in `ISAC_UPLAY_ABI_PROBE=1` mode now replaces the target export's return
address with a shared return trampoline while leaving the original argument
stack intact. Per-thread bounded state retains the real caller address and
argument shapes. The trampoline records metadata about the integer and
floating-point return channels, restores them exactly, and jumps to the
original caller. Nested calls are handled as a per-thread LIFO with a depth
limit of eight.

The probe samples at most 16 calls per targeted export. It records normalized
caller RVAs, null/scalar/pointer argument classes, writable-output mutation,
and recognizable UTF-8 lengths. It stores no raw pointers or pointed-to bytes;
non-small argument scalars are redacted. A Wine smoke DLL verifies that a
writable output parameter is changed by the forwarded call and that the exact
scalar return survives the trampoline.

The initial connected capture completed 89 call/return pairs without an ABI
error, but it also established that a generic register snapshot cannot prove
an export's argument count: unused Windows x64 volatile registers retain
unrelated values. The probe therefore now captures one bounded executable-code
window for each unique normalized game call site. Runtime unwind metadata is
used as the preferred instruction boundary, with a fixed-size fallback for
large functions. These code-only windows reveal the real argument setup and
post-call return handling without recording account, ticket, or profile data.

The same capture observed two later startup exports that were absent from the
original target set: `UPLAY_USER_SetGameSession` and
`UPLAY_WIN_RefreshActions`. Both are now included.

One further normal connected menu launch should now supply the contracts
needed to implement the first local Uplay compatibility shim. Gameplay and
world probes are intentionally excluded from that capture.
