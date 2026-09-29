# Opt-in typed tutorial startup over the real local transport

Date: 2026-09-27. User explicitly approved a capture-derived experimental
template. This is a runnable startup-delivery experiment, **not completion
of the capture-independent world generator or gameplay server**.

## Implemented path

`prepare-world-startup.py` loads the existing initial tutorial message using
the decoded dictionary and full 0x0007 codec. It requires the observed
successful-creation binding and tutorial shape, then removes known retail
identity fields through typed substitutions. Output `ISACWST1` contains one
canonical raw-reference WorldStart. No timestamps, opaque stream tail,
retail connect response or later gameplay messages are replayed. Output is
mode 0600 and exclusive-create; evidence is never overwritten.

The prepared private artifact is `private/tutorial-startup.isacwst`, 20,638
bytes. It is not a public asset and is not guaranteed free of unknown private
fields. The backend reads only a bounded owner-only regular file, rejects
symlinks and malformed/noncanonical bodies, and requires local authentication
and profile mode before admitting the experiment.

After authenticated instance admission, `ServerListSession` builds:

1. Generated type 2 connection acceptance and empty 0x0102 flush.
2. Generated 0x014d dictionary of references in the rebound model.
3. Typed, re-encoded 0x0007 startup snapshot.
4. Empty 0x0102 flush to enqueue the decoded batch (parser f84280, finding 011).

These are channel-multiplexed application frames sent through the existing
compressed TLS transport, not the old plaintext replay injection bridge.
Serialization completes before admission commits. A route caches its startup
frames for reconnect consistency; duplicates on the same channel do not send
again. Expiration/parent revocation/character deletion checks still precede
admission. Closing a channel removes its admission, not the still-valid route.

## Local substitutions and deliberate uncertainty

| Fields | Policy |
| --- | --- |
| +4e0 and raw +4f0 | Actual local selected character ID; observed retail binding is established. |
| +2b0 | Authenticated local display name. |
| Tagged +500 | Local account UUID text; its wider semantic role remains provisional. |
| +2a0, +670/+680 | New route-lifetime IDs, preserving equal-value aliases. |
| Item reference_0 | New route-lifetime item-instance IDs, replaced in every typed reference alias throughout the snapshot. |
| +20, +4b8 and item reference_1 | Preserve captured world/catalog/definition keys; do not randomize asset references. |
| Pose, stats, flags, collections and other fields | Retain captured tutorial values pending independent semantic recovery. |

An additional within-message comparison established **+670 equals +680** in
the tutorial snapshot. The first draft's distinct-ID check rejected the
template; the corrected rebinder preserves this equality. Every compact
reference loses its capture-local index and side value before re-encoding;
the generated dictionary is checked by decoding the resulting batch.

Template preparation uses local placeholder identities. Runtime binding then
uses the actual local character/account and fresh route identities, so even
the stored template does not retain the known retail IDs. Unknown fields are
not claimed sanitized, semantically correct, or reusable across game builds.
No client registration gate or asset lookup is patched to force success.

## Opt-in and diagnostics

`steam-isac-mode.sh custom --world-startup -- %command%` selects the new
`transport-world-start` runner mode. It keeps the existing name-lineage trace,
DLL overlay and network isolation, and freezes a validated template in the
private capture. Default custom mode and retail mode do not enable startup.
No inherited environment switch or mere template existence can enable it.

Backend log stages distinguish template readiness, startup batch sent and
unsupported follow-up message types. Up to 64 distinct unsupported types are
reported independently of the ordinary 512-message log cap. No raw payloads,
names or IDs are printed. No response is invented for an unknown request.

## Verification and next run

- World tests: 49 passing, including eight new template/admission tests and
  the real tutorial decode/rebind regression.
- Existing profile tests: 30 passing; discovery/admission tests: 13 passing.
- Isolated transport suite: 10 passing; its integration test runs both default
  and startup-enabled synthetic clients through actual local SDK/auth/profile,
  discovery, compressed TLS, dictionary decoding and character binding.
- Backend socket regressions: 7 passing. Namespace/socket tests initially hit
  sandbox restrictions, then passed with approved execution outside it.
- Launcher tests verify explicit opt-in, unchanged ordinary modes and refusal
  of the world-startup flag with retail mode.

No actual game was launched by this change. Client acceptance, complete world
loading and playability remain unverified. The experiment intentionally omits
unknown 0x00dd, ongoing 0x0012 state updates and simulation; the snapshot may
only advance loading. The next evidence must distinguish rejection of this
batch from successful asset/player construction followed by missing world
continuation. Use the existing capture, not another broad probe by default.
