# Finding 045: first world replay reached partial interactive state

Date: 2026-09-25

The first isolated world replay injected all 730 captured frames with no
injection, isolation, or parsing error while suppressing 5,439 later retail
deliveries. The client reached an interactive but incomplete Post Office: the
stash and loadout UI worked, while the Base of Operations presentation, exit,
and fast travel did not.

This proves that the captured pre-gate stream is sufficient for initial world
activation and at least part of the character/inventory snapshot. It does not
prove that loadout mutations persisted. Because the original capture ended at
the first complete type-`0x0012`, the failure is consistent with missing
post-gate progression, Base upgrade, mission-completion, world-phase, and
transition state rather than missing client assets alone.

`ISAC_WORLD_CONTINUATION_CAPTURE=1` now extends the private capture through
clean game shutdown with 16-MiB/65,536-span safety limits. The first gate is
marked exactly once so the existing replay validator remains compatible.
Payload-free message metadata is retained for up to 32,768 records. The Linux
capture helper can also write action markers aligned to the game probe's
monotonic tick domain, and `analyze-world-continuation.py` correlates inbound
types, outbound types, channels, and streams around those markers.

The intended controlled actions are full Post Office load, ammo-box use,
crossing a region boundary, and fast travel. Region windows distinguish a
server-backed state fetch from client-only presentation streaming; dispatch
metadata will also expose a reader change during a transition.
