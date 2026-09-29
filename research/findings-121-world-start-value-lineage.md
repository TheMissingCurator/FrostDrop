# World-start values: capture comparison and actual client consumers

Date: 2026-09-27. Offline analysis only. No game/DLL modifications, new
capture, launch-option changes, or backend response changes in this finding.
The backend still stops at connection acceptance with world pending.

## Outcome and limits

We can now distinguish character binding, spawn pose, item instances and item
definitions using actual client consumers, not just repeated bytes. We do
**not** yet have a complete validated, capture-independent startup template.
In particular, the world selection reference, remaining catalog keys, tag
lists and progression/stat defaults require more semantic work.

The three initial worlds are tutorial (T), first gate (G), and stable hub (H).
They come from the same retail account; G/H also share a character. Equality
across them cannot distinguish an account value from a universal default.
Private identifiers and player strings are deliberately omitted here.

## Reproducible comparison

`tools/compare-world-start.py` reads the existing tutorial/bootstrap formats,
seeds the reference dictionary, decodes the first 0x0007, and verifies exact
re-encoding and resulting dictionary state. It compares resolved references,
not their capture-local indices. Output contains lengths, equality groups,
scalar numbers, overlap counts and identity-match booleans, not raw IDs or
captured strings. No capture data is installed as backend defaults.

| Measurement | T | G | H |
| --- | ---: | ---: | ---: |
| Body bytes | 8450 | 11179 | 11666 |
| Dictionary entries after decode | 341 | 663 | 663 |
| Unique nonzero references in message | 340 | 662 | 662 |
| Item rows at +4d0 | 199 | 244 | 244 |
| Unique item reference_0 values | 199 | 244 | 244 |
| Unique item reference_1 values | 126 | 144 | 144 |

No item reference_0 is shared between any two snapshots. All 144 distinct
reference_1 values in G/H are shared; T shares 114 with each. References 2/3
are zero in every observed item, not necessarily every possible item variant.

The tutorial's successful character-creation identifier equals **both +4e0
and +4f0**. Those fields agree in all three snapshots. +20 is different and
must not be replaced with the character ID. +2a0 changes in every snapshot.

## Descriptor lifetime and ownership

All addresses below are RVAs in the saved runtime text snapshot documented
in finding 118 (SHA-256 filename ending `...66c03eefb74.bin`), not file offsets
in the protected on-disk executable.

```text
type-7 registration (181b4b9 / 181b4e2 / 181b517)
  -> callback 134a970
  -> 1654bc0: deep-copy message into owner+2c0 (pending)
  -> 1630fc0 or 16310a0: transfer into owner+2c8 (active)
  -> 16303c0 -> 18b7140: apply startup / create player
```

At 1654bc0, allocation size is 0x768 and copy constructor is 1539c40.
Existing pending storage is destroyed through its virtual destructor before
replacement, and owner+2a4 becomes 1. The copied message outlives the incoming
packet. 1630fc0 destroys an old active message, transfers the pending pointer,
clears pending, and changes loading state to 6. 16310a0 can instead transfer
and enter state 12 on the reuse path. 159e3c0 applies that path's snapshot and
destroys/clears active storage at 159e43f/159e441.

Helper **1654dc0** tests whether existing loaded state is reusable:

- owner+2a4 must be 1, and the object at owner+250 must have +548 set;
- pending+20 must equal that object's raw identifier at +8;
- pending lists +6d0/+6e0 must equal its lists +2d0/+2e0.

String-list comparator aed420 requires equal counts and ordered exact string
equality. This is **not an unconditional startup rejection gate**: 16310a0
takes state 3 when reuse is unavailable. We must not patch this comparison
or mistake its conditions for proof that a fresh world already exists.
16303c0 passes +6d0/+6e0 to fd3ec0, which copies them to +2d0/+2e0 and
dispatches individual entries through 5af190/55dbd0. Their names/roles are
not yet established. Treating them as arbitrary empty lists is ungrounded.

## Field provenance and safe generation policy

| Field | Consumer evidence | Local-world policy / unresolved part |
| --- | --- | --- |
| +20 reference | Loaded-state identity comparison in 1654dc0; T differs from G/H | World-selection candidate. Resolve its fresh-load producer/asset mapping; do not generate a random UUID or use the character ID. |
| +4e0 reference | 18b7140 resolves it through e09240 and passes it to 18dbe70; 159c7a0 uses it through b8d980 | Bind to the locally created character/entity identity, consistently with +4f0 for this observed player path. |
| +4f0 raw16 | Matches creation result; 18dbe70 establishes an additional identity mapping; 159c7a0 copies it into player+418 | Use the same local character ID for this observed shape, never the retail ID. |
| +290 vec3 / +29c float | 159cbb2..159cc14 passes position and heading to transform component vtable+b0; 1590ae6..1590afc also applies heading | Spawn position/heading, tied to the selected world. Optional caller-supplied pose can override them. |
| +3b8 string | 159c94c calls cdb020 -> cdaf10 and immediately uses resolved object+360/+368 | Player archetype-name lookup. All captures use `soldier`, also present as an exact NUL-terminated static string at RVA 319c568. Valid observed candidate, not a whole startup template. |
| +4b8 reference | 159c8a9 calls effea0 against catalog reached via world+138, then +b8 | Catalog key, asset category unresolved. Null key returns null; missing key falls back to catalog+18. Do not assume the fallback is usable. |
| +4c8 bool | 159c8d5/159c995 select branches in a configuration object | T=false, G/H=true. Meaning not proven; do not label gender or tutorial completion. |
| +2a0 / +2b0 / +3b0 | Identity/name bundle passed to 55ff40; 18dbe70 also installs reference/name through 5ae370/5ae080 | +2a0 changes per capture; name-like bytes remain the same. Wider identity relationship and enum semantics unresolved. |
| Tagged +500 block | 159cc57..159ccca copies it to player+428..460 | Observed tag 2 and 36-byte UUID-shaped text. Same in all captures, but not any established character/peer ID. Do not reuse as a constant; producer unresolved. |
| +288 / +28c | Passed to methods +40/+30 on player+5d8 | Observed 601 vs 5251, and 200. Stat meanings not established; not sufficient to label health/stamina. |

### Inventory: instance IDs are not asset IDs

At 159d024..159d031, +4d0 is passed to **1579bd0**. That function resolves
each item's reference_1 (in-memory item+10) through **cea480 -> f07d10**,
against a catalog reached through world+138, then +d8. An unresolved
definition is skipped. With a definition, **eb2e20** looks up reference_0
through ce27e0; an existing runtime item is reused, otherwise e38260 creates
one using the definition.

This independently explains the comparison: reference_1 is a definition
lookup key, while reference_0 identifies the runtime instance. A local model
must preserve valid definition keys but assign its own instance identities
and maintain all equipment/collection aliases. Replacing every GUID with a
random UUID would break definitions. Copying every GUID would retain retail
instance/session data. The 199 tutorial rows are not proof of 199 separately
owned inventory items; the complete collection semantics remain open.

## Next bounded work, without a new retail capture

1. Follow the fresh-loading branch that installs the world object used at
   owner+250: determine how +20 resolves into local world assets and what
   +6d0/+6e0 select. The completion path is 1587f70 -> 16303c0; the alternative
   loaded-world path is 159e3c0 -> 16303c0. These are precise anchors, not a
   request for another broad probe.
2. Resolve the tagged +500 producer and remaining required catalog/stat
   fields before calling a generated snapshot semantically complete.
3. Build a typed local-world template from supported asset keys and explicit
   defaults; join local character/session/item state, then encode through
   the existing dictionary-aware codec. No per-session retail values or
   opaque replay tail should be embedded.

Reset routine fa6600 -> 11634f0 and validator fe2e10 are useful structural
evidence, **not** evidence that an all-zero model is valid. The validator
checks a restricted signed field and pose numeric validity; it does not
prove required asset references or gameplay state are present.

## Verification

Six new comparison tests cover reference-index independence, unresolved
reference rejection, bit-exact float equality, redaction, minimum input
count, and the three private capture regressions including both character
bindings and item-reference overlaps. Private tests skip when evidence is
unavailable. `python3 -m unittest discover -s tests -p 'test_*world*.py'`
passes all 41 tests, including these six. This analysis does not establish
world loading in a game run.
