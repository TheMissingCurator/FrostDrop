# Retail tutorial startup and activity capture

This mode observes normal online retail play through a forwarding DLL. Steam
and Ubisoft Connect's normal login/ownership path remains in place. No debugger,
custom backend, namespace, replay, injection or executable-memory patch is used.
The original loader is backed up and verified. Nothing is sent to local services.

## Numpad markers

Turn **Num Lock on**, keep the game focused, and hold a key for about a quarter
second. Markers are sampled approximately every 100 ms; very fast taps can be
missed. Each press records once; holding it does not repeat. You can reuse each
marker for successive events after releasing the key.

| Key | Marker | When to press |
| --- | --- | --- |
| Numpad 1 | World loaded | You first have control in the tutorial area |
| Numpad 2 | Objective started | You begin the chosen objective |
| Numpad 3 | Objective completed | The game shows completion |
| Numpad 4 | AI spawned | You first notice the AI appearing/encounter becoming active |
| Numpad 5 | Safe house entered | You enter the safe house |
| Numpad 6 | Merchant accessed | You open the merchant interface |
| Numpad 7 | Coordinator voice onset | Press when you first **hear** the coordinator line, not when the mission appears |
| Numpad 8 | Vault attempt | Press immediately before trying the chosen obstacle; report afterward whether it succeeded |
| Numpad 9 | Combat started | Enemies engage you or you begin the encounter |
| Numpad 0 | Notable enemy action | Press for an action you can describe afterward (for example takes cover, flanks, fires, throws a grenade); repeat after releasing |
| Numpad Decimal | Combat ended | The encounter has settled and enemies are no longer engaging |

Top-row digits do not trigger markers. Keys are observed, not consumed or
remapped, so any existing in-game numpad bindings still run. Marker 4 is a human
observation, not proof of the exact server spawn timestamp. The enemy-action
marker does not encode *which* action occurred; jot down its type and order
after the run. All markers and
captured chunks use the game's GetTickCount64 time domain. There is no overlay
or audible acknowledgment. Check recorded markers after the run.

## Install and launch

Close Division and Ubisoft Connect first. Skip installation if the assistant
already installed the tested build:

```sh
bash tools/build-uplay-probe.sh --retail-tutorial
bash tools/manage-uplay-probe.sh install \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-tutorial
```

Steam launch option:

```text
"/path/to/ProjectISAC/tools/steam-tutorial-probe.sh" -- %command%
```

Networking stays **on**. No backend terminal or Enter prompt is needed. Use an
existing tutorial character if available. Creating a character is optional and
only appropriate if a free slot exists; never delete a retail character to make
room. Retail actions change your real retail account.

For the dialogue/vault/AI comparison, mark the safe-house handoff with Numpad
2 or 3 as appropriate. Press Numpad 7 only if the coordinator line actually
begins. At one easily identified obstacle, press Numpad 8 just before the
vault input and note the location and success/failure afterward. If you enter
combat naturally, use Numpad 9 at engagement, Numpad 4 when you first notice
AI spawning, Numpad 0 for a small number of distinct enemy actions, and
Numpad Decimal once combat has ended. It is fine to let enemies act briefly
from a safe position; do not put your character at risk merely to extend the
capture. Avoid unnecessary looting or purchases in this focused run. Quit
normally after the marked actions. Stay within roughly 15 minutes to leave
room for launcher/loading time in the 20-minute observer.

An existing retail character is sufficient for vault and combat observations.
If the specific tutorial coordinator line is one-time and unavailable on that
character, a separate new-character run may be needed **only if you have a
free slot**. Do not delete a character or switch to a second world session
inside one capture; the observer intentionally stops at a second world request.

## Captured data and boundaries

The four fixed observation sites are:

- Inbound decrypted delivery: select a previously unseen reader after the
  observed large channel-0 instance-connect request. Synchronize on the 19-byte
  framed game connect reply, accommodating a five-byte setup prefix and
  fragmentation. Capture subsequent bytes of that selected world stream.
- Outbound serialized writer: record only validated channel-0 envelopes from
  the same writer that sent that instance-connect request. Exclude entire
  envelopes containing type 0 or type 2; known credential-bearing connect/login
  payloads are not queued or saved. Other writers/channels are not captured.
- Parsed game connect reply: save its reconstructed 17-byte body, and compare
  it exactly with the selected stream's sync reply. A mismatch stops capture.
- Parsed character-create reply: save status and, on success, the 16-byte new
  character identifier. This is not a complete profile-list capture.

World bytes are original application-stream chunks, not individual network
packets. The inspector reassembles frame boundaries. Connect/create records
come from parsed objects and are explicitly reconstructed, not raw packets.
Known authentication/discovery bearers are excluded, but unknown world payloads
can contain character/account identifiers, other players, inventory, mission
data or other sensitive fields. Treat **all capture files as private**. This
cannot guarantee that every unknown field is credential-free.

The observer does not establish mission, voice, vault, or AI semantics automatically.
In particular, this marker/traffic capture does **not** read the live
`CoverVaultIsAllowed` property or an audio-playback function. Those require a
separate build-attested, read-only client observer before claiming either is
the causal gate.
It provides causal candidates and startup bytes to study client readers and
consumers. It does not turn those bytes into a local tutorial implementation.
Interactions carried solely by other channels are outside this capture.

## Limits, inspect and restore

Observation begins after runtime attestation (up to 30 seconds), lasts up to
20 minutes, and is bounded by 64 MiB, 500,000 records, one million traps,
64 readers and 512 retained thread handles. A 256-slot preallocated reusable
queue keeps file writes out of the exception handler. Read, queue, lock or
source-replacement failures stop observation, not gameplay, and mark gaps.
Threads are sampled; pre-armed debug-register owners are skipped. Missing
events are not proof that a request never occurred. Marker timing is approximate.

Files are in `evidence/*-retail-tutorial-*/tutorial-private/`. The launcher sets
directory mode 0700 and umask 0077. The observer flushes drained payloads and
markers every worker pass; queued final records can be lost on abrupt exit.
An end record can be absent after normal process termination as well. Review
gaps, pending frame bytes and connect-reply correlation before decoding.

```sh
python3 tools/inspect-retail-tutorial.py "evidence/YOUR-retail-tutorial-CAPTURE"
```

This prints only frame counts/types, connection metadata and message counts in
three-second-before/five-second-after marker windows, plus aggregate type
counts between each Numpad 9 and Numpad Decimal combat pair. It never prints captured
payload bytes or identifiers. Windows are comparisons, not semantic proof.

For decoded dictionary, world-prefix and reward-structure summaries:

```sh
python3 tools/decode-retail-world.py "evidence/YOUR-retail-tutorial-CAPTURE"
```

This also checks byte-identical round trips for completed codecs and reports
unsupported schemas explicitly. Type `0x0007` now has a complete codec for the
observed empty-dynamic-subobject shape, reported separately under
`type0007_complete_observed_shape`; the legacy prefix diagnostics remain.
Nonempty dynamic subobjects are explicitly unsupported. A complete wire codec
is not a generated world-state implementation. Identifier
and name values are not printed. Unknown message dictionary effects and
observer coverage remain limitations. See
[finding 118](../research/findings-118-retail-tutorial-world-decoding.md) and
[finding 120](../research/findings-120-generated-connect-and-complete-startup-shape.md).

After closing Division and Ubisoft Connect, restore the original loader before
switching back to custom mode:

```sh
bash tools/manage-uplay-probe.sh restore \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-tutorial
```

Clearing launch options disables observation but does not restore the DLL.
No character database or game saves are changed by this probe.
