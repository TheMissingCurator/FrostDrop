# Targeted retail character creation capture

This is a connected retail test. Normal Steam/Ubisoft Connect and account
ownership checks remain in place. The forwarding DLL calls the original loader.
No GDB, local backend, namespaces, response injection or world replay is used.
The executable and game data are not modified. A forwarding DLL is installed
temporarily, retaining the verified original loader backup.

## Prepared capture

Four hardware observation sites capture only:

1. `profile_client` create request (type 5): request ID and two flags.
2. Create response (type 6): request ID, status, returned identifier on success.
3. Profile list response (type 2): header and up to eight character entries,
   including each bounded character blob (up to 10,000 bytes).
4. Profile token response (type 8): request ID, status, two strings and two
   optional-section flags. **Live token blobs and the world stream are omitted.**

Payload files contain decoded fields re-encoded in canonical order, **not raw
network packets**. Parsed string semantics are retained; original varint encoding,
string terminators/embedded-NUL wire details and original packet boundaries are
not preserved. These files are reference evidence, not replay-ready world saves.

Each process waits up to 30 seconds for verified code signatures. Once ready,
observation lasts up to 20 minutes or 64 records/12,000 hits. Expiry stops only
observation, not the game. Threads are sampled every 100 ms (up to 256 retained
thread handles); absence of an event is not conclusive proof that it never ran.
Existing hardware-debug-register owners are skipped, not overwritten.

## Install and launch

Division and Ubisoft Connect must be closed before installing. Run from the
project directory if the assistant has not already installed this build:

```sh
bash tools/build-uplay-probe.sh --retail-profile
bash tools/manage-uplay-probe.sh install \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-profile
```

Use this Steam launch option:

```text
"/path/to/ProjectISAC/tools/steam-profile-probe.sh" -- %command%
```

Keep the network **on**. This uses real retail servers and changes made in the
retail UI are real account changes. No Enter prompt or separate backend terminal.
Only create a character if you have a free slot; never delete an existing
character for the capture. If no slot is free, stop at character selection.

Within the observation window:

1. Reach character selection with the existing characters.
2. Create one new character in an unused slot.
3. Continue until the first playable tutorial area, if possible.
4. Return to character selection to obtain the updated list, then quit normally.

The goal is the creation exchange and a subsequent list containing the returned
identifier. No extended combat or tutorial completion is needed. If returning
to selection is unavailable, quit; do not discard the character just to force it.

## Inspect and restore

Captures are under `evidence/*-retail-profile-*/profile-private/`. The parent
directory is mode 0700, metadata is 0600, and the inherited umask is 0077.
Treat all raw JSONL and Proton logs as private. A redacted summary is available:

```sh
python3 tools/inspect-retail-profile.py "evidence/YOUR-retail-profile-CAPTURE"
```

The summary reports IDs only as correlation integers, counts, status and blob
lengths; it does not print account/character identifiers, strings or blob contents.
An `incomplete-field-capture` or missing `end` record must not be treated as a
complete trace. Per-process `refused` records from Ubisoft's launcher can be
normal; the game process must also have a `ready` record and target events.

After the game and Ubisoft Connect are closed, restore before switching back
to custom mode (which requires the original retail DLL on disk):

```sh
bash tools/manage-uplay-probe.sh restore \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-profile
```

Clearing launch options disables observation but does not restore the DLL.
No account data or captured credentials are imported into the local backend.
