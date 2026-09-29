# Read-only retail character-finalization trace

This is a connected retail test on the user's own account. Ubisoft Connect,
Steam and the retail server remain in use. The temporary forwarding DLL calls
the verified original Ubisoft loader. No backend, isolation, debugger, response
change or live-world modification is used.

The observer uses four attested execution-breakpoint sites: profile create
request, create reply, profile list reply, and the generic outbound writer.
The latter examines a bounded temporary envelope, discards login-bearing
types, and saves only the 16-byte character ID of a world-channel 147-byte
`0x000c` submission. It does not save its payload or any token. Profile lists
remain private because they contain IDs and character presentation blobs.
The observer can miss events on unsampled threads, or stop at its 20-minute,
12,000-hit or 64-result bound; absence of an event is not proof it did not run.

## Prepare and run

Close Division and Ubisoft Connect. The checked retail loader must be active
before installation. From the project directory:

```sh
bash tools/build-uplay-probe.sh --retail-finalization
bash tools/manage-uplay-probe.sh install \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-finalization
```

Steam launch option:

```text
"/path/to/ProjectISAC/tools/steam-finalization-probe.sh" -- %command%
```

Keep network on. Create one character only in the free retail slot; do not
delete another character. Finish the mirror customization, enter the tutorial,
then return to character selection as soon as practical and quit. That gives
the narrowest before/after profile list around finalization. If returning to
selection is unavailable, quit normally. No combat or mission completion is
needed for this capture.

The capture is `evidence/*-retail-finalization-*/finalization-private/`.
Summarize without printing IDs or blobs:

```sh
python3 tools/inspect-retail-profile.py "evidence/YOUR-retail-finalization-CAPTURE"
```

When the game and Ubisoft Connect are closed, restore the verified original:

```sh
bash tools/manage-uplay-probe.sh restore \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-finalization
```

Clearing Steam launch options alone does not restore the on-disk DLL. This
trace should establish timing/correlation; a second targeted producer trace
may still be needed to prove which server request commits the profile state.
