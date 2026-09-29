# Focused retail instance handshake capture

This is a connected retail test using the normal Steam/Ubisoft Connect ownership
and login path. The temporary forwarding DLL calls the verified original loader.
No local backend, GDB, network isolation, response replacement or world replay is
used. The current local backend responses are unchanged.

## What one run captures

Four hardware execution observation sites cover:

1. Parsed auth reply (type `0x0003`): three token fingerprints and deadlines.
2. Parsed discovery join reply (type `0x0006`): success, scalar fields, instance
   and location string fingerprints, and the returned token fingerprint.
3. Instance connect request serialization (type `0x0000`): all three token
   slots and the optional fourth slot, preserving their order.
4. Parsed game connect reply (type `0x0002`): the fingerprint/zero status of
   its 16-byte prefix and the following boolean. The boolean's meaning is not
   yet established; capturing it does not by itself prove world readiness.

Tokens are read briefly into bounded scratch memory, SHA-256 hashed and scrubbed.
Only lengths, fingerprints and deadlines enter the observation queue or JSONL;
no reusable raw bearer is saved. Remaining lifetimes are estimates derived from
client-local absolute epoch-second deadlines, not the exact incoming wire TTL.
Account names, player identifiers and world payloads are not collected by this
observer. Treat the JSONL and normal Proton logs as private nevertheless.

Observation waits up to 30 seconds for verified code signatures, then lasts up
to five minutes or 64 records/12,000 hits. Expiry stops observation, not the game.
Threads are sampled every 100 ms, with up to 256 retained thread handles.
Existing hardware-debug-register owners are skipped. No executable code patch,
trampoline or VirtualProtect call is used. Each drained record is flushed to disk;
the last queued observations can still be lost on an abrupt process exit.

## Install and launch

Close Division and Ubisoft Connect before installation. If the assistant has
already installed this build, skip these commands:

```sh
bash tools/build-uplay-probe.sh --retail-handshake
bash tools/manage-uplay-probe.sh install \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-handshake
```

Use this Steam launch option:

```text
"/path/to/ProjectISAC/tools/steam-handshake-probe.sh" -- %command%
```

Keep networking **on**. Select an existing character, press Continue, wait until
the playable world has loaded, then quit normally. No new character, inventory
changes, combat, extended gameplay, Enter prompt or backend terminal is needed.
This is the real retail account; any gameplay changes still affect that account.

## Inspect and restore

Captures are written to `evidence/*-retail-handshake-*/handshake-private/`.
Capture directories are mode 0700 and files inherit umask 0077. Get a redacted
summary without printing credentials or fingerprints:

```sh
python3 tools/inspect-retail-handshake.py "evidence/YOUR-retail-handshake-CAPTURE"
```

The summary correlates instance slot fingerprints with the auth slots and the
discovery join token. Incomplete field captures are ignored. A missing end record
does not invalidate existing complete observations, but absence of an event is
not conclusive. A launcher-process refusal can be normal; look for the game
process's ready record and target observations.

After closing Division and Ubisoft Connect, restore the original loader before
switching back to custom mode, which requires that original DLL on disk:

```sh
bash tools/manage-uplay-probe.sh restore \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  --retail-handshake
```

Clearing Steam launch options disables observation but does not restore the DLL.
The verified original backup is retained. No retail credentials are imported or
replayed by the local backend.
