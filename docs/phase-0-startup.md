# Phase 0: startup boundary

## Question

What is the first observable difference between a normal launch and a launch
performed with the PC disconnected from the network?

This phase does not modify the game, Ubisoft Connect, DNS, certificates, or
the Windows hosts file.

## Before testing

Record these facts in `research/startup-observations.md`:

- Storefront: Ubisoft Connect, Steam, or Epic
- Game edition and installed DLC
- Installation directory
- Windows version
- Ubisoft Connect version
- Whether Ubisoft Connect's ordinary Offline Mode has previously been enabled
- Exact game version shown by the launcher or executable
- On Linux: distribution, kernel, GPU/driver, and exact Proton version

Make a backup of any local save/configuration directories before testing. Do
not copy your Ubisoft Connect credential store into this repository.

## Linux with Steam Proton

The Steam release has AppID `365590`. Its default Wine prefix is normally in:

```text
<Steam-library>/steamapps/compatdata/365590/pfx/
```

Pin one Proton version in Steam under **Properties > Compatibility**. Do not
change Proton versions between the connected and disconnected tests because a
launcher regression would invalidate the comparison.

In **Properties > General > Launch Options**, enable Valve's Proton log:

```text
PROTON_LOG=1 PROTON_LOG_DIR="/absolute/path/to/ProjectISAC/evidence/proton-logs" %command%
```

Create the log directory if needed:

```bash
mkdir -p ./evidence/proton-logs
```

Run the connected capture from the Project ISAC directory:

```bash
./tools/capture-startup-linux.sh connected \
  "/path/to/steamapps/common/Tom Clancy's The Division" \
  "/path/to/steamapps/compatdata/365590"
```

After a successful menu launch, repeat while physically disconnected:

```bash
./tools/capture-startup-linux.sh disconnected \
  "/path/to/steamapps/common/Tom Clancy's The Division" \
  "/path/to/steamapps/compatdata/365590"
```

The compatdata argument is optional but strongly recommended. Use the
`compatdata/365590` directory, not its `pfx` child.

Before the disconnected test, put Steam into its supported Offline Mode while
still connected, exit Steam cleanly, disconnect networking, and reopen Steam.
This avoids confusing a Steam startup failure with a Division startup failure.

If the connected launch does not reach the menu, stop there. First establish a
known-good Proton/Ubisoft Connect combination; otherwise the comparison says
nothing about the game's server dependency.

## Windows alternative

### Test A: connected baseline

1. Close the game and Ubisoft Connect completely.
2. Open PowerShell in this repository.
3. Run:

   ```powershell
   .\tools\capture-startup.ps1 -Label connected -InstallDir "D:\path\to\The Division"
   ```

4. When prompted, launch the game normally and wait until the main menu is
   stable.
5. Return to PowerShell and press Enter.
6. Record what appeared and the approximate timestamps.

### Test B: cold disconnected launch

1. Close the game and Ubisoft Connect completely.
2. Disable Wi-Fi and unplug Ethernet. Confirm that Windows reports no network.
3. Run:

   ```powershell
   .\tools\capture-startup.ps1 -Label disconnected -InstallDir "D:\path\to\The Division"
   ```

4. Launch it through the same storefront and wait for either the menu or a
   stable error.
5. Return to PowerShell and press Enter.
6. Record the exact error text/code and which processes appeared.
7. Restore the network only after the capture has finished.

Do not repeatedly retry an error; one clean attempt is more useful.

## Focused backend packet capture

After the ordinary startup boundary has been established, Linux users can
capture only the dedicated Division TCP ports while retaining the normal
process and socket timeline:

```bash
ISAC_CAPTURE_BACKEND=1 ./tools/capture-startup-linux.sh backend-protocol \
  "/path/to/steamapps/common/Tom Clancy's The Division" \
  "/path/to/steamapps/compatdata/365590"
```

The script asks for sudo before launch because packet capture requires raw
socket access. Its filter includes only TCP ports 51000, 55000, and 55002;
ordinary web, Ubisoft account, Steam, and DNS traffic are excluded. It writes
`backend-ports.pcap` and a payload-free `backend-packets-summary.txt` inside
the evidence directory.

Treat the PCAP as private even with the narrow filter. The custom game
protocol may contain opaque session material.

Analyze its framing and unencrypted TLS handshake metadata without displaying
payload bytes or hashes:

```bash
./tools/analyze-backend-pcap.py evidence/<capture>/backend-ports.pcap
```

The analyzer supports classic PCAP with Ethernet, raw IPv4, Linux cooked v1,
or Linux cooked v2 link layers. Payload equality is represented by local class
labels such as `P005`; the underlying bytes and hashes are never printed.

When the Proton launch options include Wine's `winsock` debug channel, isolate
the full game process and summarize only the dedicated service sockets with:

```bash
./tools/analyze-winsock-trace.py evidence/<capture>/steam-365590.log
```

The tool auto-detects the `thedivision.exe` process with the largest Winsock
trace. It reports endpoints, socket handles, thread IDs, and API call counts;
it does not inspect or print network payloads.

### Optional Test C: Ubisoft Connect Offline Mode

Use the launcher's ordinary, supported Offline Mode while physically
disconnected and repeat the capture as `offline-mode`. This establishes
whether cached launcher entitlement is enough to start `TheDivision.exe`.

## Interpreting the first result

| Observation | Likely first boundary |
| --- | --- |
| Game process never starts | Storefront/launcher entitlement or launch orchestration |
| Game starts, then immediately reports a connection error | Game authentication/session bootstrap |
| Menu appears but no character is available | Profile/character service |
| Character selection works but the world will not load | World-session allocation or simulation server |

On Linux, also check whether the corresponding `steam-365590.log` shows
`TheDivision.exe`. If it does not, the failure may still be in Steam, Proton,
or Ubisoft Connect rather than in the game protocol.

This classification is provisional. It tells us which component to study
next; it does not prove that later systems are local.

## Sharing results safely

The generated `summary.txt`, `processes-*.csv`, `connections-*.csv`, and
`executables.sha256` files contain metadata only. Review them anyway before
sharing. Do not upload launcher logs or packet captures without checking them
for account identifiers, tokens, local usernames, and unrelated network
activity.
