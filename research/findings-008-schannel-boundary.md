# Finding 008: the dedicated backend does not use the public Schannel boundary

Date: 2026-09-22

Evidence: `evidence/20260922-003048-schannel-trace-connected-linux`

The capture covered entry into the world followed by a skill use. It combined
a dedicated-port PCAP with a Proton trace using the `secur32`, `schannel`, and
DLL-loader Wine debug channels. `tcpdump` recorded 1,226 packets with zero
kernel drops.

## World-session confirmation

The run repeated the previously observed service sequence:

- a short mutual-TLS exchange on port 51000;
- five small parallel probes on port 55002;
- an initial lower-rate port-55000 stream;
- a second, higher-rate port-55000 stream after
  `UPLAY_USER_SetGameSession`.

The second port-55000 stream lasted 31.8 seconds and transferred about 19 KB
from the client and 78 KB from the server. The initial port-55000 stream
transferred about 11 KB out and 14 KB in over 56.8 seconds. This again makes
the second connection the strongest world-simulation candidate. The skill use
occurred while that stream was active.

## Process isolation matters

The Proton log contains thousands of Schannel calls made by Ubisoft Connect.
Those calls are not evidence about the game protocol. The full Division game
process in this run was Windows PID `0x04e0` (decimal 1248), identified by its
load of `thedivision.exe` and independently matched to the forwarding probe's
process ID.

Filtering the Wine trace to PID `0x04e0` showed only security-provider startup:

- `SECUR32_initializeProviders` and package initialization;
- GnuTLS capability checks performed while Wine initialized `secur32.dll`;
- no `InitializeSecurityContext` calls;
- no `EncryptMessage` or `DecryptMessage` calls;
- no Schannel encrypt/decrypt buffer processing.

The capability messages all occurred together during DLL initialization,
before the dedicated backend connections. They do not indicate that the game
used Schannel for those connections.

## Static binary observations

At rest, `thedivision.exe` is protected in `.UBX0`/`.UBX1` sections. Its
ordinary code/data sections have no file content, and useful network or TLS
library strings are not visible in the on-disk image. The executable imports
`WS2_32.dll`, but its normal import table exposes only ordinal 51; the remaining
socket functions are likely resolved after the protected image initializes.

The game-loaded companion modules do not reveal a separate TLS library. In
particular, `gbplayerclient.dll` has no Winsock or crypto imports, and the
retail Uplay bridge imports only Kernel32 and Advapi32. This leaves the
runtime-unpacked game image as the leading owner of the dedicated protocol.

## Conclusion and next boundary

The public Windows SSPI/Schannel API is rejected as the plaintext interception
point for ports 51000 and 55000. The next useful boundary is Winsock: trace
socket handles, function names, thread IDs, endpoints, and transfer lengths,
then correlate the socket-owning threads with the two port-55000 streams.

A later runtime-memory or function-hook experiment may be required to locate
the game's private TLS implementation. Passive PCAP capture alone cannot
recover application messages because the sessions use ephemeral ECDH.
