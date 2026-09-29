# Experimental local SDK session and configuration

**Isolation update:** [findings-075](findings-075-network-namespace.md) replaces
the host-network-off requirement below with shared network-namespace isolation.
The runner command and Steam launch options are unchanged; keep the host online.
The preflight instructions below describe the initial revision only.

Date: 2026-09-26. Implementation following findings-072/073, not a successful
game capture. No live Ubisoft request was made for this implementation.

## Added

- `src/isac_backend/sdk_services.py`: fixed-loopback HTTP service on 55003.
  Candidate POST `/vN/profiles/sessions`, authenticated GET
  `/vN/applications/{applicationId}/configuration`, authenticated DELETE sessions.
  Unknown routes return 404, never forward or redirect to another service.
- Synthetic profile/user ID agrees with `src/uplay_local/local.c`. Session IDs,
  tokens and tickets are freshly generated, expire after three hours, and
  exist only in memory. This is not ownership verification or character data.
- Session response supplies the traced fields, ISO-8601 timestamps and the
  exact `Prod` enum spelling (literal at RVA 0x347101c; comparison at
  0x2173843). Placeholder spaceId and `uplay` platformType remain assumptions.
- Configuration uses direct sections, typed resources and all 30 explicit
  feature switches. Everything/HttpClient are true; Connection/WebSocketClient
  and other optional SDK features are false. This is an experimental minimum,
  not proof that later game code needs no other feature. Resources beyond
  sessions/applications have not been implemented.
- Opt-in `ISAC_SDK_LOCAL=1` replaces the exact NUL-terminated SDK base URL
  literal at RVA 0x3471510 with `http://127.0.0.1:55003/{version}` in memory.
  The existing executable metadata gate plus exact bytes, region bounds and
  page protection checks must pass. A mismatch terminates the process rather
  than silently continuing with that retail template. The original protection
  is restored; the executable on disk and global certificate trust are untouched.
  This is not an executable-content hash check.
- Patch runs during the first local launcher export's one-time initialization.
  No new sweep or instruction hooks. SDK descriptor constructors pass the
  literal to string constructor 0x211abe0 without a hardcoded original length
  (session call 0x214b026).
- `SDK_LOCAL_ROUTE_READY` proves template replacement only. Whether descriptors
  were copied earlier, HTTP is accepted, the JSON is accepted, or tickets reach
  game auth must be established by the next run.

## Runner and isolation boundary

`run-offline-integration.sh GAME COMPAT sdk-local` starts the SDK service plus
existing certificate, directory, latency and main-channel listeners. The Steam
wrapper is `steam-login-handoff-wrapper.sh --sdk-local`; thread sweep stays off.
The service PID is cleaned up with the other listeners and `sdk-services.log`
is copied to evidence. Request logs contain route class, status and response
size, not input URLs, headers, account tokens or response bodies. They cap at
1000 events. The startup packet filter deliberately excludes plaintext 55003.

Runner and wrapper refuse to start while any non-loopback interface is
administratively UP. They do not change interfaces, firewall rules or namespaces.
**This preflight is not persistent isolation. Keep all external networking
disabled until the game has exited.** Re-enabling it during the run invalidates
the isolation assumption. Other retail URLs may remain in defaults or unrelated
networking code; local routing and SDK switches alone cannot prevent egress.

## Next capture and interpretation

With the game stopped, set Steam launch options:

```text
"/path/to/ProjectISAC/tools/steam-login-handoff-wrapper.sh" --sdk-local %command%
```

Disable external networking, then run:

```sh
./tools/run-offline-integration.sh \
  "/path/to/SteamLibrary/steamapps/common/Tom Clancy's The Division" \
  "/path/to/SteamLibrary/steamapps/compatdata/365590" \
  sdk-local
```

Press Enter when services are ready to begin capturing, launch through Steam,
and stop at the first stable result. Exit the game and finish the capture prompt.
Do not reuse the old wrapper without `--sdk-local`.

Evidence ladder:

1. `SDK_LOCAL_ROUTE_READY` — literal patched, not proof of a request.
2. `SDK_HTTP route=session-create status=200` — synthetic response sent.
3. `SDK_HTTP route=configuration status=200` — client used issued session
   header and ticket to request configuration; strong evidence of session uptake.
4. Existing handoff analysis — configuration acceptance/ticket publication,
   auth-client creation and port-55001 connection still need client evidence.

Even step 4 is not world loading: encrypted main-backend login/world responses
are still unimplemented. The prior plaintext replay protocol is not that wire
format. Failure at any earlier stage is diagnostic, not a playable backend.

## Verification

Python tests cover session lifecycle/expiry/capacity, identity and config shape,
actual HTTP session/config/logout roundtrip, malformed and oversized bodies,
ambiguous framing, unsupported routes, credential-log redaction and log limits.
Network-preflight tests cover interface flags and wrapper refusal/environment.
Native Wine test exercises the real patch helper against synthetic memory:
bounds, signature mismatch, no-access rejection, shorter replacement, padding,
adjacent bytes, repeated-call refusal and read-only protection restoration.
These are synthetic tests, not execution of the retail SDK JSON parser.

Validation completed: all 200 Python tests passed, native SDK-route Wine smoke
passed, existing standalone Uplay-shim Wine smoke passed, and changed shell
scripts passed `bash -n`. The tested DLL was installed with SHA-256
`3d96c4bb685b35d60c327b4e95ad1a0a2d5642c8e6fab3870ab7cb091d9c4c19`;
the verified retail backup was retained. No game launch was performed here.
