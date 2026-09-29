# Finding 054: full offline integration stage

Date: 2026-09-25

The successful disconnected standalone-Uplay result makes it possible to test
the complete Project ISAC chain in one run. All three retained private world
artifacts validate as self-contained `ISACWBS1` streams:

| Slice | Spans | Frames | Duration |
| --- | ---: | ---: | ---: |
| First gate | 464 | 730 | 18.786 s |
| Stable hub | 1,348 | 7,820 | 58.081 s |
| Full continuation/actions | 7,082 | 51,280 | 328.562 s |

`tools/run-offline-integration.sh` now chooses the full continuation/actions
slice by default. It verifies that the standalone Uplay DLL is active,
validates the private login/control profile and replay, refuses to collide with
an existing listener on port 55000, starts the local bootstrap server, invokes
the ordinary Linux evidence capture, and stores the server transcript and
artifact hashes alongside that evidence. Backend cleanup is automatic.

The first attempted combined run reached ROMEO `P-59-100`. Its evidence had no
stack or dispatch log and the backend had no captured client transcript. The
standalone Uplay shim was active, but none of the bridge/replay environment
reached Division, so the game followed its ordinary unavailable-server path.
This is a launch-configuration failure rather than a local-protocol result.

The runner now prints a single Steam wrapper launch option and waits for an
explicit confirmation after it is saved. The wrapper exports all six required
environment switches into Proton. Backend termination is bounded and its log
is copied during cleanup as well as successful completion, preventing an
interrupted shutdown from losing the transcript.

This combined test intentionally includes every already-proven component. It
does not assume that the disconnected run will immediately reach an
interactive world: the current replay injector originally selected its world
reader after a small genuine transport delivery. If that delivery is absent,
the combined logs should identify that reader/source association as the next
implementation boundary without requiring separate login, hub, and gameplay
captures.
