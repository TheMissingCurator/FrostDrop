# FrostDrop

Research, documentation, and experimental backend code from an ongoing effort to RE the PC version of *Tom Clancy’s The Division*. The work was recorded under the name Project ISAC. Linux running the Windows game through Steam Proton is the main test environment.

## Notes!

- Low key a vibe coded project! 
- Hopefully this is enough for anyone else to start their own projects! I would much rather have someone competent to work on this then me!
- The backend code is here now, but I still have no clue if it works on other machines besides mine! so yk...


## Read the research

- [Startup observations](research/startup-observations.md) introduce the initial network and process observations.
- [Numbered findings](research/) record experiments, evidence, interpretations, and corrections in chronological order. Start with [finding 001](research/findings-001-launcher-boundary.md) and follow the numbered sequence. The most recent note, [finding 150](research/findings-150-cover-vault-live-value-probe.md), describes a probe that has **not yet produced a retail measurement**.
- [Architecture notes](docs/architecture.md) describe the investigated service boundaries.
- [Documentation](docs/) preserves test procedures and implementation notes from the research.

## Code and current limits

- [`src/isac_protocol/`](src/isac_protocol/) contains the decoded framing and message codecs. [`src/isac_backend/`](src/isac_backend/) contains local authentication, profile, service, and experimental world handlers. [`src/uplay_local/`](src/uplay_local/) and [`src/uplay_probe/`](src/uplay_probe/) contain the Windows compatibility and observation code.
- [`tools/`](tools/) contains the build, launch, capture, and inspection scripts. [`tests/`](tests/) contains synthetic tests and opt-in tests that need a local Steam/Proton setup or private research fixtures. The [SDK adapter guide](docs/sdk-adapter-test.md) describes the current custom launch experiment.
- The local client has reached the Agent Activation tutorial and displayed the next safe-house activity in observed runs. This is a narrow, capture-derived experiment. It is **not a complete or generally playable backend**. Safe-house objective progression, many world messages, rewards, and durable tutorial state are not implemented. Movement and traversal still have unresolved gates, including sprint and vault behavior.
- `CoverVaultIsAllowed` has a read-only retail probe, but its live value has **not been measured**. The missing vault behavior does not justify changing a backend response by guesswork. Dialogue and audio triggers are also unresolved.
- The current workflow has been tested on one local Linux/Proton setup. A clean setup on another machine and a launch independent of Ubisoft infrastructure have not been verified.

Private captures, local profiles, generated certificates and keys, compiled binaries, and original game files are excluded. Some experiments require private capture-derived templates, so publishing the source does not make every historical command reproducible. Bring your own legitimately installed game files; none are distributed here.

Run the source tests with `PYTHONPATH=src python3 -m unittest discover -s tests`. Tests needing Steam/Proton, a debugger, or private research fixtures are opt-in or skipped when their prerequisites are absent. A passing source suite does not establish a playable retail-client session.

Findings are point-in-time observations. Later notes may revise earlier interpretations; read the dated evidence and stated limits before relying on a claim.
