# SnowDrop

Research notes and documentation from an ongoing effort to understand the PC version of *Tom Clancy’s The Division* and its startup, network, profile, and world-session behavior. The work was recorded under the name Project ISAC.

## Read the research

- [Startup observations](research/startup-observations.md) introduce the initial network and process observations.
- [Numbered findings](research/) record experiments, evidence, interpretations, and corrections in chronological order. Start with [finding 001](research/findings-001-launcher-boundary.md) and follow the numbered sequence. The most recent note, [finding 150](research/findings-150-cover-vault-live-value-probe.md), describes a probe that has **not yet produced a retail measurement**.
- [Architecture notes](docs/architecture.md) describe the investigated service boundaries.
- [Documentation](docs/) preserves test procedures and implementation notes from the research.

This publication contains documentation only. The backend, instrumentation source, binaries, game files, and private captures are not included. Commands in historical notes may refer to those unpublished files and are not runnable from this repository alone. Absolute paths from the original workstation have been replaced with `/path/to/...` placeholders.

Findings are point-in-time observations. Later notes may revise earlier interpretations; read the dated evidence and stated limits before relying on a claim.
