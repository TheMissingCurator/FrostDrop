# Retail probe launch returned to forwarding DLL

Date: 2026-09-27

User selected the earlier retail forwarding architecture, without GDB or
network isolation. The offline adapter/backend workflow is not changed.

`steam-service-name-probe.sh` now invokes `retail_forward_probe.py`, which
verifies the game executable, original retail backup and installed probe,
strips legacy ISAC options, restores Steam's deferred loader environment and
execs Steam's original argv. It imports no adapter/namespace/debugger module.
There is no child monitor, forced timeout, existing-Wine rejection, backend,
mount or debugger fallback. Old GDB drivers are retained as reference only.

`build-uplay-probe.sh --retail-only` reuses the established 89-export assembly
forwarder and original-loader resolution. It compiles ABI sampling off and
links the separate `retail_probe.c` entry point instead of the large legacy
stack/local-backend implementation. Currently the entry point is intentionally
empty: export-name logging establishes a retail launch baseline. **The type-5
parser/name-lineage observer is not yet ported and no decoded fields are
claimed.** This implementation change must not be represented as completing
the service-name investigation.

Four tests pass, including real Wine in a temporary prefix with a synthetic
original DLL. Forwarded return value/output are preserved even with legacy
ABI, stack, plaintext, adapter, bridge, injection and loopback flags set; no
optional probe logs appear. Other tests verify hash rejection, opaque argv
and environment handling. No real Ubisoft login/game launch was performed.

With filesystem approval, installed retail-only probe SHA-256
`c78ef4052865cb3cd5f73d3b413177396fd57d45e7a71008b2cdf3c5b4181eb7`
replaced the active loader. Existing original backup hash
`df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8`
was retained and verified. No prefix/login data changed. Frozen response
sources retain their findings-100 hashes.

Unlike the previous overlay approach this installation persists when launch
options are cleared. Use `manage-uplay-probe.sh restore GAME_DIRECTORY` with
the game/Connect stopped to return to a pure retail loader or before custom
mode. See `docs/retail-forward-probe.md` for exact commands and limitations.
