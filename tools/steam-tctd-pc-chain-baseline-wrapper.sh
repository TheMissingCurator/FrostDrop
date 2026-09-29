#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: steam-tctd-pc-chain-baseline-wrapper.sh STEAM_COMMAND [ARGUMENT ...]" >&2
    exit 2
fi

export ISAC_STACK_PROBE=1
export ISAC_CODE_PROBE=1
export ISAC_LOCAL_BACKEND_BRIDGE=1
export ISAC_TRANSPORT_STARTUP_PROBE=1
export ISAC_TCTD_CHAIN_PROBE=1
export ISAC_TCTD_CHAIN_REMOTE=1
unset ISAC_TCTD_PC_LOOPBACK

exec "$@"
