#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: steam-tctd-pc-connected-wrapper.sh STEAM_COMMAND [ARGUMENT ...]" >&2
    exit 2
fi

export ISAC_STACK_PROBE=1
export ISAC_TRANSPORT_STARTUP_PROBE=1
unset ISAC_TCTD_PC_LOOPBACK
unset ISAC_LOCAL_BACKEND_BRIDGE

exec "$@"
