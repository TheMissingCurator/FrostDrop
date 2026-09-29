#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: steam-offline-wrapper.sh STEAM_COMMAND [ARGUMENT ...]" >&2
    exit 2
fi

export ISAC_STACK_PROBE=1
export ISAC_LOCAL_BACKEND_BRIDGE=1
export ISAC_LOCAL_BACKEND_INJECT=1
export ISAC_LOCAL_BACKEND_ISOLATE_TYPE3=1
export ISAC_WORLD_BOOTSTRAP_PROBE=1
export ISAC_WORLD_BOOTSTRAP_REPLAY=1

exec "$@"
