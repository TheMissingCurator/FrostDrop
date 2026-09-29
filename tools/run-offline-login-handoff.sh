#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: run-offline-login-handoff.sh GAME_DIRECTORY COMPATDATA_DIRECTORY [off|on]" >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
handoff_sweep=${3:-off}
if [[ $handoff_sweep != off && $handoff_sweep != on ]]; then
    echo "Sweep mode must be off or on." >&2
    exit 2
fi
exec "$script_dir/run-offline-integration.sh" "$1" "$2" "tctd-handoff-$handoff_sweep"
