#!/usr/bin/env bash
set -euo pipefail
if [[ $# -eq 0 ]]; then
    echo "Usage: steam-tctd-allocation-wrapper.sh STEAM_COMMAND [ARGUMENT ...]" >&2
    exit 2
fi
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# Remove inherited probe flags so the four hardware slots have one owner.
for isac_name in ${!ISAC_@}; do unset "$isac_name"; done
umask 077
capture_dir=$(mktemp -d "$project_dir/private/tctd-allocation-XXXXXXXX")
touch "$capture_dir/records.bin"
capture_windows="Z:${capture_dir//\//\\}\\records.bin"
export ISAC_TCTD_ALLOCATION_FILE="$capture_windows"
export ISAC_STACK_PROBE=1
export ISAC_LOCAL_BACKEND_BRIDGE=1
export ISAC_TRANSPORT_STARTUP_PROBE=1
export ISAC_TCTD_ALLOCATION_CAPTURE=1
exec "$@"
