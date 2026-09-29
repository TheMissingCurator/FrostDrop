#!/usr/bin/env bash
set -euo pipefail
if [[ $# -eq 0 ]]; then
    echo "Usage: steam-startup-leads-wrapper.sh STEAM_COMMAND [ARGUMENT ...]" >&2
    exit 2
fi
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for variable in "${!ISAC_@}"; do unset "$variable"; done
umask 077
capture_dir=$(mktemp -d "$project_dir/private/startup-leads-XXXXXXXX")
touch "$capture_dir/resolvers.tsv"
touch "$capture_dir/static-rdata.bin"
export ISAC_STARTUP_LEADS_FILE="Z:${capture_dir//\//\\}\\resolvers.tsv"
export ISAC_STARTUP_STATIC_FILE="Z:${capture_dir//\//\\}\\static-rdata.bin"
export ISAC_STARTUP_LEADS=1
export ISAC_STACK_PROBE=1
export ISAC_LOCAL_BACKEND_BRIDGE=1
export ISAC_TRANSPORT_STARTUP_PROBE=1
export ISAC_TCTD_PC_LOOPBACK=1
export ISAC_TCTD_LOCAL_ACCEPT=1
export ISAC_TCTD_ECHO_LOCAL=1
exec "$@"
