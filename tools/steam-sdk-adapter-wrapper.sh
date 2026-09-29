#!/usr/bin/env bash
set -euo pipefail
adapter_script_dir=${BASH_SOURCE[0]%/*}
[[ $adapter_script_dir != "${BASH_SOURCE[0]}" ]] || adapter_script_dir=.
source "$adapter_script_dir/steam-helper-env.sh"
adapter_project=$(cd -- "$adapter_script_dir/.." && pwd)
if (( $# == 0 )); then
    echo "Usage: steam-sdk-adapter-wrapper.sh STEAM_COMMAND [ARGUMENT ...]" >&2
    exit 2
fi
# No host-network fallback. Saved game-only variables stay inert until launch.
exec /usr/bin/python3 "$adapter_project/tools/isac-netns.py" join-game -- \
    /usr/bin/python3 "$adapter_project/tools/sdk_adapter_test.py" launch -- "$@"
