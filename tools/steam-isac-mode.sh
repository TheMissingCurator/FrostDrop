#!/usr/bin/env bash
set -euo pipefail
mode_script_dir=${BASH_SOURCE[0]%/*}
[[ $mode_script_dir != "${BASH_SOURCE[0]}" ]] || mode_script_dir=.
source "$mode_script_dir/steam-helper-env.sh"
mode_project=$(cd -- "$mode_script_dir/.." && pwd)
exec /usr/bin/python3 "$mode_project/tools/steam_isac_mode.py" "$@"
