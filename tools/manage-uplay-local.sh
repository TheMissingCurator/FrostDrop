#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 status|install|restore GAME_DIRECTORY" >&2
    exit 2
}

if [[ $# -ne 2 ]]; then
    usage
fi

action=$1
game_dir=$2
expected_retail_hash=df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
shim="$project_dir/dist/uplay_local/uplay_r1_loader64.dll"
active_loader="$game_dir/uplay_r1_loader64.dll"
original_loader="$game_dir/uplay_r1_loader64_isac_original.dll"

if [[ ! -d $game_dir || ! -f $game_dir/thedivision.exe ]]; then
    echo "Not a Division game directory: $game_dir" >&2
    exit 2
fi

hash_file() {
    sha256sum -- "$1" | awk '{ print $1 }'
}

show_status() {
    if [[ -f $active_loader ]]; then
        echo "Active loader:   $(hash_file "$active_loader")"
    else
        echo "Active loader:   MISSING"
    fi
    if [[ -f $original_loader ]]; then
        echo "Original backup: $(hash_file "$original_loader")"
    else
        echo "Original backup: MISSING"
    fi
    if [[ -f $shim ]]; then
        echo "Built local:     $(hash_file "$shim")"
    else
        echo "Built local:     MISSING"
    fi
}

require_stopped_processes() {
    local matches
    matches=$(
        ps -eo pid=,comm= |
            awk '$2 == "thedivision.exe" ||
                 $2 == "upc.exe" ||
                 $2 == "UbisoftGameLaun" { print }'
    )
    if [[ -n $matches ]]; then
        echo "Division or Ubisoft Connect is still running:" >&2
        echo "$matches" >&2
        echo "Stop those processes cleanly before changing the loader." >&2
        exit 1
    fi
}

case $action in
    status)
        show_status
        ;;

    install)
        require_stopped_processes
        if [[ ! -f $shim ]]; then
            "$project_dir/tools/build-uplay-local.sh"
        fi
        if [[ -f $original_loader ]]; then
            if [[ $(hash_file "$original_loader") != $expected_retail_hash ]]; then
                echo "Existing original backup has an unexpected hash; refusing." >&2
                show_status >&2
                exit 1
            fi
        else
            if [[ ! -f $active_loader ]]; then
                echo "Retail loader is missing; refusing." >&2
                exit 1
            fi
            if [[ $(hash_file "$active_loader") != $expected_retail_hash ]]; then
                echo "Active loader is not the verified retail DLL; refusing to create backup." >&2
                show_status >&2
                exit 1
            fi
            mv -- "$active_loader" "$original_loader"
        fi
        if ! install -m 0644 -- "$shim" "$active_loader"; then
            if [[ ! -f $active_loader && -f $original_loader ]]; then
                cp -p -- "$original_loader" "$active_loader"
            fi
            echo "Local shim installation failed; restored retail when needed." >&2
            exit 1
        fi
        echo "Standalone local shim installed. Original backup retained at:"
        echo "$original_loader"
        show_status
        ;;

    restore)
        require_stopped_processes
        if [[ ! -f $original_loader ]]; then
            echo "Original backup is missing; refusing." >&2
            exit 1
        fi
        if [[ $(hash_file "$original_loader") != $expected_retail_hash ]]; then
            echo "Original backup has an unexpected hash; refusing." >&2
            show_status >&2
            exit 1
        fi
        install -m 0644 -- "$original_loader" "$active_loader"
        echo "Retail loader restored. The verified backup was retained."
        show_status
        ;;

    *)
        usage
        ;;
esac
