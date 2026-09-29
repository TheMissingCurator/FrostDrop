#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 status|install|restore GAME_DIRECTORY [--retail-only|--retail-profile|--retail-finalization|--retail-handshake|--retail-tutorial|--retail-presentation|--retail-vault-state]" >&2
    exit 2
}

if [[ $# -ne 2 && $# -ne 3 ]]; then
    usage
fi

action=$1
game_dir=$2
expected_retail_hash=df220db2dd4f0f668a91a0c4dd5f370e7d5abc7a2f655f90776c2fc032f70ea8

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
probe="$project_dir/dist/uplay_probe/uplay_r1_loader64.dll"
build_args=()
if [[ $# -eq 3 ]]; then
    [[ $3 == --retail-only || $3 == --retail-profile || $3 == --retail-finalization || $3 == --retail-handshake || $3 == --retail-tutorial || $3 == --retail-presentation || $3 == --retail-vault-state ]] || usage
    probe="$project_dir/dist/uplay_retail_probe/uplay_r1_loader64.dll"
    [[ $3 != --retail-profile ]] || probe="$project_dir/dist/uplay_retail_profile/uplay_r1_loader64.dll"
    [[ $3 != --retail-finalization ]] || probe="$project_dir/dist/uplay_retail_finalization/uplay_r1_loader64.dll"
    [[ $3 != --retail-handshake ]] || probe="$project_dir/dist/uplay_retail_handshake/uplay_r1_loader64.dll"
    [[ $3 != --retail-tutorial ]] || probe="$project_dir/dist/uplay_retail_tutorial/uplay_r1_loader64.dll"
    [[ $3 != --retail-presentation ]] || probe="$project_dir/dist/uplay_retail_presentation/uplay_r1_loader64.dll"
    [[ $3 != --retail-vault-state ]] || probe="$project_dir/dist/uplay_retail_vault_state/uplay_r1_loader64.dll"
    build_args=("$3")
fi
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
    if [[ -f $probe ]]; then
        echo "Built probe:     $(hash_file "$probe")"
    else
        echo "Built probe:     MISSING"
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
        if [[ -L $active_loader || -L $original_loader || -L $probe ]]; then
            echo "Refusing a symlink loader, backup or probe." >&2
            exit 1
        fi
        if [[ ${#build_args[@]} -gt 0 && -f $active_loader ]]; then
            active_hash=$(hash_file "$active_loader")
            prior_probe="$project_dir/dist/uplay_retail_probe/previous/$active_hash.dll"
            known_previous=false
            # Initial tested forwarding baseline predates build archival.
            if [[ $active_hash == c78ef4052865cb3cd5f73d3b413177396fd57d45e7a71008b2cdf3c5b4181eb7 ]]; then
                known_previous=true
            elif [[ -f $prior_probe && ! -L $prior_probe && $(hash_file "$prior_probe") == "$active_hash" ]]; then
                known_previous=true
            fi
            for variant in uplay_retail_probe uplay_retail_profile uplay_retail_finalization uplay_retail_handshake uplay_retail_tutorial uplay_retail_presentation uplay_retail_vault_state; do
                for candidate in "$project_dir/dist/$variant/uplay_r1_loader64.dll" "$project_dir/dist/$variant/previous/$active_hash.dll"; do
                    if [[ -f $candidate && ! -L $candidate && $(hash_file "$candidate") == "$active_hash" ]]; then
                        known_previous=true
                    fi
                done
            done
            if [[ $active_hash != "$expected_retail_hash" ]] &&
               { [[ ! -f $probe ]] || [[ $active_hash != "$(hash_file "$probe")" ]]; } && ! $known_previous; then
                echo "Restore the retail loader before switching probe implementations." >&2
                exit 1
            fi
        fi
        if [[ ! -f $probe ]]; then
            "$project_dir/tools/build-uplay-probe.sh" "${build_args[@]}"
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
                echo "Active loader does not match the analyzed retail build; refusing." >&2
                show_status >&2
                exit 1
            fi
            mv -- "$active_loader" "$original_loader"
        fi

        if ! install -m 0644 -- "$probe" "$active_loader"; then
            if [[ ! -f $active_loader && -f $original_loader ]]; then
                cp -p -- "$original_loader" "$active_loader"
            fi
            echo "Probe installation failed; restored the retail loader when needed." >&2
            exit 1
        fi

        echo "Probe installed. Original backup retained at:"
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
