#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
build_dir="$project_dir/build/uplay_local"
shim="$project_dir/dist/uplay_local/uplay_r1_loader64.dll"
compiler=${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}
wine_command=${ISAC_WINE:-wine}
wineserver_command=${ISAC_WINESERVER:-${WINESERVER:-wineserver}}

"$project_dir/tools/build-uplay-local.sh"
"$compiler" \
    -O2 -Wall -Wextra -Werror \
    -I"$build_dir" \
    "$project_dir/tests/uplay_local_smoke.c" \
    -o "$build_dir/uplay_local_smoke.exe"

test_dir=$(mktemp -d -p /tmp project-isac-uplay-local.XXXXXXXX)
test_prefix="$test_dir/wine-prefix"
trap 'rm -rf -- "$test_dir"' EXIT INT TERM
cp -- "$shim" "$test_dir/uplay_r1_loader64.dll"

WINEPREFIX="$test_prefix" WINEDEBUG=-all "$wine_command" wineboot -u \
    >/dev/null 2>&1
WINEPREFIX="$test_prefix" WINEDEBUG=-all "$wine_command" \
    "$build_dir/uplay_local_smoke.exe" \
    "Z:\\$test_dir\\uplay_r1_loader64.dll"

# SDK routing must reject this synthetic host executable, with a specific
# diagnostic, before attempting to read the game's fixed template address.
sdk_status=0
WINEPREFIX="$test_prefix" WINEDEBUG=-all ISAC_SDK_LOCAL=1 ISAC_STACK_PROBE=1 \
    "$wine_command" "$build_dir/uplay_local_smoke.exe" \
    "Z:\\$test_dir\\uplay_r1_loader64.dll" || sdk_status=$?
if [[ $sdk_status -ne 83 ]]; then
    echo "Expected SDK guard termination 0x4953 (shell status 83), got $sdk_status." >&2
    exit 1
fi
rg -q '^SDK_LOCAL_ROUTE_ERROR .*stage=file-name,win32_error=0,.*modified=0,terminating=1' \
    "$test_dir/project-isac-stack-probe.log"
sdk_status=0
WINEPREFIX="$test_prefix" WINEDEBUG=-all ISAC_SDK_LOCAL=1 ISAC_STACK_PROBE=1 ISAC_SDK_PROTECT_TRACE=1 \
    "$wine_command" "$build_dir/uplay_local_smoke.exe" \
    "Z:\\$test_dir\\uplay_r1_loader64.dll" || sdk_status=$?
test "$sdk_status" -eq 83
rg -q '^SDK_PROTECT_HOLD .*delay_ms=2000,diagnostic-only=1,termination-still-required=1' \
    "$test_dir/project-isac-stack-probe.log"
WINEPREFIX="$test_prefix" "$wineserver_command" -k
WINEPREFIX="$test_prefix" "$wineserver_command" -w

test -f "$test_dir/project-isac-uplay-local.log"
rg -q '^LOCAL_SHIM_READY ' "$test_dir/project-isac-uplay-local.log"
rg -q '^LOCAL_FIRST_CALL .*function=UPLAY_Start' \
    "$test_dir/project-isac-uplay-local.log"
rg -q '^LOCAL_FIRST_CALL .*function=UPLAY_USER_GetAccountIdUtf8' \
    "$test_dir/project-isac-uplay-local.log"
if [[ -e $test_dir/uplay_r1_loader64_isac_original.dll ]]; then
    echo "Smoke test unexpectedly contains the retail forwarding target." >&2
    exit 1
fi

echo "Standalone local Uplay shim assertions passed."
