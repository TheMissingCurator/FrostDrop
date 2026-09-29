#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d -p /tmp project-isac-sdk-route.XXXXXXXX)
export WINEPREFIX="$test_dir/prefix" WINEDEBUG=-all
cleanup() {
    "${ISAC_WINESERVER:-wineserver}" -k || true
    "${ISAC_WINESERVER:-wineserver}" -w || true
    rm -rf -- "$test_dir"
}
trap cleanup EXIT
"${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}" -O2 -Wall -Wextra -Werror \
    "$project_dir/tests/sdk_local_route_smoke.c" -o "$test_dir/sdk-route.exe"
"${ISAC_WINE:-wine}" "$test_dir/sdk-route.exe"
"${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}" -O2 -Wall -Wextra -Werror \
    "$project_dir/tests/sdk_api_bindings_smoke.c" -o "$test_dir/sdk-bindings.exe"
"${ISAC_WINE:-wine}" "$test_dir/sdk-bindings.exe"
"${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}" -O2 -Wall -Wextra -Werror \
    "$project_dir/tests/sdk_protect_path_smoke.c" -o "$test_dir/sdk-path.exe"
"${ISAC_WINE:-wine}" "$test_dir/sdk-path.exe"
