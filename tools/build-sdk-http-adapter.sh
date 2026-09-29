#!/usr/bin/env bash
# Build an isolated integration library, NOT a deployable/auto-enabled game DLL.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
compiler=${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}
archiver=${ISAC_MINGW_AR:-x86_64-w64-mingw32-ar}
build_dir="$project_dir/build/sdk_http_adapter"
mkdir -p -- "$build_dir"
objects=()
for module in sdk_http_adapter sdk_http_native_request sdk_http_native_result sdk_http_native_service sdk_http_install_win32; do
    "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
        -c "$project_dir/src/uplay_probe/$module.c" -o "$build_dir/$module.o"
    objects+=("$build_dir/$module.o")
done
"$archiver" rcs "$build_dir/libisac_sdk_http.a" "${objects[@]}"
echo "Built integration library: $build_dir/libisac_sdk_http.a"
echo "Not installed: requires live build validation, transport enforcement and pre-publication admission."
