#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
source_dir="$project_dir/src/uplay_local"
flavor=uplay_local
extra_flags=()
extra_objects=()
if [[ ${1:-} == --sdk-adapter && $# -eq 1 ]]; then
    flavor=uplay_sdk_adapter
    extra_flags+=(-DISAC_SDK_ADAPTER_BUILD)
elif (( $# != 0 )); then
    echo "Usage: $0 [--sdk-adapter]" >&2
    exit 2
fi
exports_file="$project_dir/src/uplay_probe/exports.txt"
build_dir="$project_dir/build/$flavor"
dist_dir="$project_dir/dist/$flavor"
compiler=${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}

if ! command -v "$compiler" >/dev/null 2>&1; then
    echo "Missing Windows x64 compiler: $compiler" >&2
    exit 1
fi
mkdir -p -- "$build_dir" "$dist_dir"
if [[ $flavor == uplay_sdk_adapter ]]; then
    bash "$script_dir/build-sdk-http-adapter.sh"
    python3 "$script_dir/generate-sdk-http-live-anchors.py" > "$build_dir/sdk_http_live_anchors.inc"
    "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -I"$build_dir" \
        -c "$project_dir/src/uplay_probe/sdk_http_live.c" -o "$build_dir/sdk_http_live.o"
    "$compiler" -c "$project_dir/src/uplay_probe/sdk_http_entry.S" -o "$build_dir/sdk_http_entry.o"
    extra_objects+=("$build_dir/sdk_http_live.o" "$build_dir/sdk_http_entry.o"
        "$project_dir/build/sdk_http_adapter/libisac_sdk_http.a" -lbcrypt)
fi

export_count=$(wc -l < "$exports_file")
if [[ $export_count -ne 89 ]]; then
    echo "Expected 89 exports, found $export_count." >&2
    exit 1
fi

awk '
    BEGIN { print "LIBRARY uplay_r1_loader64"; print "EXPORTS" }
    {
        printf "    %s=isac_local_wrap_%d @%d\n", $2, NR - 1, $1
    }
' "$exports_file" > "$build_dir/uplay_local.def"

awk '{ printf "    \"%s\",\n", $2 }' "$exports_file" \
    > "$build_dir/export_names.inc"

{
    printf '%s\n' \
        '    .text' \
        '    .extern isac_local_dispatch' \
        '' \
        '    .macro ISAC_LOCAL_WRAPPER index' \
        '    .globl isac_local_wrap_\index' \
        '    .def isac_local_wrap_\index; .scl 2; .type 32; .endef' \
        '    .seh_proc isac_local_wrap_\index' \
        'isac_local_wrap_\index:' \
        '    subq $72, %rsp' \
        '    .seh_stackalloc 72' \
        '    .seh_endprologue' \
        '    movq %rcx, 40(%rsp)' \
        '    movq %rdx, 48(%rsp)' \
        '    movq %r8, 56(%rsp)' \
        '    movq %r9, 64(%rsp)' \
        '    movq 64(%rsp), %rax' \
        '    movq %rax, 32(%rsp)' \
        '    movl $\index, %ecx' \
        '    movq 40(%rsp), %rdx' \
        '    movq 48(%rsp), %r8' \
        '    movq 56(%rsp), %r9' \
        '    call isac_local_dispatch' \
        '    addq $72, %rsp' \
        '    ret' \
        '    .seh_endproc' \
        '    .endm' \
        ''
    seq 0 88 | awk '{ printf "    ISAC_LOCAL_WRAPPER %d\n", $1 }'
    printf '%s\n' ''
} > "$build_dir/wrappers.S"

"$compiler" \
    -c -O2 -Wall -Wextra -Werror "${extra_flags[@]}" \
    -I"$build_dir" -I"$project_dir/src/uplay_probe" \
    "$source_dir/local.c" \
    -o "$build_dir/local.o"
"$compiler" \
    -c -O2 -Wall -Wextra -Werror \
    -I"$project_dir/src/uplay_probe" \
    "$project_dir/src/uplay_probe/stack_probe.c" \
    -o "$build_dir/stack_probe.o"
"$compiler" -c "$build_dir/wrappers.S" -o "$build_dir/wrappers.o"
"$compiler" \
    -shared -static-libgcc \
    -Wl,--no-insert-timestamp \
    -Wl,--disable-auto-import \
    "$build_dir/local.o" \
    "$build_dir/stack_probe.o" \
    "$build_dir/wrappers.o" \
    "${extra_objects[@]}" \
    "$build_dir/uplay_local.def" \
    -lws2_32 \
    -o "$dist_dir/uplay_r1_loader64.dll"

sha256sum "$dist_dir/uplay_r1_loader64.dll" > "$dist_dir/SHA256SUMS"
echo "Built: $dist_dir/uplay_r1_loader64.dll"
