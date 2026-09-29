#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
source_dir="$project_dir/src/uplay_probe"
build_dir="$project_dir/build/uplay_probe"
dist_dir="$project_dir/dist/uplay_probe"
exports_file="$source_dir/exports.txt"
compiler=${ISAC_MINGW_CC:-x86_64-w64-mingw32-gcc}
stack_source="$source_dir/stack_probe.c"
probe_defines=()
if [[ ( ${1:-} == --retail-only || ${1:-} == --retail-profile || ${1:-} == --retail-finalization || ${1:-} == --retail-handshake || ${1:-} == --retail-tutorial || ${1:-} == --retail-presentation || ${1:-} == --retail-vault-state ) && $# -eq 1 ]]; then
    probe_variant=uplay_retail_probe
    stack_source="$source_dir/retail_type5_win.c"
    if [[ $1 == --retail-profile ]]; then
        probe_variant=uplay_retail_profile
        stack_source="$source_dir/retail_profile_win.c"
    fi
    if [[ $1 == --retail-finalization ]]; then
        probe_variant=uplay_retail_finalization
        stack_source="$source_dir/retail_finalization_win.c"
    fi
    if [[ $1 == --retail-handshake ]]; then
        probe_variant=uplay_retail_handshake
        stack_source="$source_dir/retail_handshake_win.c"
    fi
    if [[ $1 == --retail-tutorial ]]; then
        probe_variant=uplay_retail_tutorial
        stack_source="$source_dir/retail_tutorial_win.c"
    fi
    if [[ $1 == --retail-presentation ]]; then
        probe_variant=uplay_retail_presentation
        stack_source="$source_dir/retail_presentation_win.c"
    fi
    if [[ $1 == --retail-vault-state ]]; then
        probe_variant=uplay_retail_vault_state
        stack_source="$source_dir/retail_vault_state_win.c"
    fi
    build_dir="$project_dir/build/$probe_variant"
    dist_dir="$project_dir/dist/$probe_variant"
    probe_defines=(-DISAC_RETAIL_ONLY=1)
elif [[ $# -ne 0 ]]; then
    echo "Usage: $0 [--retail-only|--retail-profile|--retail-finalization|--retail-handshake|--retail-tutorial|--retail-presentation|--retail-vault-state]" >&2
    exit 2
fi

if ! command -v "$compiler" >/dev/null 2>&1; then
    echo "Missing Windows x64 compiler: $compiler" >&2
    exit 1
fi

mkdir -p -- "$build_dir" "$dist_dir"
if [[ ${#probe_defines[@]} -gt 0 && -f $dist_dir/uplay_r1_loader64.dll ]]; then
    previous_probe_hash=$(sha256sum -- "$dist_dir/uplay_r1_loader64.dll" | awk '{print $1}')
    mkdir -p -- "$dist_dir/previous"
    if [[ ! -e $dist_dir/previous/$previous_probe_hash.dll ]]; then
        cp -p -- "$dist_dir/uplay_r1_loader64.dll" "$dist_dir/previous/$previous_probe_hash.dll"
    fi
fi

export_count=$(wc -l < "$exports_file")
if [[ $export_count -ne 89 ]]; then
    echo "Expected 89 exports, found $export_count." >&2
    exit 1
fi

awk '
    BEGIN {
        print "LIBRARY uplay_r1_loader64"
        print "EXPORTS"
    }
    {
        ordinal = $1
        name = $2
        wrapper_index = NR - 1
        printf "    %s=isac_wrap_%d @%d\n", name, wrapper_index, ordinal
    }
' "$exports_file" > "$build_dir/uplay_probe.def"

awk '
    {
        name = $2
        printf "    \"%s\",\n", name
    }
' "$exports_file" > "$build_dir/export_names.inc"

{
    printf '%s\n' \
        '    .text' \
        '    .extern isac_resolve_and_log' \
        '    .extern isac_abi_enter' \
        '    .extern isac_abi_leave' \
        '' \
        '    .globl isac_abi_return_trampoline' \
        '    .def isac_abi_return_trampoline; .scl 2; .type 32; .endef' \
        '    .seh_proc isac_abi_return_trampoline' \
        'isac_abi_return_trampoline:' \
        '    subq $96, %rsp' \
        '    .seh_stackalloc 96' \
        '    .seh_endprologue' \
        '    movq %rax, 32(%rsp)' \
        '    movq %rdx, 40(%rsp)' \
        '    movdqu %xmm0, 48(%rsp)' \
        '    movdqu %xmm1, 64(%rsp)' \
        '    movq 32(%rsp), %rcx' \
        '    movq 40(%rsp), %rdx' \
        '    movq 48(%rsp), %r8' \
        '    call isac_abi_leave' \
        '    movq %rax, %r11' \
        '    movq 32(%rsp), %rax' \
        '    movq 40(%rsp), %rdx' \
        '    movdqu 48(%rsp), %xmm0' \
        '    movdqu 64(%rsp), %xmm1' \
        '    addq $96, %rsp' \
        '    jmp *%r11' \
        '    .seh_endproc' \
        '' \
        '    .macro ISAC_WRAPPER index' \
        '    .globl isac_wrap_\index' \
        '    .def isac_wrap_\index; .scl 2; .type 32; .endef' \
        '    .seh_proc isac_wrap_\index' \
        'isac_wrap_\index:' \
        '    subq $168, %rsp' \
        '    .seh_stackalloc 168' \
        '    .seh_endprologue' \
        '    movq %rcx, 32(%rsp)' \
        '    movq %rdx, 40(%rsp)' \
        '    movq %r8, 48(%rsp)' \
        '    movq %r9, 56(%rsp)' \
        '    movdqu %xmm0, 64(%rsp)' \
        '    movdqu %xmm1, 80(%rsp)' \
        '    movdqu %xmm2, 96(%rsp)' \
        '    movdqu %xmm3, 112(%rsp)' \
        '    movl $\index, %ecx' \
        '    call isac_resolve_and_log' \
        '    movq %rax, 128(%rsp)' \
        '    testq %rax, %rax' \
        '    jz .Labi_done_\index' \
        '    movl $\index, %ecx' \
        '    movq 168(%rsp), %rdx' \
        '    leaq 32(%rsp), %r8' \
        '    leaq 168(%rsp), %r9' \
        '    call isac_abi_enter' \
        '    testl %eax, %eax' \
        '    jz .Labi_done_\index' \
        '    leaq isac_abi_return_trampoline(%rip), %rax' \
        '    movq %rax, 168(%rsp)' \
        '.Labi_done_\index:' \
        '    movq 128(%rsp), %r11' \
        '    movq 32(%rsp), %rcx' \
        '    movq 40(%rsp), %rdx' \
        '    movq 48(%rsp), %r8' \
        '    movq 56(%rsp), %r9' \
        '    movdqu 64(%rsp), %xmm0' \
        '    movdqu 80(%rsp), %xmm1' \
        '    movdqu 96(%rsp), %xmm2' \
        '    movdqu 112(%rsp), %xmm3' \
        '    addq $168, %rsp' \
        '    testq %r11, %r11' \
        '    jz .Lmissing_\index' \
        '    jmp *%r11' \
        '.Lmissing_\index:' \
        '    xorl %eax, %eax' \
        '    ret' \
        '    .seh_endproc' \
        '    .endm' \
        ''
    seq 0 88 | awk '{ printf "    ISAC_WRAPPER %d\n", $1 }'
    printf '%s\n' ''
} > "$build_dir/wrappers.S"

"$compiler" \
    -c \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -I"$build_dir" \
    "${probe_defines[@]}" \
    "$source_dir/probe.c" \
    -o "$build_dir/probe.o"

"$compiler" \
    -c \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -I"$source_dir" \
    "$stack_source" \
    -o "$build_dir/stack_probe.o"

"$compiler" \
    -c \
    "$build_dir/wrappers.S" \
    -o "$build_dir/wrappers.o"

"$compiler" \
    -shared \
    -static-libgcc \
    -Wl,--no-insert-timestamp \
    -Wl,--disable-auto-import \
    "$build_dir/probe.o" \
    "$build_dir/stack_probe.o" \
    "$build_dir/wrappers.o" \
    "$build_dir/uplay_probe.def" \
    -lws2_32 \
    -o "$dist_dir/uplay_r1_loader64.dll"

sha256sum "$dist_dir/uplay_r1_loader64.dll" > "$dist_dir/SHA256SUMS"

echo "Built: $dist_dir/uplay_r1_loader64.dll"
echo "See docs/uplay-probe.md before installing it."
