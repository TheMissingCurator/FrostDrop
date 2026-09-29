#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/uplay_probe/sdk_api_bindings.h"
#include "../src/uplay_probe/sdk_api_code.h"
#include "../src/uplay_probe/sdk_protect_path.h"

/* Test-only assembly: a harmless Nt-shaped function returns a constant.
 * It does not call or patch a real protection API. */
extern DWORD fixture_call(uintptr_t *target, SIZE_T *length, DWORD requested);
extern BYTE fixture_entry[], fixture_jump[], fixture_return[];
__asm__(".text\n"
        ".globl fixture_entry, fixture_jump, fixture_call, fixture_return\n"
        "fixture_entry:\n jmp fixture_jump\n"
        "fixture_jump:\n movl $0xc0000022, %eax\n ret\n"
        "fixture_call:\n subq $40, %rsp\n"
        " movq %r8, %r9\n movq %rdx, %r8\n movq %rcx, %rdx\n movq $-1, %rcx\n"
        " call fixture_entry\n"
        "fixture_return:\n addq $40, %rsp\n ret\n");

static void handler_contract(void) {
    EXCEPTION_RECORD record;
    CONTEXT context, original;
    EXCEPTION_POINTERS exception = {&record, &context};
    uintptr_t target = 0x12345000;
    SIZE_T length = 50;
    ZeroMemory(&context, sizeof(context));
    ZeroMemory(&record, sizeof(record));
    ZeroMemory(&isac_sdk_path, sizeof(isac_sdk_path));
    isac_sdk_path.active = 1;
    isac_sdk_path.thread = GetCurrentThreadId();
    isac_sdk_path.entry = (uintptr_t)fixture_entry;
    isac_sdk_path.jump = (uintptr_t)fixture_jump;
    isac_sdk_path.returned = (uintptr_t)fixture_return;
    isac_sdk_path.target = target; isac_sdk_path.length = length; isac_sdk_path.requested = 8;
    context.Dr7 = 1;
    original = context;
    assert(!isac_sdk_path_arm_context(&context));
    assert(!strcmp(isac_sdk_path.status, "debug-registers-busy"));
    assert(!memcmp(&context, &original, sizeof(context)) && !isac_sdk_path.armed);
    context.Dr7 = 0;
    assert(isac_sdk_path_arm_context(&context));
    isac_sdk_path.armed = 1;
    record.ExceptionCode = EXCEPTION_SINGLE_STEP;
    context.Rip = isac_sdk_path.entry; context.Dr6 = 1;
    context.Rcx = UINT64_MAX; context.Rdx = (uintptr_t)&target; context.R8 = (uintptr_t)&length; context.R9 = 8;
    context.Rax = 123;
    SetLastError(ERROR_BUSY);
    assert(isac_sdk_path_exception(&exception) == EXCEPTION_CONTINUE_EXECUTION);
    assert(isac_sdk_path.entered && context.Rax == 123 && GetLastError() == ERROR_BUSY);
    context.Rip = isac_sdk_path.jump; context.Dr6 = 2;
    assert(isac_sdk_path_exception(&exception) == EXCEPTION_CONTINUE_EXECUTION && isac_sdk_path.jumped);
    context.Rip = isac_sdk_path.returned; context.Dr6 = 4; context.Rax = 0xc0000022;
    assert(isac_sdk_path_exception(&exception) == EXCEPTION_CONTINUE_EXECUTION);
    assert(isac_sdk_path.completed && !isac_sdk_path.armed && context.Dr7 == 0);
    assert(context.Rax == 0xc0000022 && isac_sdk_path.ntstatus == 0xc0000022);
    record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    assert(isac_sdk_path_exception(&exception) == EXCEPTION_CONTINUE_SEARCH);
    isac_sdk_path.active = 0;
}

static void code_bounds(void) {
    ISAC_API_CODE code;
    ISAC_SDK_JUMP jump;
    int32_t displacement;
    uintptr_t output;
    DWORD old;
    BYTE *page = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    assert(page);
    memset(page, 0x90, 4096);
    ZeroMemory(&code, sizeof(code));
    code.status = "ok"; code.entry = (uintptr_t)page; code.length = 32;
    code.bytes[0] = 0xe9; displacement = 32 - 5;
    memcpy(code.bytes + 1, &displacement, 4);
    assert(!strcmp(isac_sdk_jump_sample(&code).status, "unsupported-target"));
    assert(VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old));
    jump = isac_sdk_jump_sample(&code);
    assert(!strcmp(jump.status, "ok") && jump.length == 128 && jump.target == (uintptr_t)page + 32);
    assert(jump.bytes[0] == 0x90 && page[32] == 0x90);
    code.bytes[0] = 0xcc;
    assert(!strcmp(isac_sdk_jump_sample(&code).status, "not-e9-entry"));
    assert(!isac_sdk_relative(1, -2, &output));
    assert(!isac_sdk_relative(UINTPTR_MAX, 1, &output));
    assert(isac_sdk_relative(100, -5, &output) && output == 95);
    code = isac_api_code_sample(GetModuleHandleW(L"kernelbase.dll"),
        (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualProtect"), 176);
    output = (uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");
    assert(isac_sdk_nt_return(&code, output) == code.entry + 0x3d);
    assert(!isac_sdk_nt_return(&code, output + 1));
    code.bytes[0x3d] ^= 1;
    assert(!isac_sdk_nt_return(&code, output));
    code = isac_api_code_sample(GetModuleHandleW(L"ntdll.dll"), output, 32);
    assert(isac_api_wine_stub(&code));
    assert(isac_binding_import(GetModuleHandleW(L"kernelbase.dll"), "ntdll.dll", "NtProtectVirtualMemory").destination == output);
    assert(!strcmp(isac_binding_forward((uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect")).status, "ok"));
    assert(VirtualFree(page, 0, MEM_RELEASE));
}

int main(void) {
    uintptr_t target = 0x12345000;
    SIZE_T length = 50;
    DWORD result;
    CONTEXT debug;
    handler_contract();
    code_bounds();
    SetLastError(ERROR_BUSY);
    isac_sdk_path_start((uintptr_t)fixture_entry, (uintptr_t)fixture_jump, (uintptr_t)fixture_return,
        target, length, 8);
    assert(GetLastError() == ERROR_BUSY);
    assert(isac_sdk_path.armed);
    result = fixture_call(&target, &length, 8);
    assert(result == 0xc0000022);
    isac_sdk_path_finish();
    printf("Fixture trace: status=%s entry=%ld jump=%ld return=%ld ntstatus=0x%lx.\n",
        isac_sdk_path.status, isac_sdk_path.entered, isac_sdk_path.jumped,
        isac_sdk_path.completed, (unsigned long)isac_sdk_path.ntstatus);
    assert(!strcmp(isac_sdk_path.status, "complete") && isac_sdk_path.entered && isac_sdk_path.jumped);
    assert(isac_sdk_path.completed && isac_sdk_path.ntstatus == result && !isac_sdk_path.armed);
    ZeroMemory(&debug, sizeof(debug));
    debug.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    assert(GetThreadContext(GetCurrentThread(), &debug));
    assert(debug.Dr0 == isac_sdk_path.saved[0] && debug.Dr1 == isac_sdk_path.saved[1]);
    assert(debug.Dr2 == isac_sdk_path.saved[2] && debug.Dr3 == isac_sdk_path.saved[3]);
    assert(debug.Dr7 == isac_sdk_path.saved[5]);
    /* A second ordinary call must no longer trigger our exception handler. */
    assert(fixture_call(&target, &length, 8) == result);
    isac_sdk_path_start((uintptr_t)fixture_entry, (uintptr_t)fixture_jump, (uintptr_t)fixture_return,
        target + 1, length, 8);
    assert(fixture_call(&target, &length, 8) == result);
    isac_sdk_path_finish();
    assert(!strcmp(isac_sdk_path.status, "unexpected-call") && !isac_sdk_path.completed);
    isac_sdk_path_start((uintptr_t)fixture_entry, (uintptr_t)fixture_jump, (uintptr_t)fixture_return,
        target, length, 8);
    isac_sdk_path_finish();
    assert(!strcmp(isac_sdk_path.status, "incomplete") && !isac_sdk_path.armed);
    puts("One-shot entry/jump/NT return trace passed; results unchanged, debug registers cleaned up.");
    return 0;
}
