#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
static unsigned int reads, writes, seen_error;
static BOOL fail_get, fail_set;
static CONTEXT initial;
static BOOL fake_get(HANDLE thread, CONTEXT *context) {
    (void)thread;
    ++reads;
    if (fail_get) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    *context = initial;
    return TRUE;
}
static BOOL fake_set(HANDLE thread, const CONTEXT *context) {
    (void)thread;
    ++writes;
    assert(context->Dr0 == initial.Dr0 && context->Dr1 == initial.Dr1);
    assert(context->Dr2 == initial.Dr2 && context->Dr3 == initial.Dr3);
    assert(context->Dr6 == initial.Dr6 && context->Dr7 == initial.Dr7);
    assert(context->ContextFlags == CONTEXT_DEBUG_REGISTERS);
    if (fail_set) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    return TRUE;
}
#define GetThreadContext fake_get
#define SetThreadContext fake_set
#include "../src/uplay_probe/sdk_native_context.h"
#undef GetThreadContext
#undef SetThreadContext
static void observe(const char *operation, const char *phase, const CONTEXT *context,
    BOOL ok, DWORD error, BOOL unchanged) {
    (void)operation; (void)context; (void)ok; (void)unchanged;
    if (!strcmp(phase, "end") && error) seen_error = error;
    SetLastError(ERROR_BAD_COMMAND);
}
int main(void) {
    ZeroMemory(&initial, sizeof(initial));
    initial.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    initial.Dr0 = 123; initial.Dr1 = 456; initial.Dr2 = 789; initial.Dr3 = 987;
    initial.Dr6 = 0xffff0ff0; initial.Dr7 = 0x15;
    SetLastError(ERROR_BUSY);
    isac_sdk_native_context(observe);
    assert(reads == 2 && writes == 1 && GetLastError() == ERROR_BUSY);
    reads = writes = seen_error = 0;
    fail_set = TRUE;
    isac_sdk_native_context(observe);
    assert(reads == 1 && writes == 1 && seen_error == ERROR_ACCESS_DENIED && GetLastError() == ERROR_BUSY);
    reads = writes = seen_error = 0;
    fail_get = TRUE;
    isac_sdk_native_context(observe);
    assert(reads == 1 && !writes && seen_error == ERROR_ACCESS_DENIED && GetLastError() == ERROR_BUSY);
    puts("Native context contract: identical state, immediate failure errors, no retry, and caller last-error preserved.");
    return 0;
}
