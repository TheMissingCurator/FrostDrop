#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

static volatile LONG g_target_called;
static volatile LONG g_breakpoint_seen;

__declspec(noinline) static void breakpoint_target(void) {
    InterlockedIncrement(&g_target_called);
}

static LONG CALLBACK breakpoint_handler(EXCEPTION_POINTERS *exception) {
    if (
        exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ||
        exception->ContextRecord->Rip != (DWORD64)(uintptr_t)breakpoint_target
    ) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    InterlockedIncrement(&g_breakpoint_seen);
    exception->ContextRecord->Dr0 = 0;
    exception->ContextRecord->Dr6 = 0;
    exception->ContextRecord->Dr7 &= ~(DWORD64)1u;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void) {
    CONTEXT context;
    PVOID handler;

    handler = AddVectoredExceptionHandler(1, breakpoint_handler);
    if (handler == NULL) {
        fputs("AddVectoredExceptionHandler failed\n", stderr);
        return 1;
    }
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        fprintf(stderr, "GetThreadContext failed: %lu\n", GetLastError());
        return 1;
    }
    context.Dr0 = (DWORD64)(uintptr_t)breakpoint_target;
    context.Dr6 = 0;
    context.Dr7 = (context.Dr7 & ~(DWORD64)0x000f000fu) | 1u;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        fprintf(stderr, "SetThreadContext failed: %lu\n", GetLastError());
        return 1;
    }
    breakpoint_target();
    RemoveVectoredExceptionHandler(handler);
    if (g_target_called != 1 || g_breakpoint_seen != 1) {
        fprintf(
            stderr,
            "Unexpected counts: target=%ld breakpoint=%ld\n",
            g_target_called,
            g_breakpoint_seen
        );
        return 1;
    }
    puts("hardware breakpoint smoke test passed");
    return 0;
}
