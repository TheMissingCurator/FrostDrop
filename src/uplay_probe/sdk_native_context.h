#ifndef ISAC_SDK_NATIVE_CONTEXT_H
#define ISAC_SDK_NATIVE_CONTEXT_H

/* Diagnostic request only: copy this thread's debug-register state back
 * unchanged. No breakpoint addresses, general registers or code are set. */
typedef void (*isac_sdk_context_observer)(const char *operation, const char *phase,
    const CONTEXT *context, BOOL ok, DWORD error, BOOL unchanged);

static void isac_sdk_native_context(isac_sdk_context_observer observer) {
    CONTEXT context, checked;
    DWORD last_error = GetLastError(), error;
    BOOL ok, same;
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (observer) observer("get", "begin", &context, FALSE, 0, FALSE);
    ok = GetThreadContext(GetCurrentThread(), &context);
    error = ok ? 0 : GetLastError();
    if (observer) observer("get", "end", &context, ok, error, FALSE);
    if (!ok) { SetLastError(last_error); return; }
    if (observer) observer("set", "begin", &context, FALSE, 0, TRUE);
    ok = SetThreadContext(GetCurrentThread(), &context);
    error = ok ? 0 : GetLastError();
    if (observer) observer("set", "end", &context, ok, error, TRUE);
    /* Verify by reading after a successful identical-state request. Never
     * retry a failed setter or "repair" differing state. */
    if (ok) {
        ZeroMemory(&checked, sizeof(checked));
        checked.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (observer) observer("verify", "begin", &checked, FALSE, 0, FALSE);
        ok = GetThreadContext(GetCurrentThread(), &checked);
        error = ok ? 0 : GetLastError();
        same = ok && context.Dr0 == checked.Dr0 && context.Dr1 == checked.Dr1 &&
            context.Dr2 == checked.Dr2 && context.Dr3 == checked.Dr3 && context.Dr7 == checked.Dr7;
        if (observer) observer("verify", "end", &checked, ok, error, same);
    }
    SetLastError(last_error);
}
#endif
