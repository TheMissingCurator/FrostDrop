/* Bounded first-chance diagnostics, NOT an assertion that an exception is fatal.
 * Pre-opened append handle; no allocation, printf, stack walking, game calls or
 * payload reads in the exception path. Never handles or modifies an exception.
 * Skip routine C++/debug-name/output notifications and our expected checkpoints.
 */
static HANDLE handoff_fault_file = INVALID_HANDLE_VALUE;
static volatile LONG handoff_fault_busy, handoff_fault_count;

static BOOL initialize_handoff_faults(void) {
    if (handoff_fault_file == INVALID_HANDLE_VALUE)
        handoff_fault_file = CreateFileW(g_stack_log_path, FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handoff_fault_file == INVALID_HANDLE_VALUE) return FALSE;
    log_status("LOGIN_HANDOFF_CONFIG", g_login_handoff_sweep_requested ?
        "sweep=on,exceptions=first-chance,exception-cap=32,proton-log=wrapper-enabled" :
        "sweep=off,exceptions=first-chance,exception-cap=32,proton-log=wrapper-enabled");
    return TRUE;
}

static char *handoff_fault_text(char *out, const char *text) {
    while (*text) *out++ = *text++;
    return out;
}
static char *handoff_fault_hex(char *out, DWORD64 value) {
    static const char digits[] = "0123456789abcdef";
    int shift;
    *out++ = '0'; *out++ = 'x';
    for (shift = 60; shift >= 0; shift -= 4) *out++ = digits[(value >> shift) & 15];
    return out;
}

static void record_handoff_exception(const EXCEPTION_POINTERS *exception) {
    DWORD code, saved_error, written;
    const CONTEXT *ctx;
    char line[640], *out = line;
    DWORD64 rva = ~(DWORD64)0, access = ~(DWORD64)0;
    DWORD i;
    if (!g_login_handoff_requested || handoff_fault_file == INVALID_HANDLE_VALUE ||
        !exception || !exception->ExceptionRecord || !exception->ContextRecord) return;
    code = exception->ExceptionRecord->ExceptionCode;
    if (code == 0xe06d7363u || code == 0x406d1388u || code == 0x40010006u ||
        code == 0x4001000au) return;
    ctx = exception->ContextRecord;
    if (code == EXCEPTION_SINGLE_STEP) {
        for (i = 0; i < 3; ++i)
            if ((ctx->Dr6 & ((DWORD64)2 << i)) &&
                ctx->Rip == (DWORD64)(uintptr_t)(g_game_base + handoff_sites[i])) return;
        if ((ctx->Dr6 & 1) && ctx->Rip ==
            (DWORD64)(uintptr_t)(g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA)) return;
    }
    saved_error = GetLastError();
    if (InterlockedCompareExchange(&handoff_fault_busy, 1, 0)) return;
    if (handoff_fault_count >= 32) goto done;
    ++handoff_fault_count;
    if (ctx->Rip >= (DWORD64)(uintptr_t)g_game_base &&
        ctx->Rip - (DWORD64)(uintptr_t)g_game_base < g_game_size)
        rva = ctx->Rip - (DWORD64)(uintptr_t)g_game_base;
    if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) &&
        exception->ExceptionRecord->NumberParameters >= 1)
        access = exception->ExceptionRecord->ExceptionInformation[0];
    out = handoff_fault_text(out, "LOGIN_HANDOFF_EXCEPTION detail=code=");
    out = handoff_fault_hex(out, code);
#define HANDOFF_FAULT_FIELD(name, value) \
    out = handoff_fault_text(out, "," name "="); out = handoff_fault_hex(out, (value))
    HANDOFF_FAULT_FIELD("sequence", handoff_fault_count);
    HANDOFF_FAULT_FIELD("tick-ms", GetTickCount64());
    HANDOFF_FAULT_FIELD("process", GetCurrentProcessId());
    HANDOFF_FAULT_FIELD("thread", GetCurrentThreadId());
    HANDOFF_FAULT_FIELD("rip", ctx->Rip);
    HANDOFF_FAULT_FIELD("game-rva", rva);
    HANDOFF_FAULT_FIELD("flags", exception->ExceptionRecord->ExceptionFlags);
    HANDOFF_FAULT_FIELD("access", access);
    HANDOFF_FAULT_FIELD("dr6", ctx->Dr6);
    HANDOFF_FAULT_FIELD("dr7", ctx->Dr7);
#undef HANDOFF_FAULT_FIELD
    out = handoff_fault_text(out, "\r\n");
    WriteFile(handoff_fault_file, line, (DWORD)(out - line), &written, NULL);
done:
    InterlockedExchange(&handoff_fault_busy, 0);
    SetLastError(saved_error);
}
