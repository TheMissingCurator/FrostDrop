/* The retail Proton trace delivered a single-step at our exact DR2 address
 * with DR6/DR7 zero. Only accept that form for a sweep-verified thread lifetime
 * and a still-matching signed checkpoint. Never swallow arbitrary single-steps.
 */
static volatile LONG handoff_fallback_count;

static BOOL handle_handoff_zero_debug(EXCEPTION_POINTERS *exception) {
    CONTEXT *ctx;
    DWORD i, saved_error;
    BYTE signature[8];
    LONG sequence;
    char detail[160];
    if (!g_login_handoff_requested || !g_login_handoff_sweep_requested ||
        !g_tctd_echo_enabled || g_dispatch_install_state != 2 || !exception ||
        !exception->ExceptionRecord || !exception->ContextRecord ||
        exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ||
        exception->ExceptionRecord->ExceptionFlags != 0) return FALSE;
    ctx = exception->ContextRecord;
    if (ctx->Dr6 || ctx->Dr7 || (ctx->EFlags & 0x100) ||
        (DWORD64)(uintptr_t)exception->ExceptionRecord->ExceptionAddress != ctx->Rip) return FALSE;
    for (i = 0; i < 3; ++i)
        if (ctx->Rip == (DWORD64)(uintptr_t)(g_game_base + handoff_sites[i])) break;
    if (i == 3) return FALSE;
    saved_error = GetLastError();
    if (!handoff_current_thread_owned() ||
        !handoff_read((uintptr_t)g_game_base, handoff_sites[i], signature, sizeof(signature)) ||
        memcmp(signature, handoff_signatures[i], sizeof(signature))) {
        SetLastError(saved_error);
        return FALSE;
    }
    record_login_handoff(i, ctx);
    sequence = InterlockedIncrement(&handoff_fallback_count);
    if (sequence <= 16) {
        snprintf(detail, sizeof(detail),
            "sequence=%ld,site=%lu,rva=0x%lx,ownership=thread-id-and-creation-time,resume=rf",
            (long)sequence, (unsigned long)i, (unsigned long)handoff_sites[i]);
        log_status("LOGIN_HANDOFF_ZERO_DEBUG_RESUMED", detail);
    }
    /* Preserve all supplied registers/ContextFlags; only suppress retrapping on
     * this instruction as with the normal handler. No invented debug registers. */
    ctx->EFlags |= 0x10000;
    SetLastError(saved_error);
    return TRUE;
}
