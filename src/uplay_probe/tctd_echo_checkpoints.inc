/* Read-only checks for the candidate service-directory consumer.
 * DR0 stays reserved for the existing port-27015 TLS acceptance mechanism.
 */
static const uintptr_t echo_sites[3] = {0x22412c0u, 0xb98feu, 0xb9ad8u};
static const BYTE echo_signatures[3][8] = {
    {0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c},
    {0x84,0xc0,0x75,0x3a,0x8b,0x05,0xa0,0x33},
    {0x4c,0x8b,0xbc,0x24,0xb0,0x07,0x00,0x00}
};
static volatile LONG echo_event_count;
static const uintptr_t leads_sites[3] = {0x22412c0u, 0x9c443u, 0x9c5e1u};
static const BYTE leads_signatures[3][8] = {
    {0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c},
    {0x85,0xc0,0x0f,0x84,0xdc,0x00,0x00,0x00},
    {0x48,0x8b,0x4c,0x24,0x40,0x4c,0x8b,0xbc}
};
static volatile LONG leads_counts[3];

static uintptr_t echo_site(DWORD i) {
    if (g_login_handoff_requested) return handoff_sites[i];
    return g_startup_leads_requested ? leads_sites[i] : echo_sites[i];
}

static BOOL initialize_echo_checkpoints(void) {
    DWORD i;
    if (g_login_handoff_requested && (g_startup_leads_requested || !handoff_getters_valid()))
        return FALSE;
    for (i = 0; i < 3; ++i) {
        const BYTE *site = g_game_base + echo_site(i);
        const BYTE *signature = g_login_handoff_requested ? handoff_signatures[i] :
            g_startup_leads_requested ? leads_signatures[i] : echo_signatures[i];
        if (!readable_code_window(site, 8) || memcmp(site, signature, 8))
            return FALSE;
    }
    if (g_login_handoff_requested) {
        log_status("LOGIN_HANDOFF_READY",
            "sites=services-poll,frontend-before-sync,channel-before-state-gate,dr0=reserved,"
            "unknown=-1,max-transitions-per-site=128,payloads=disabled,mutation=disabled");
        return TRUE;
    }
    if (g_startup_leads_requested) {
        if (!initialize_startup_leads_capture()) return FALSE;
        log_status("STARTUP_LEADS_READY",
            "sites=constructor,selection-count,selection-result,dr0=reserved,names=private,max-events-per-site=64");
        return TRUE;
    }
    log_status("TCTD_ECHO_CHECKPOINTS_READY",
        "sites=constructor,parse-result,consumer-finished,dr0=reserved,payloads=disabled");
    return TRUE;
}

static BOOL echo_context(CONTEXT *ctx, BOOL enabled) {
    DWORD64 accept = (DWORD64)(uintptr_t)(g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA);
    DWORD64 sites[3];
    DWORD i;
    for (i = 0; i < 3; ++i) sites[i] = (DWORD64)(uintptr_t)(g_game_base + echo_site(i));
    if (enabled && (((ctx->Dr7 & 3u) && ctx->Dr0 != accept) ||
        ((ctx->Dr7 & 12u) && ctx->Dr1 != sites[0]) ||
        ((ctx->Dr7 & 48u) && ctx->Dr2 != sites[1]) ||
        ((ctx->Dr7 & 192u) && ctx->Dr3 != sites[2]))) return FALSE;
    if (enabled) {
        ctx->Dr1 = sites[0]; ctx->Dr2 = sites[1]; ctx->Dr3 = sites[2];
        ctx->Dr7 = (ctx->Dr7 & ~(DWORD64)0xfff000fcu) | 0x54u;
    } else {
        if (ctx->Dr1 == sites[0]) { ctx->Dr1 = 0; ctx->Dr7 &= ~(DWORD64)0x00f0000cu; }
        if (ctx->Dr2 == sites[1]) { ctx->Dr2 = 0; ctx->Dr7 &= ~(DWORD64)0x0f000030u; }
        if (ctx->Dr3 == sites[2]) { ctx->Dr3 = 0; ctx->Dr7 &= ~(DWORD64)0xf00000c0u; }
        if (ctx->Dr0 == accept) { ctx->Dr0 = 0; ctx->Dr7 &= ~(DWORD64)0x000f0003u; }
    }
    ctx->Dr6 = 0;
    return TRUE;
}

static BOOL echo_breakpoints(HANDLE thread, BOOL enabled) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return GetThreadContext(thread, &ctx) && echo_context(&ctx, enabled) &&
           SetThreadContext(thread, &ctx);
}

static BOOL echo_consumer_is_local(const CONTEXT *ctx) {
    const BYTE *owner = (const BYTE *)(uintptr_t)ctx->R14;
    const BYTE *transport;
    SOCKET socket_handle;
    if (!readable_memory_window(owner, 0x18)) return FALSE;
    memcpy(&transport, owner + 0x10, sizeof(transport));
    if (!readable_memory_window(transport, 0xd0)) return FALSE;
    memcpy(&socket_handle, transport + 0xc8, sizeof(socket_handle));
    return socket_peer_is_port(socket_handle, 51000);
}

static BOOL handle_echo_breakpoint(CONTEXT *ctx) {
    DWORD i, saved_error;
    char detail[192];
    LONG event;
    BOOL relevant;
    if (!g_tctd_echo_enabled) return FALSE;
    for (i = 0; i < 3; ++i) {
        if (!(ctx->Dr6 & ((DWORD64)2 << i)) ||
            ctx->Rip != (DWORD64)(uintptr_t)(g_game_base + echo_site(i))) continue;
        saved_error = GetLastError();
        if (g_login_handoff_requested) {
            record_login_handoff(i, ctx);
            SetLastError(saved_error);
            ctx->Dr6 = 0; ctx->EFlags |= 0x10000;
            return TRUE;
        }
        if (g_startup_leads_requested) {
            event = InterlockedIncrement(&leads_counts[i]);
            if (event <= 64) {
                DWORD state = 0xffffffffu, kind = (DWORD)ctx->R12;
                WORD port = 0;
                BOOL connected = FALSE, valid = FALSE;
                const BYTE *owner = (const BYTE *)(uintptr_t)ctx->R13;
                const BYTE *selected = (const BYTE *)(uintptr_t)ctx->Rbx;
                uintptr_t connection = 0, caller = 0;
                const void *return_slot = (const void *)(uintptr_t)(ctx->Rsp + (i == 0 ? 0 : 0xb8));
                if (readable_memory_window(return_slot, sizeof(caller))) {
                    memcpy(&caller, return_slot, sizeof(caller));
                    caller = caller >= (uintptr_t)g_game_base &&
                        caller - (uintptr_t)g_game_base < g_game_size ? caller - (uintptr_t)g_game_base : 0;
                }
                if (i != 0 && readable_memory_window(owner, 0x3c)) memcpy(&state, owner + 0x38, 4);
                if (i == 2 && readable_memory_window(selected, 0x68)) {
                    memcpy(&port, selected + 0x58, 2);
                    memcpy(&kind, selected + 0x5c, 4);
                    memcpy(&connection, selected + 0x60, sizeof(connection));
                    valid = TRUE; connected = connection != 0;
                }
                if (i == 0) snprintf(detail, sizeof(detail),
                    "stage=constructor,event=%ld,port=%lu,version=%lu,caller_rva=0x%llx",
                    event, (unsigned long)(ctx->R8 & 0xffff), (unsigned long)(DWORD)ctx->R9,
                    (unsigned long long)caller);
                else snprintf(detail, sizeof(detail),
                    "stage=%s,event=%ld,state=%lu,kind=%lu,count=%lu,selected=%d,readable=%d,port=%u,connection=%d,caller_rva=0x%llx",
                    i == 1 ? "selection-count" : "selection-result", event, (unsigned long)state,
                    (unsigned long)kind, (unsigned long)(i == 1 ? (DWORD)ctx->Rax : 0),
                    i == 2 && ctx->Rbx != 0, valid, port, connected, (unsigned long long)caller);
                log_status("STARTUP_LEADS_CHECKPOINT", detail);
            }
            SetLastError(saved_error);
            ctx->Dr6 = 0; ctx->EFlags |= 0x10000;
            return TRUE;
        }
        relevant = i == 0 ? ((ctx->R8 & 0xffffu) == 51000 ||
                            (ctx->R8 & 0xffffu) == 55001 ||
                            (ctx->R8 & 0xffffu) == 55002) : echo_consumer_is_local(ctx);
        if (relevant && (event = InterlockedIncrement(&echo_event_count)) <= 64) {
            snprintf(detail, sizeof(detail),
                "sequence=%ld,stage=%s,port=%lu,value=%lu,payloads=disabled",
                event, i == 0 ? "expected-protocol" : i == 1 ? "parse-result" : "consumer-finished",
                (unsigned long)(i == 0 ? ctx->R8 & 0xffffu : 51000),
                (unsigned long)(i == 0 ? (DWORD)ctx->R9 : i == 1 ? ctx->Rax & 0xffu : 1));
            log_status("TCTD_ECHO_CHECKPOINT", detail);
        }
        SetLastError(saved_error);
        ctx->Dr6 = 0;
        ctx->EFlags |= 0x10000;
        return TRUE;
    }
    return FALSE;
}
