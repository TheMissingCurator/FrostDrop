static HANDLE handoff_test_go;
static void test_handoff_log_output(const char *capture_path) {
    char path[MAX_PATH], output[4096], detail[768], oversized[1200];
    BYTE frontend[0x29b0] = {0}, services[0x600] = {0}, auth[0x1700] = {0};
    BYTE client[0x50] = {0}, manager[0x80] = {0};
    CONTEXT ctx = {0};
    uintptr_t pointer;
    DWORD value, read;
    HANDLE file;
    char *first, *second, *end, *field;
    int length = snprintf(path, sizeof(path), "%s.handoff.log", capture_path);
    assert(length > 0 && (size_t)length < sizeof(path));
    assert(MultiByteToWideChar(CP_ACP, 0, path, -1, g_stack_log_path, MAX_PATH));
    pointer = (uintptr_t)services; memcpy(frontend + 0x60, &pointer, 8);
    pointer = (uintptr_t)auth; memcpy(frontend + 0x68, &pointer, 8);
    pointer = (uintptr_t)client; memcpy(auth + 0x1128, &pointer, 8);
    pointer = (uintptr_t)manager; memcpy(client, &pointer, 8);
    value = 7; memcpy(services + 0x220, &value, 4);
    value = 2; memcpy(manager + 0x38, &value, 4);
    ctx.Rsi = (uintptr_t)frontend;
    ZeroMemory(handoff_last, sizeof(handoff_last));
    ZeroMemory(handoff_counts, sizeof(handoff_counts));
    record_login_handoff(1, &ctx);
    value = 0x80000000u; memcpy(services + 0x220, &value, 4);
    memcpy(manager + 0x38, &value, 4);
    value = 0x7fffffffu; memcpy(auth + 0x1124, &value, 4);
    frontend[0x29a8] = frontend[0x29aa] = 255;
    auth[0x10] = auth[0xfa8] = auth[0x1120] = 255;
    record_login_handoff(1, &ctx);
    record_login_handoff(1, &ctx); /* unchanged state must still deduplicate */
    assert(handoff_counts[1] == 2);
    memset(detail, 'x', sizeof(detail) - 1); detail[sizeof(detail) - 1] = 0;
    log_status("HANDOFF_TEST_MAX_DETAIL", detail);
    memset(oversized, 'z', sizeof(oversized) - 1); oversized[sizeof(oversized) - 1] = 0;
    log_status("HANDOFF_TEST_OVERFLOW", oversized);
    file = CreateFileW(g_stack_log_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    assert(ReadFile(file, output, sizeof(output) - 1, &read, NULL)); output[read] = 0;
    first = strstr(output, "LOGIN_HANDOFF_CHECKPOINT "); assert(first);
    end = strstr(first, "\r\n"); assert(end && end - first >= 384);
    field = strstr(first, "services-state=7,auth-state=0,"); assert(field && field < end);
    field = strstr(first, "services-ticket-present=-1,auth-ticket-present=-1,"); assert(field && field < end);
    assert(strstr(first, "auth-client-present=1,pending-ticket-login=0,channel-present=0,manager-state=2\r\n"));
    second = strstr(end + 2, "LOGIN_HANDOFF_CHECKPOINT "); assert(second);
    assert(!strstr(second + 1, "LOGIN_HANDOFF_CHECKPOINT "));
    assert(strstr(second, "services-state=-2147483648,auth-state=2147483647,"));
    assert(strstr(second, "suppress-auth=255,suppress-copy=255,"));
    assert(strstr(second, "manager-state=-2147483648\r\n"));
    assert(strstr(output, detail));
    assert(!strstr(output, "HANDOFF_TEST_OVERFLOW"));
    assert(strstr(output, "STACK_PROBE_LOG_ERROR detail=status-format-or-size\r\n"));
    CloseHandle(file);
    g_stack_log_path[0] = 0;
}

static void test_handoff_zero_debug(void) {
    CONTEXT ctx, before;
    EXCEPTION_RECORD record = {0};
    EXCEPTION_POINTERS exception = {&record, &ctx};
    LONG saved_install = g_dispatch_install_state;
    DWORD i;
    g_dispatch_install_state = 2;
    g_login_handoff_sweep_requested = TRUE;
    ZeroMemory(&ctx, sizeof(ctx));
    record.ExceptionCode = EXCEPTION_SINGLE_STEP;
    ctx.Rip = (uintptr_t)g_game_base + handoff_sites[1];
    record.ExceptionAddress = (void *)(uintptr_t)ctx.Rip;
    assert(!handoff_current_thread_owned());
    assert(!handle_handoff_zero_debug(&exception));
    assert(handoff_publish_owner(GetCurrentThread()));
    assert(handoff_current_thread_owned());
    /* Reused ID with a different creation timestamp is not ownership. */
    handoff_owned[0].created.dwLowDateTime ^= 1;
    assert(!handoff_current_thread_owned() && !handle_handoff_zero_debug(&exception));
    handoff_owned[0].created.dwLowDateTime ^= 1;
    ZeroMemory(handoff_last, sizeof(handoff_last));
    ZeroMemory(handoff_counts, sizeof(handoff_counts));
    for (i = 0; i < 3; ++i) {
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.Rip = (uintptr_t)g_game_base + handoff_sites[i];
        record.ExceptionAddress = (void *)(uintptr_t)ctx.Rip;
        before = ctx; SetLastError(9912);
        assert(dispatch_exception_handler(&exception) == EXCEPTION_CONTINUE_EXECUTION);
        assert(GetLastError() == 9912);
        before.EFlags |= 0x10000;
        assert(!memcmp(&ctx, &before, sizeof(ctx)));
        assert(handoff_counts[i] == 1);
    }
    assert(handoff_fallback_count == 3);
    ctx.Rip = (uintptr_t)g_game_base + handoff_sites[1];
    record.ExceptionAddress = (void *)(uintptr_t)ctx.Rip;
    before = ctx;
    g_game_base[handoff_sites[1]] ^= 1;
    assert(!handle_handoff_zero_debug(&exception));
    assert(!memcmp(&ctx, &before, sizeof(ctx)));
    g_game_base[handoff_sites[1]] ^= 1;
    ctx.Dr6 = 4; assert(!handle_handoff_zero_debug(&exception)); ctx.Dr6 = 0;
    ctx.Dr7 = 0x54; assert(!handle_handoff_zero_debug(&exception)); ctx.Dr7 = 0;
    ctx.EFlags |= 0x100; assert(!handle_handoff_zero_debug(&exception)); ctx.EFlags &= ~0x100;
    record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    assert(!handle_handoff_zero_debug(&exception)); record.ExceptionFlags = 0;
    record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    assert(dispatch_exception_handler(&exception) == EXCEPTION_CONTINUE_SEARCH);
    record.ExceptionCode = EXCEPTION_SINGLE_STEP;
    record.ExceptionAddress = NULL;
    assert(!handle_handoff_zero_debug(&exception));
    ctx.Rip += 1; record.ExceptionAddress = (void *)(uintptr_t)ctx.Rip;
    assert(dispatch_exception_handler(&exception) == EXCEPTION_CONTINUE_SEARCH);
    ctx.Rip -= 1; record.ExceptionAddress = (void *)(uintptr_t)ctx.Rip;
    g_login_handoff_sweep_requested = FALSE;
    assert(!handle_handoff_zero_debug(&exception));
    g_login_handoff_sweep_requested = TRUE; g_dispatch_install_state = 1;
    assert(!handle_handoff_zero_debug(&exception));
    g_dispatch_install_state = 2; g_tctd_echo_enabled = FALSE;
    assert(!handle_handoff_zero_debug(&exception));
    g_tctd_echo_enabled = TRUE; g_login_handoff_requested = FALSE;
    assert(!handle_handoff_zero_debug(&exception));
    g_login_handoff_requested = TRUE; g_login_handoff_sweep_requested = FALSE;
    g_dispatch_install_state = saved_install;
    handoff_owned_count = 0;
}

static DWORD WINAPI handoff_late_test_thread(LPVOID worker) {
    assert(WaitForSingleObject(handoff_test_go, 10000) == WAIT_OBJECT_0);
    ((void (*)(void *))(g_game_base + handoff_sites[0]))(worker);
    return 0;
}

static void test_handoff_thread_coverage(void) {
    HANDLE thread;
    PVOID handler;
    CONTEXT ctx;
    BYTE worker[0x110] = {0};
    DWORD pass;
    LONG saved_install = g_dispatch_install_state;
    handoff_test_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    assert(handoff_test_go);
    /* Stand-in executable entry; real handler and Windows debug registers. */
    g_game_base[handoff_sites[0]] = 0xc3;
    assert(FlushInstructionCache(GetCurrentProcess(), g_game_base + handoff_sites[0], 1));
    handler = AddVectoredExceptionHandler(1, dispatch_exception_handler);
    assert(handler);
    ZeroMemory(handoff_last, sizeof(handoff_last));
    ZeroMemory(handoff_counts, sizeof(handoff_counts));
    g_dispatch_install_state = 2;
    g_login_handoff_sweep_requested = FALSE;
    pass = handoff_sweep_count;
    refresh_login_handoff_threads();
    assert(handoff_sweep_count == pass);
    g_login_handoff_sweep_requested = TRUE;
    handoff_next_sweep = 0;
    refresh_login_handoff_threads();
    pass = handoff_sweep_count;
    refresh_login_handoff_threads();
    assert(handoff_sweep_count == pass); /* rate limited */
    thread = CreateThread(NULL, 0, handoff_late_test_thread, worker, CREATE_SUSPENDED, NULL);
    assert(thread);
    handoff_next_sweep = 0;
    refresh_login_handoff_threads(); /* thread born after first sweep, no sockets */
    ZeroMemory(&ctx, sizeof(ctx)); ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    assert(GetThreadContext(thread, &ctx) && handoff_debug_matches(&ctx));
    assert(handoff_verify_thread(thread) == HANDOFF_THREAD_VERIFIED);
    ctx.Dr0 = (uintptr_t)g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA;
    ctx.Dr7 |= 1;
    ctx.Dr2 = 0; ctx.Dr7 &= ~(DWORD64)0x30;
    assert(SetThreadContext(thread, &ctx));
    assert(handoff_verify_thread(thread) == HANDOFF_THREAD_REPAIRED);
    assert(GetThreadContext(thread, &ctx) && handoff_debug_matches(&ctx));
    assert(ctx.Dr0 == (uintptr_t)g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA && (ctx.Dr7 & 3) == 1);
    ctx.Dr2 = 123; /* active foreign breakpoint must not be overwritten */
    assert(SetThreadContext(thread, &ctx));
    assert(handoff_verify_thread(thread) == HANDOFF_THREAD_CONFLICT);
    assert(GetThreadContext(thread, &ctx) && ctx.Dr2 == 123);
    ctx.Dr2 = (uintptr_t)g_game_base + handoff_sites[1];
    ctx.Dr0 = 0; ctx.Dr7 &= ~(DWORD64)3;
    assert(SetThreadContext(thread, &ctx));
    assert(ResumeThread(thread) == 1); /* sweeps balanced every suspension */
    assert(SetEvent(handoff_test_go));
    assert(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    assert(handoff_counts[0] == 1); /* actual exception on late thread */
    CloseHandle(thread); CloseHandle(handoff_test_go);
    assert(RemoveVectoredExceptionHandler(handler));
    memcpy(g_game_base + handoff_sites[0], handoff_signatures[0], 8);
    g_dispatch_install_state = saved_install;
    g_login_handoff_requested = FALSE;
    handoff_next_sweep = 0; pass = handoff_sweep_count;
    refresh_login_handoff_threads();
    assert(handoff_sweep_count == pass); /* other modes untouched */
    g_login_handoff_sweep_requested = FALSE;
}

static void test_handoff_fault_logging(void) {
    WCHAR directory[MAX_PATH], path[MAX_PATH];
    EXCEPTION_RECORD record = {0};
    CONTEXT ctx = {0}, before;
    EXCEPTION_POINTERS exception = {&record, &ctx};
    HANDLE file;
    char output[22000];
    DWORD read, i;
    LONG count;
    assert(GetTempPathW(MAX_PATH, directory));
    assert(GetTempFileNameW(directory, L"ihf", 0, path));
    lstrcpyW(g_stack_log_path, path);
    g_login_handoff_requested = TRUE;
    assert(initialize_handoff_faults());
    record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = 1;
    record.ExceptionInformation[1] = (ULONG_PTR)"DO_NOT_LOG_PAYLOAD";
    ctx.Rip = (uintptr_t)g_game_base + 0x1234;
    ctx.Dr6 = 0; ctx.Dr7 = 0x54;
    before = ctx;
    SetLastError(7890);
    assert(dispatch_exception_handler(&exception) == EXCEPTION_CONTINUE_SEARCH);
    assert(GetLastError() == 7890 && !memcmp(&ctx, &before, sizeof(ctx)));
    assert(handoff_fault_count == 1);
    handoff_fault_busy = 1;
    record_handoff_exception(&exception);
    assert(handoff_fault_count == 1 && handoff_fault_busy == 1);
    handoff_fault_busy = 0;
    record.ExceptionCode = 0xe06d7363u;
    record_handoff_exception(&exception);
    assert(handoff_fault_count == 1);
    record.ExceptionCode = EXCEPTION_SINGLE_STEP;
    for (i = 0; i < 3; ++i) {
        ctx.Rip = (uintptr_t)g_game_base + handoff_sites[i]; ctx.Dr6 = (DWORD64)2 << i;
        record_handoff_exception(&exception);
        assert(handoff_fault_count == 1);
    }
    ctx.Rip = (uintptr_t)g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA; ctx.Dr6 = 1;
    record_handoff_exception(&exception);
    assert(handoff_fault_count == 1);
    ctx.Rip = (uintptr_t)g_game_base + 0x1234;
    record_handoff_exception(&exception); /* unexpected single-step */
    assert(handoff_fault_count == 2);
    for (i = 0; i < 40; ++i) record_handoff_exception(&exception);
    assert(handoff_fault_count == 32);
    CloseHandle(handoff_fault_file); handoff_fault_file = INVALID_HANDLE_VALUE;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    assert(ReadFile(file, output, sizeof(output) - 1, &read, NULL)); output[read] = 0;
    assert(strstr(output, "sweep=off") && strstr(output, "code=0x00000000c0000005"));
    assert(strstr(output, "access=0x0000000000000001"));
    assert(!strstr(output, "DO_NOT_LOG_PAYLOAD"));
    count = 0;
    for (char *p = output; (p = strstr(p, "LOGIN_HANDOFF_EXCEPTION ")) != NULL; ++p) ++count;
    assert(count == 32);
    CloseHandle(file); assert(DeleteFileW(path));
    g_stack_log_path[0] = 0;
    g_login_handoff_requested = FALSE;
}

static void test_login_handoff(void) {
    CONTEXT ctx, before;
    BYTE frontend[0x29b0] = {0}, services[0x600] = {0}, auth[0x1700] = {0};
    BYTE client[0x50] = {0}, manager[0x80] = {0}, worker[0x110] = {0}, async[0x100] = {0};
    uintptr_t table[3] = {0}, pointer;
    DWORD i, value = 5, old_protect;
    BYTE *guard;
    const char dummy[] = "synthetic-not-a-real-ticket";
    static const BYTE getters[4][8] = {
        {0x48,0x8b,0x41,0x48,0xc3,0xcc,0xcc,0xcc},
        {0x48,0x8b,0x81,0x08,0x04,0x00,0x00,0xc3},
        {0x48,0x8b,0x81,0x88,0x00,0x00,0x00,0xc3},
        {0x48,0x8b,0x81,0x08,0x08,0x00,0x00,0xc3}
    };
    g_login_handoff_requested = TRUE;
    for (i = 0; i < 3; ++i)
        memcpy(g_game_base + handoff_sites[i], handoff_signatures[i], 8);
    for (i = 0; i < 4; ++i) memcpy(g_game_base + 0x12920 + i * 0x20, getters[i], 8);
    assert(initialize_echo_checkpoints());
    g_startup_leads_requested = TRUE;
    assert(!initialize_echo_checkpoints());
    g_startup_leads_requested = FALSE;
    for (i = 0; i < 3; ++i) {
        g_game_base[handoff_sites[i]] ^= 1;
        assert(!initialize_echo_checkpoints());
        g_game_base[handoff_sites[i]] ^= 1;
    }
    g_game_base[0x12920] ^= 1;
    assert(!initialize_echo_checkpoints());
    g_game_base[0x12920] ^= 1;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.Dr0 = (uintptr_t)g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA; ctx.Dr7 = 1;
    assert(echo_context(&ctx, TRUE) && ctx.Dr7 == 0x55);
    assert(ctx.Dr1 == (uintptr_t)g_game_base + handoff_sites[0]);
    ctx.Rip = ctx.Dr1; ctx.Dr6 = 2; ctx.Rcx = (uintptr_t)worker;
    pointer = (uintptr_t)async; memcpy(worker + 0x48, &pointer, 8);
    value = 1; memcpy(async + 0x68, &value, 4);
    before = ctx; SetLastError(7654);
    assert(handle_echo_breakpoint(&ctx));
    assert(GetLastError() == 7654);
    before.Dr6 = 0; before.EFlags |= 0x10000;
    assert(!memcmp(&ctx, &before, sizeof(ctx)));
    assert(handoff_counts[0] == 1 && handoff_last[0][0].fields[1] == 1);
    ctx.Dr6 = 2;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[0] == 1);
    value = 2; memcpy(async + 0x68, &value, 4); ctx.Dr6 = 2;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[0] == 2);
    assert(handoff_last[0][0].fields[1] == 2);
    pointer = (uintptr_t)services; memcpy(frontend + 0x60, &pointer, 8);
    pointer = (uintptr_t)auth; memcpy(frontend + 0x68, &pointer, 8);
    pointer = (uintptr_t)client; memcpy(auth + 0x1128, &pointer, 8);
    pointer = (uintptr_t)manager; memcpy(client, &pointer, 8);
    value = 2; memcpy(manager + 0x38, &value, 4);
    value = 7; memcpy(services + 0x220, &value, 4);
    table[2] = (uintptr_t)g_game_base + 0x12920;
    pointer = (uintptr_t)table; memcpy(services + 0x228, &pointer, 8);
    memcpy(auth + 0xf50, &pointer, 8);
    pointer = (uintptr_t)dummy; memcpy(services + 0x228 + 0x48, &pointer, 8);
    memcpy(auth + 0xf50 + 0x48, &pointer, 8);
    assert(handoff_nonempty((uintptr_t)services, 0x228) == 1);
    assert(handoff_nonempty(1, 0) == -1);
    assert(!handoff_read(UINTPTR_MAX, 8, &pointer, 8));
    ctx.Rip = ctx.Dr2; ctx.Dr6 = 4; ctx.Rsi = (uintptr_t)frontend;
    before = ctx;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[1] == 1);
    before.Dr6 = 0; before.EFlags |= 0x10000;
    assert(!memcmp(&ctx, &before, sizeof(ctx)));
    assert(handoff_last[1][0].fields[3] == 1 && handoff_last[1][0].fields[4] == 1);
    assert(handoff_last[1][0].fields[14] == 2);
    frontend[0x29aa] = 1; ctx.Dr6 = 4;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[1] == 2);
    assert(handoff_last[1][0].fields[10] == 1);
    ctx.Dr6 = 4;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[1] == 2);
    ctx.Rip = ctx.Dr3; ctx.Dr6 = 8; ctx.Rbp = (uintptr_t)manager;
    ctx.R15 = 0; ctx.R12 = 0x1001;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[2] == 1);
    assert(handoff_last[2][0].fields[0] == 2 && handoff_last[2][0].fields[2] == 0x1001);
    guard = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    assert(guard && VirtualProtect(guard, 4096, PAGE_NOACCESS, &old_protect));
    assert(handoff_number((uintptr_t)guard, 0, FALSE) == -1);
    ctx.Rbp = (uintptr_t)guard; ctx.Dr6 = 8;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[2] == 2);
    assert(handoff_last[2][1].fields[0] == -1);
    assert(VirtualFree(guard, 0, MEM_RELEASE));
    handoff_counts[2] = 127; ctx.R15 = 1; ctx.Dr6 = 8;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[2] == 128);
    ctx.R15 = 2; ctx.Dr6 = 8;
    assert(handle_echo_breakpoint(&ctx) && handoff_counts[2] == 128);
    assert(echo_context(&ctx, FALSE) && ctx.Dr7 == 0);
    ctx.Dr2 = 123; ctx.Dr7 = 16;
    assert(!echo_context(&ctx, TRUE) && ctx.Dr2 == 123);
    test_handoff_zero_debug();
    test_handoff_thread_coverage();
    test_handoff_fault_logging();
}
