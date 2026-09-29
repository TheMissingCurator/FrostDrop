/* Poll from the existing bridge worker, independently of game socket activity.
 * Suspend one peer at a time. Do not log, allocate, or take our locks while it
 * is stopped. Read back actual debug registers; never trust the thread-ID cache.
 * This is sampled coverage, not an interception of every thread's first code. */
typedef enum {
    HANDOFF_THREAD_VERIFIED, HANDOFF_THREAD_REPAIRED,
    HANDOFF_THREAD_CONFLICT, HANDOFF_THREAD_FAILED,
    HANDOFF_THREAD_RESUME_FAILED
} HandoffThreadResult;
static ULONGLONG handoff_next_sweep, handoff_next_report;
static DWORD handoff_sweep_count, handoff_thread_reports;
/* Single sweep-worker writer; immutable entries published before peer resume.
 * Creation time prevents a reused thread ID from inheriting breakpoint ownership. */
typedef struct { DWORD id; FILETIME created; } HandoffOwnedThread;
static HandoffOwnedThread handoff_owned[512];
static volatile LONG handoff_owned_count;

static BOOL handoff_publish_owner(HANDLE thread) {
    FILETIME created, exited, kernel, user;
    DWORD id = GetThreadId(thread);
    LONG i, count = InterlockedCompareExchange(&handoff_owned_count, 0, 0);
    if (!id || !GetThreadTimes(thread, &created, &exited, &kernel, &user)) return FALSE;
    for (i = 0; i < count; ++i)
        if (handoff_owned[i].id == id &&
            handoff_owned[i].created.dwLowDateTime == created.dwLowDateTime &&
            handoff_owned[i].created.dwHighDateTime == created.dwHighDateTime) return TRUE;
    if (count >= 512) return FALSE;
    handoff_owned[count].id = id;
    handoff_owned[count].created = created;
    InterlockedExchange(&handoff_owned_count, count + 1);
    return TRUE;
}

static BOOL handoff_current_thread_owned(void) {
    FILETIME created, exited, kernel, user;
    DWORD id = GetCurrentThreadId();
    LONG i, count = InterlockedCompareExchange(&handoff_owned_count, 0, 0);
    if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user)) return FALSE;
    for (i = 0; i < count; ++i)
        if (handoff_owned[i].id == id &&
            handoff_owned[i].created.dwLowDateTime == created.dwLowDateTime &&
            handoff_owned[i].created.dwHighDateTime == created.dwHighDateTime) return TRUE;
    return FALSE;
}

static BOOL handoff_debug_matches(const CONTEXT *ctx) {
    return ctx->Dr1 == (DWORD64)(uintptr_t)(g_game_base + handoff_sites[0]) &&
        ctx->Dr2 == (DWORD64)(uintptr_t)(g_game_base + handoff_sites[1]) &&
        ctx->Dr3 == (DWORD64)(uintptr_t)(g_game_base + handoff_sites[2]) &&
        (ctx->Dr7 & (DWORD64)0xfff000fcu) == 0x54u;
}

/* Caller supplies a peer thread handle, never GetCurrentThread(). */
static HandoffThreadResult handoff_verify_thread(HANDLE thread) {
    CONTEXT before, desired, after;
    HandoffThreadResult result = HANDOFF_THREAD_FAILED;
    ZeroMemory(&before, sizeof(before));
    ZeroMemory(&after, sizeof(after));
    before.ContextFlags = after.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (SuspendThread(thread) == (DWORD)-1) return result;
    if (!GetThreadContext(thread, &before)) goto resume;
    desired = before;
    if (!echo_context(&desired, TRUE)) {
        result = HANDOFF_THREAD_CONFLICT;
        goto resume;
    }
    if (handoff_debug_matches(&before)) {
        result = HANDOFF_THREAD_VERIFIED;
        goto resume;
    }
    desired.Dr6 = before.Dr6;
    if (!SetThreadContext(thread, &desired)) goto resume;
    if (GetThreadContext(thread, &after) && handoff_debug_matches(&after) &&
        after.Dr0 == before.Dr0 &&
        (after.Dr7 & 0x000f0003u) == (before.Dr7 & 0x000f0003u))
        result = HANDOFF_THREAD_REPAIRED;
resume:
    if ((result == HANDOFF_THREAD_VERIFIED || result == HANDOFF_THREAD_REPAIRED) &&
        !handoff_publish_owner(thread)) {
        if (result == HANDOFF_THREAD_REPAIRED) SetThreadContext(thread, &before);
        result = HANDOFF_THREAD_FAILED;
    }
    /* Undo exactly our own suspension, including on all failure paths. */
    if (ResumeThread(thread) == (DWORD)-1) result = HANDOFF_THREAD_RESUME_FAILED;
    return result;
}

static void refresh_login_handoff_threads(void) {
    HANDLE snapshot;
    THREADENTRY32 entry;
    DWORD pid, self, seen = 0, verified = 0, repaired = 0, conflicts = 0, failed = 0;
    DWORD resume_failed = 0, enumeration_error = 0;
    ULONGLONG now;
    BOOL have_entry;
    char detail[320];
    if (!g_login_handoff_requested || !g_login_handoff_sweep_requested || !g_tctd_echo_enabled ||
        g_dispatch_install_state != 2) return;
    now = GetTickCount64();
    if (now < handoff_next_sweep) return;
    handoff_next_sweep = now + 250;
    ++handoff_sweep_count;
    pid = GetCurrentProcessId(); self = GetCurrentThreadId();
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        enumeration_error = GetLastError();
        goto report;
    }
    ZeroMemory(&entry, sizeof(entry)); entry.dwSize = sizeof(entry);
    have_entry = Thread32First(snapshot, &entry);
    while (have_entry) {
        if (entry.th32OwnerProcessID == pid && entry.th32ThreadID != self) {
            HANDLE thread;
            HandoffThreadResult result = HANDOFF_THREAD_FAILED;
            ++seen;
            thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION |
                                THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID);
            if (thread) {
                result = handoff_verify_thread(thread);
                CloseHandle(thread);
            }
            if (result == HANDOFF_THREAD_VERIFIED) ++verified;
            else if (result == HANDOFF_THREAD_REPAIRED) { ++verified; ++repaired; }
            else if (result == HANDOFF_THREAD_CONFLICT) ++conflicts;
            else if (result == HANDOFF_THREAD_RESUME_FAILED) ++resume_failed;
            else ++failed;
            if (result != HANDOFF_THREAD_VERIFIED && handoff_thread_reports < 128) {
                ++handoff_thread_reports;
                snprintf(detail, sizeof(detail), "target-thread=%lu,result=%s",
                    (unsigned long)entry.th32ThreadID,
                    result == HANDOFF_THREAD_REPAIRED ? "armed-readback-ok" :
                    result == HANDOFF_THREAD_CONFLICT ? "foreign-breakpoint-conflict" :
                    result == HANDOFF_THREAD_RESUME_FAILED ? "resume-failed" : "unverified");
                log_status("LOGIN_HANDOFF_THREAD", detail);
                if (handoff_thread_reports == 128)
                    log_status("LOGIN_HANDOFF_THREAD_LIMIT", "individual-records=128,sweeps=continue");
            }
        }
        entry.dwSize = sizeof(entry);
        have_entry = Thread32Next(snapshot, &entry);
    }
    enumeration_error = GetLastError();
    if (enumeration_error == ERROR_NO_MORE_FILES) enumeration_error = 0;
    CloseHandle(snapshot);
report:
    if (now >= handoff_next_report || repaired || resume_failed) {
        handoff_next_report = now + 5000;
        snprintf(detail, sizeof(detail),
            "pass=%lu,seen=%lu,verified=%lu,repaired=%lu,conflicts=%lu,unverified=%lu,"
            "resume-failed=%lu,enumeration-error=%lu,interval-ms=250",
            (unsigned long)handoff_sweep_count, (unsigned long)seen,
            (unsigned long)verified, (unsigned long)repaired, (unsigned long)conflicts,
            (unsigned long)failed, (unsigned long)resume_failed, (unsigned long)enumeration_error);
        log_status("LOGIN_HANDOFF_COVERAGE", detail);
    }
}
