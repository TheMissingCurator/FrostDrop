/* Bounded resolver metadata, never URLs, headers, tokens or response bodies.
 * The wrapper creates the empty file with mode 0600 in a fresh 0700 folder. */
static WCHAR startup_leads_file[MAX_PATH];
static volatile LONG startup_leads_file_ready, startup_leads_lock;
static LONG startup_leads_records;

/* Companion to the existing runtime .text image. Fixed module .rdata only,
 * never heap, account objects, or the writable .data section. */
static BOOL write_startup_static_section(const WCHAR *path, DWORD rva, DWORD length) {
    struct { char magic[8]; DWORD rva, length; } header = {{'I','S','A','C','R','D','0','1'}, rva, length};
    BYTE chunk[4096];
    DWORD offset = 0, written;
    HANDLE file;
    BOOL ok;
    _Static_assert(sizeof(header) == 16, "static capture header");
    if (!length || rva >= g_game_size || length > g_game_size - rva) return FALSE;
    file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    ok = GetFileSize(file, NULL) == 0 &&
         WriteFile(file, &header, sizeof(header), &written, NULL) && written == sizeof(header);
    while (ok && offset < length) {
        SIZE_T received = 0;
        DWORD amount = length - offset;
        if (amount > sizeof(chunk)) amount = sizeof(chunk);
        ok = ReadProcessMemory(GetCurrentProcess(), g_game_base + rva + offset,
                               chunk, amount, &received) && received == amount &&
             WriteFile(file, chunk, amount, &written, NULL) && written == amount;
        if (ok) offset += amount;
    }
    if (ok) ok = FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

static void capture_startup_static_section(void) {
    WCHAR path[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"ISAC_STARTUP_STATIC_FILE", path, MAX_PATH);
    if (!length) return; /* Older wrappers preserve their previous behavior. */
    if (length >= MAX_PATH || !write_startup_static_section(path, 0x2901000u, 0x152cc8au)) {
        log_status("STARTUP_STATIC_ERROR", "capture-failed,partial-file-retained,probe-continues=yes");
        return;
    }
    log_status("STARTUP_STATIC_CAPTURED",
        "section=rdata,rva=0x2901000,bytes=22203530,payloads=private,heap=excluded,data-section=excluded");
}

static BOOL initialize_startup_leads_capture(void) {
    DWORD length, written;
    HANDLE file;
    BOOL ok;
    length = GetEnvironmentVariableW(L"ISAC_STARTUP_LEADS_FILE", startup_leads_file, MAX_PATH);
    if (!length || length >= MAX_PATH) return FALSE;
    file = CreateFileW(startup_leads_file, GENERIC_WRITE, FILE_SHARE_READ,
                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    ok = GetFileSize(file, NULL) == 0 &&
         WriteFile(file, "ISACDNS1\n", 9, &written, NULL) && written == 9;
    CloseHandle(file);
    if (ok) {
        InterlockedExchange(&startup_leads_file_ready, 1);
        capture_startup_static_section();
    }
    return ok;
}

static const char *startup_leads_safe_name(const char *name) {
    unsigned int i;
    if (!name || !name[0]) return "-";
    for (i = 0; i < 128 && name[i]; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == ':'))
            return "-";
    }
    return i < 128 ? name : "-";
}

static void capture_startup_resolver(LONG attempt, const char *api,
    const char *node, const char *service, int result, BOOL redirected) {
    char record[384], detail[160];
    DWORD written;
    HANDLE file;
    int length;
    BOOL ok;
    if (!g_startup_leads_requested || !startup_leads_file_ready) return;
    if (InterlockedCompareExchange(&startup_leads_lock, 1, 0)) {
        log_status("STARTUP_LEADS_DROP", "reason=private-writer-busy");
        return;
    }
    if (startup_leads_records >= 128) {
        InterlockedExchange(&startup_leads_lock, 0);
        return;
    }
    ++startup_leads_records;
    length = snprintf(record, sizeof(record), "%llu\t%lu\t%ld\t%s\t%d\t%d\t%s\t%s\n",
        (unsigned long long)GetTickCount64(), (unsigned long)GetCurrentThreadId(),
        attempt, api, result, (int)redirected,
        startup_leads_safe_name(node), startup_leads_safe_name(service));
    file = CreateFileW(startup_leads_file, FILE_APPEND_DATA, FILE_SHARE_READ,
                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok = file != INVALID_HANDLE_VALUE;
    if (ok) {
        ok = length > 0 && length < (int)sizeof(record) &&
             WriteFile(file, record, (DWORD)length, &written, NULL) && written == (DWORD)length;
        CloseHandle(file);
    }
    snprintf(detail, sizeof(detail), "attempt=%ld,api=%s,result=%d,names=private,record=%ld",
             attempt, api, result, startup_leads_records);
    log_status(ok ? "STARTUP_LEADS_RESOLVER" : "STARTUP_LEADS_ERROR", detail);
    InterlockedExchange(&startup_leads_lock, 0);
}
