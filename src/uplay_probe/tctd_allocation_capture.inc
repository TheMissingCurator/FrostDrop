/* Included after stack_probe.c's checked-memory and transport helpers.
 * Four signature-checked hardware checkpoints; no game instructions patched.
 * The runtime text image supplies the ABI, not guessed SSL structure offsets.
 */
static const uintptr_t allocation_sites[4] = {
    0x224817bu, 0x0f11d8u, 0x0f1251u, 0x0bb4dfu
};
static const BYTE allocation_signatures[4][8] = {
    {0xe8,0xb0,0x05,0x00,0x00,0x48,0x8b,0x8c},
    {0x66,0x83,0x7c,0x24,0x30,0x00,0x74,0x1d},
    {0x84,0xc0,0x75,0x0c,0x48,0x8b,0x4b,0x08},
    {0xe8,0x8c,0x00,0x18,0x02,0x84,0xc0,0x75}
};
static WCHAR allocation_file[MAX_PATH];
static volatile LONG allocation_lock;
static LONG allocation_sequence;
static DWORD allocation_bytes;

typedef struct allocation_record_header {
    DWORD kind, sequence, thread, length;
    ULONGLONG tick, object, site;
    DWORD result, reserved;
} allocation_record_header;
_Static_assert(sizeof(allocation_record_header) == 48, "capture ABI");

static BOOL initialize_allocation_capture(void) {
    DWORD i, written, length;
    HANDLE file;
    length = GetEnvironmentVariableW(
        L"ISAC_TCTD_ALLOCATION_FILE", allocation_file, MAX_PATH
    );
    if (length == 0 || length >= MAX_PATH) {
        log_status("TCTD_ALLOCATION_ERROR", "missing-private-output-path");
        return FALSE;
    }
    for (i = 0; i < 4; ++i) {
        const BYTE *site = g_game_base + allocation_sites[i];
        if (!readable_code_window(site, 8) ||
            memcmp(site, allocation_signatures[i], 8) != 0) {
            log_status("TCTD_ALLOCATION_ERROR", "checkpoint-signature-mismatch");
            return FALSE;
        }
    }
    /* Wrapper precreates a 0600 file in its own 0700 directory. */
    file = CreateFileW(allocation_file, GENERIC_WRITE, FILE_SHARE_READ,
                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        log_status("TCTD_ALLOCATION_ERROR", "private-output-open-failed");
        return FALSE;
    }
    if (GetFileSize(file, NULL) != 0 ||
        !WriteFile(file, "ISACAL01", 8, &written, NULL) || written != 8) {
        CloseHandle(file);
        log_status("TCTD_ALLOCATION_ERROR", "private-output-not-empty-or-write-failed");
        return FALSE;
    }
    CloseHandle(file);
    log_status("TCTD_ALLOCATION_READY",
        "checkpoints=tls-plaintext,message-status,parsed-allocation,handoff,"
        "payloads=private,max-events=128,max-bytes=1048576");
    return TRUE;
}

static void write_allocation_record(DWORD kind, const CONTEXT *ctx,
    ULONGLONG object, DWORD result, const void *data, DWORD length) {
    allocation_record_header header;
    HANDLE file;
    DWORD written;
    BOOL ok;
    char detail[256];
    if (length > 65536 || (length && !readable_memory_window(data, length))) {
        log_status("TCTD_ALLOCATION_ERROR", "invalid-payload-range");
        return;
    }
    if (InterlockedCompareExchange(&allocation_lock, 1, 0) != 0) {
        log_status("TCTD_ALLOCATION_DROP", "capture-busy");
        return;
    }
    if (allocation_sequence >= 128 || allocation_bytes + length > 1048576) {
        InterlockedExchange(&allocation_lock, 0);
        return;
    }
    ZeroMemory(&header, sizeof(header));
    header.kind = kind;
    header.sequence = ++allocation_sequence;
    header.thread = GetCurrentThreadId();
    header.length = length;
    header.tick = GetTickCount64();
    header.object = object;
    header.site = ctx->Rip - (ULONGLONG)(uintptr_t)g_game_base;
    header.result = result;
    file = CreateFileW(allocation_file, FILE_APPEND_DATA, FILE_SHARE_READ,
                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok = file != INVALID_HANDLE_VALUE;
    if (ok) {
        ok = WriteFile(file, &header, sizeof(header), &written, NULL) &&
             written == sizeof(header);
        if (ok && length)
            ok = WriteFile(file, data, length, &written, NULL) && written == length;
        CloseHandle(file);
    }
    allocation_bytes += length;
    snprintf(detail, sizeof(detail),
        "sequence=%lu,kind=%lu,site-rva=0x%llx,bytes=%lu,result=%lu,payloads=private",
        (unsigned long)header.sequence, (unsigned long)kind,
        (unsigned long long)header.site, (unsigned long)length,
        (unsigned long)result);
    log_status(ok ? "TCTD_ALLOCATION_RECORD" : "TCTD_ALLOCATION_ERROR", detail);
    InterlockedExchange(&allocation_lock, 0);
}

static void capture_allocation_checkpoint(DWORD slot, const CONTEXT *ctx) {
    const BYTE *object;
    const BYTE *payload;
    DWORD length;
    if (slot == 0) {
        /* Call to 2248730: rcx=transport, rdx=decrypted chunk, r8d=size.
         * 2248000 obtains this chunk from the TLS read queue, not Winsock. */
        SOCKET socket_handle;
        object = (const BYTE *)(uintptr_t)ctx->Rcx;
        if (!readable_memory_window(object, 0xd0)) return;
        memcpy(&socket_handle, object + 0xc8, sizeof(socket_handle));
        if (!socket_peer_is_port(socket_handle, 27015)) return;
        write_allocation_record(1, ctx, ctx->Rcx, 0,
            (const void *)(uintptr_t)ctx->Rdx, (DWORD)ctx->R8);
    } else if (slot == 1) {
        WORD status;
        object = (const BYTE *)(uintptr_t)(ctx->Rsp + 0x20);
        if (!readable_memory_window(object, 0x30)) return;
        memcpy(&status, object + 0x10, sizeof(status));
        write_allocation_record(2, ctx, ctx->Rbx, status, object, 0x30);
    } else {
        DWORD result = slot == 2 ? (DWORD)(ctx->Rax & 0xff) : 1;
        object = slot == 2 ? (const BYTE *)(uintptr_t)(ctx->Rsp + 0x60)
                          : (const BYTE *)(uintptr_t)ctx->Rdx;
        if (!result) {
            write_allocation_record(3, ctx, ctx->Rbx, result, NULL, 0);
            return;
        }
        /* Output string: 0x400 inline bytes, data pointer at +0x408,
         * used length at +0x410. Never capture unused capacity. */
        if (!readable_memory_window(object, 0x418)) return;
        memcpy(&payload, object + 0x408, sizeof(payload));
        memcpy(&length, object + 0x410, sizeof(length));
        write_allocation_record(slot + 1, ctx, ctx->Rbx, result, payload, length);
    }
}

static BOOL allocation_breakpoints(HANDLE thread, BOOL enabled) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return FALSE;
    if (enabled && (ctx.Dr7 & 0xff) &&
        (ctx.Dr0 != (DWORD64)(uintptr_t)(g_game_base + allocation_sites[0]) ||
         ctx.Dr1 != (DWORD64)(uintptr_t)(g_game_base + allocation_sites[1]) ||
         ctx.Dr2 != (DWORD64)(uintptr_t)(g_game_base + allocation_sites[2]) ||
         ctx.Dr3 != (DWORD64)(uintptr_t)(g_game_base + allocation_sites[3])))
        return FALSE;
    ctx.Dr0 = enabled ? (DWORD64)(uintptr_t)(g_game_base + allocation_sites[0]) : 0;
    ctx.Dr1 = enabled ? (DWORD64)(uintptr_t)(g_game_base + allocation_sites[1]) : 0;
    ctx.Dr2 = enabled ? (DWORD64)(uintptr_t)(g_game_base + allocation_sites[2]) : 0;
    ctx.Dr3 = enabled ? (DWORD64)(uintptr_t)(g_game_base + allocation_sites[3]) : 0;
    ctx.Dr6 = 0;
    ctx.Dr7 = (ctx.Dr7 & ~(DWORD64)0xffff00ffu) | (enabled ? 0x55u : 0);
    return SetThreadContext(thread, &ctx);
}

static BOOL handle_allocation_breakpoint(CONTEXT *ctx) {
    DWORD slot, saved_error;
    if (!g_tctd_allocation_enabled) return FALSE;
    for (slot = 0; slot < 4; ++slot) {
        if ((ctx->Dr6 & ((DWORD64)1 << slot)) &&
            ctx->Rip == (DWORD64)(uintptr_t)(g_game_base + allocation_sites[slot])) {
            saved_error = GetLastError();
            capture_allocation_checkpoint(slot, ctx);
            SetLastError(saved_error);
            ctx->Dr6 = 0;
            ctx->EFlags |= 0x10000; /* RF: execute the watched instruction once. */
            return TRUE;
        }
    }
    return FALSE;
}
