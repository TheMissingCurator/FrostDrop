/* Exercise the actual capture and verifier handlers with synthetic contexts.
 * No retail executable or network connection is used. */
#include "../src/uplay_probe/stack_probe.c"
#include <assert.h>
#include "login_handoff_smoke.inc"

static unsigned int test_port = 27015;
static INT WSAAPI test_resolve_a(PCSTR node, PCSTR service, const ADDRINFOA *hints, PADDRINFOA *out) {
    (void)node; (void)service; (void)hints; (void)out;
    WSASetLastError(11002);
    return 11002;
}
static INT WSAAPI test_resolve_w(PCWSTR node, PCWSTR service, const ADDRINFOW *hints, PADDRINFOW *out) {
    (void)node; (void)service; (void)hints; (void)out;
    WSASetLastError(11002);
    return 11002;
}
static int WSAAPI test_peer(SOCKET sock, struct sockaddr *address, int *length) {
    struct sockaddr_in peer;
    (void)sock;
    ZeroMemory(&peer, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons((u_short)test_port);
    memcpy(address, &peer, sizeof(peer));
    *length = sizeof(peer);
    return 0;
}

int main(int argc, char **argv) {
    CONTEXT ctx;
    BYTE transport[0xd0] = {0}, stack[0x500] = {0}, verifier[0x144] = {0};
    const BYTE payload[] = "allocation-test";
    const BYTE *pointer = payload;
    DWORD length = sizeof(payload) - 1, mode = 1;
    DWORD i;
    assert(argc == 2);
    assert(SetEnvironmentVariableA("ISAC_TCTD_ALLOCATION_FILE", argv[1]));
    g_game_base = VirtualAlloc(NULL, 0x2249000, MEM_RESERVE | MEM_COMMIT,
                              PAGE_EXECUTE_READWRITE);
    assert(g_game_base);
    for (i = 0; i < 3; ++i)
        memcpy(g_game_base + echo_sites[i], echo_signatures[i], 8);
    assert(initialize_echo_checkpoints());
    g_game_base[echo_sites[0]] ^= 1;
    assert(!initialize_echo_checkpoints());
    g_game_base[echo_sites[0]] ^= 1;
    g_tctd_echo_enabled = TRUE;
    ZeroMemory(&ctx, sizeof(ctx));
    assert(echo_context(&ctx, TRUE));
    assert(ctx.Dr7 == 0x54 && ctx.Dr0 == 0);
    ctx.Dr0 = (DWORD64)(uintptr_t)(g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA);
    ctx.Dr7 |= 1;
    assert(echo_context(&ctx, TRUE));
    assert(ctx.Dr7 == 0x55 && ctx.Dr0 != 0);
    ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + echo_sites[0]);
    ctx.Dr6 = 2; ctx.R8 = 51000; ctx.R9 = 1572;
    SetLastError(4321);
    assert(handle_echo_breakpoint(&ctx));
    assert(echo_event_count == 1 && GetLastError() == 4321 && (ctx.EFlags & 0x10000));
    ctx.Dr6 = 2; ctx.R8 = 443;
    assert(handle_echo_breakpoint(&ctx) && echo_event_count == 1);
    {
        const BYTE *test_transport = transport;
        memcpy(stack + 0x10, &test_transport, sizeof(test_transport));
        ctx.R14 = (DWORD64)(uintptr_t)stack;
        g_getpeername = test_peer;
        test_port = 51000;
        ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + echo_sites[1]);
        ctx.Dr6 = 4; ctx.Rax = 0;
        assert(handle_echo_breakpoint(&ctx) && echo_event_count == 2);
        ctx.Dr6 = 4; ctx.Rax = 1;
        assert(handle_echo_breakpoint(&ctx) && echo_event_count == 3);
        ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + echo_sites[2]);
        ctx.Dr6 = 8;
        assert(handle_echo_breakpoint(&ctx) && echo_event_count == 4);
        test_port = 443; ctx.Dr6 = 8;
        assert(handle_echo_breakpoint(&ctx) && echo_event_count == 4);
        ctx.R14 = 1; ctx.Dr6 = 8;
        assert(handle_echo_breakpoint(&ctx) && echo_event_count == 4);
        test_port = 27015;
    }
    ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + echo_sites[0]);
    ctx.Dr6 = 2; ctx.R8 = 55001; ctx.R9 = 2056;
    assert(handle_echo_breakpoint(&ctx) && echo_event_count == 5);
    ctx.Dr6 = 2; ctx.R8 = 55002; ctx.R9 = 556;
    assert(handle_echo_breakpoint(&ctx) && echo_event_count == 6);
    assert(echo_context(&ctx, FALSE));
    assert(ctx.Dr0 == 0 && ctx.Dr1 == 0 && ctx.Dr2 == 0 && ctx.Dr3 == 0 && ctx.Dr7 == 0);
    ctx.Dr1 = 123; ctx.Dr7 = 4;
    assert(!echo_context(&ctx, TRUE) && ctx.Dr1 == 123);
    {
        char private_path[MAX_PATH];
        BYTE manager[0x200] = {0}, candidate[0x68] = {0};
        DWORD state = 2, kind = 0;
        WORD selected_port = 55001;
        uintptr_t connection = 123, caller;
        snprintf(private_path, sizeof(private_path), "%s.dns", argv[1]);
        assert(SetEnvironmentVariableA("ISAC_STARTUP_LEADS_FILE", private_path));
        g_startup_leads_requested = TRUE;
        g_game_size = 0x2249000;
        for (i = 0; i < 3; ++i)
            memcpy(g_game_base + leads_sites[i], leads_signatures[i], 8);
        g_game_base[leads_sites[1]] ^= 1;
        assert(!initialize_echo_checkpoints());
        g_game_base[leads_sites[1]] ^= 1;
        assert(initialize_echo_checkpoints());
        assert(!initialize_startup_leads_capture()); /* Never overwrite a capture. */
        ZeroMemory(&ctx, sizeof(ctx));
        assert(echo_context(&ctx, TRUE));
        assert(ctx.Dr2 == (DWORD64)(uintptr_t)(g_game_base + leads_sites[1]));
        ctx.Dr0 = (DWORD64)(uintptr_t)(g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA);
        ctx.Dr7 |= 1;
        assert(echo_context(&ctx, TRUE) && ctx.Dr7 == 0x55);
        ctx.Rsp = (DWORD64)(uintptr_t)stack;
        caller = (uintptr_t)g_game_base + 0x5c152;
        memcpy(stack + 0xb8, &caller, sizeof(caller));
        memcpy(manager + 0x38, &state, sizeof(state));
        ctx.R13 = (DWORD64)(uintptr_t)manager;
        ctx.R12 = kind; ctx.Rax = 1;
        ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + leads_sites[1]);
        ctx.Dr6 = 4;
        SetLastError(9876);
        assert(handle_echo_breakpoint(&ctx));
        assert(leads_counts[1] == 1 && GetLastError() == 9876 && (ctx.EFlags & 0x10000));
        memcpy(candidate + 0x58, &selected_port, sizeof(selected_port));
        memcpy(candidate + 0x5c, &kind, sizeof(kind));
        memcpy(candidate + 0x60, &connection, sizeof(connection));
        ctx.Rbx = (DWORD64)(uintptr_t)candidate;
        ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + leads_sites[2]);
        ctx.Dr6 = 8;
        assert(handle_echo_breakpoint(&ctx) && leads_counts[2] == 1);
        ctx.Rbx = 0; ctx.R13 = 1; ctx.Rsp = 1; ctx.Dr6 = 8;
        assert(handle_echo_breakpoint(&ctx) && leads_counts[2] == 2);
        ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + leads_sites[0]);
        ctx.R8 = 443; ctx.R9 = 999; ctx.Dr6 = 2;
        assert(handle_echo_breakpoint(&ctx) && leads_counts[0] == 1);
        assert(echo_context(&ctx, FALSE) && ctx.Dr7 == 0 && ctx.Dr0 == 0);
        assert(strcmp(startup_leads_safe_name("example.invalid"), "example.invalid") == 0);
        assert(strcmp(startup_leads_safe_name("https://secret.invalid/token?abc"), "-") == 0);
        assert(strcmp(startup_leads_safe_name("host\nforged"), "-") == 0);
        g_original_getaddrinfo_a = test_resolve_a;
        g_original_getaddrinfo_w = test_resolve_w;
        assert(hook_transport_getaddrinfo_a("example.invalid", "80", NULL, NULL) == 11002);
        assert(WSAGetLastError() == 11002);
        assert(hook_transport_getaddrinfo_w(L"other.invalid", L"443", NULL, NULL) == 11002);
        assert(WSAGetLastError() == 11002 && startup_leads_records == 2);
        capture_startup_resolver(3, "a", "https://secret.invalid/token?abc", "80", 11002, FALSE);
        startup_leads_records = 128;
        capture_startup_resolver(4, "a", "limit.invalid", "80", 11002, FALSE);
        assert(startup_leads_records == 128);
        g_startup_leads_requested = FALSE;
    }
    test_login_handoff();
    test_handoff_log_output(argv[1]);
    {
        WCHAR snapshot[MAX_PATH];
        char snapshot_ascii[MAX_PATH];
        HANDLE file;
        BYTE header[16];
        DWORD amount, protect;
        snprintf(snapshot_ascii, sizeof(snapshot_ascii), "%s.rdata", argv[1]);
        assert(MultiByteToWideChar(CP_ACP, 0, snapshot_ascii, -1, snapshot, MAX_PATH));
        memcpy(g_game_base + 0x3000, "GET /synthetic HTTP/1.1", 23);
        assert(write_startup_static_section(snapshot, 0x3000, 4097));
        assert(!write_startup_static_section(snapshot, 0x3000, 4097));
        assert(!write_startup_static_section(snapshot, (DWORD)g_game_size, 1));
        file = CreateFileW(snapshot, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        assert(file != INVALID_HANDLE_VALUE && GetFileSize(file, NULL) == 4113);
        assert(ReadFile(file, header, sizeof(header), &amount, NULL) && amount == sizeof(header));
        assert(memcmp(header, "ISACRD01", 8) == 0);
        assert(header[8] == 0 && header[9] == 0x30 && header[12] == 1 && header[13] == 0x10);
        CloseHandle(file);
        snprintf(snapshot_ascii, sizeof(snapshot_ascii), "%s.fault", argv[1]);
        assert(MultiByteToWideChar(CP_ACP, 0, snapshot_ascii, -1, snapshot, MAX_PATH));
        assert(VirtualProtect(g_game_base + 0x6000, 4096, PAGE_NOACCESS, &protect));
        assert(!write_startup_static_section(snapshot, 0x6000, 8));
        assert(VirtualProtect(g_game_base + 0x6000, 4096, protect, &amount));
    }
    g_tctd_echo_enabled = FALSE;
    g_tctd_echo_requested = FALSE;
    assert(!transport_redirect_tctd_pc_ascii("tctd-pc-echo.ubisoft.com", "51000"));
    g_tctd_echo_requested = TRUE;
    assert(transport_redirect_tctd_pc_ascii("TCTD-PC-ECHO.UBISOFT.COM", "51000"));
    assert(transport_redirect_tctd_pc_wide(L"tctd-pc-echo.ubisoft.com", L"51000"));
    assert(!transport_redirect_tctd_pc_ascii("tctd-pc-echo.ubisoft.com", "443"));
    assert(!transport_redirect_tctd_pc_ascii("unrelated.example", "51000"));
    assert(!transport_redirect_tctd_pc_ascii(NULL, "51000"));
    g_tctd_echo_requested = FALSE;
    for (i = 0; i < 4; ++i)
        memcpy(g_game_base + allocation_sites[i], allocation_signatures[i], 8);
    /* Signature failures must leave the capture file untouched. */
    g_game_base[allocation_sites[0]] ^= 1;
    assert(!initialize_allocation_capture());
    g_game_base[allocation_sites[0]] ^= 1;
    assert(initialize_allocation_capture());
    g_tctd_allocation_enabled = TRUE;
    g_getpeername = test_peer;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + allocation_sites[0]);
    ctx.Dr6 = 1;
    ctx.Rcx = (DWORD64)(uintptr_t)transport;
    ctx.Rdx = (DWORD64)(uintptr_t)payload;
    ctx.R8 = length;
    test_port = 443;
    assert(handle_allocation_breakpoint(&ctx));
    assert(allocation_sequence == 0);
    test_port = 27015;
    ctx.Dr6 = 1;
    SetLastError(1234);
    assert(handle_allocation_breakpoint(&ctx));
    assert(GetLastError() == 1234 && (ctx.EFlags & 0x10000));
    assert(allocation_sequence == 1);
    ctx.R8 = 65537;
    ctx.Dr6 = 1;
    assert(handle_allocation_breakpoint(&ctx));
    assert(allocation_sequence == 1);
    ctx.Rsp = (DWORD64)(uintptr_t)stack;
    ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + allocation_sites[1]);
    ctx.Dr6 = 2;
    assert(handle_allocation_breakpoint(&ctx));
    memcpy(stack + 0x468, &pointer, sizeof(pointer));
    memcpy(stack + 0x470, &length, sizeof(length));
    ctx.Rax = 1;
    ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + allocation_sites[2]);
    ctx.Dr6 = 4;
    assert(handle_allocation_breakpoint(&ctx));
    ctx.Rdx = (DWORD64)(uintptr_t)(stack + 0x60);
    ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + allocation_sites[3]);
    ctx.Dr6 = 8;
    assert(handle_allocation_breakpoint(&ctx));
    assert(allocation_sequence == 4);
    /* No uninitialized output is captured after parser failure. */
    ctx.Rax = 0;
    ctx.Rip = (DWORD64)(uintptr_t)(g_game_base + allocation_sites[2]);
    ctx.Dr6 = 4;
    assert(handle_allocation_breakpoint(&ctx));
    assert(allocation_sequence == 5);
    /* The verifier handler can apply repeatedly and preserves successes. */
    memcpy(verifier + 0x140, &mode, sizeof(mode));
    ctx.Rbp = (DWORD64)(uintptr_t)verifier;
    for (i = 0; i < 2; ++i) {
        ctx.Rax = 0;
        g_tctd_local_accept_armed = 1;
        apply_tctd_local_acceptance(&ctx);
        assert(ctx.Rax == 1 && g_tctd_local_accept_armed == 0);
    }
    assert(g_tctd_local_accept_applied == 2);
    ctx.Rax = 7;
    apply_tctd_local_acceptance(&ctx);
    assert(ctx.Rax == 7);
    VirtualFree(g_game_base, 0, MEM_RELEASE);
    puts("Allocation capture and repeated acceptance assertions passed.");
    return 0;
}
