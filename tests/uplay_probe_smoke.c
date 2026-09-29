#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define ISAC_EXPORT_COUNT 89u

static const char *const g_export_names[ISAC_EXPORT_COUNT] = {
#include "export_names.inc"
};

static HANDLE g_server_ready;
static volatile LONG g_server_result;

static DWORD WINAPI loopback_server(LPVOID parameter) {
    SOCKET listener = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in address;
    char request;
    int reuse = 1;

    (void)parameter;
    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(55000);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        SetEvent(g_server_ready);
        return 1;
    }
    setsockopt(
        listener,
        SOL_SOCKET,
        SO_REUSEADDR,
        (const char *)&reuse,
        sizeof(reuse)
    );
    if (
        bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0
    ) {
        closesocket(listener);
        SetEvent(g_server_ready);
        return 1;
    }
    InterlockedExchange(&g_server_result, 1);
    SetEvent(g_server_ready);

    client = accept(listener, NULL, NULL);
    if (
        client != INVALID_SOCKET &&
        recv(client, &request, 1, 0) == 1 &&
        request == 'Q' &&
        send(client, "A", 1, 0) == 1
    ) {
        InterlockedExchange(&g_server_result, 2);
    }
    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    closesocket(listener);
    return 0;
}

static int exercise_stack_probe(void) {
    union {
        FARPROC generic;
        int (WSAAPI *send_function)(SOCKET, const char *, int, int);
    } dynamic_send;
    union {
        FARPROC generic;
        int (WSAAPI *recv_function)(SOCKET, char *, int, int);
    } dynamic_recv;
    HMODULE ws2_module;
    HANDLE server_thread;
    SOCKET client = INVALID_SOCKET;
    struct sockaddr_in address;
    char response;
    int result = 1;

    g_server_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_server_ready == NULL) {
        return 1;
    }
    server_thread = CreateThread(NULL, 0, loopback_server, NULL, 0, NULL);
    if (server_thread == NULL) {
        CloseHandle(g_server_ready);
        return 1;
    }
    WaitForSingleObject(g_server_ready, 5000);
    if (g_server_result != 1) {
        goto cleanup;
    }

    ws2_module = GetModuleHandleW(L"ws2_32.dll");
    if (ws2_module == NULL) {
        goto cleanup;
    }
    dynamic_send.generic = GetProcAddress(ws2_module, "send");
    dynamic_recv.generic = GetProcAddress(ws2_module, "recv");
    if (
        dynamic_send.send_function == NULL ||
        dynamic_recv.recv_function == NULL
    ) {
        goto cleanup;
    }

    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(55000);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (
        client == INVALID_SOCKET ||
        connect(
            client,
            (const struct sockaddr *)&address,
            sizeof(address)
        ) != 0 ||
        dynamic_send.send_function(client, "Q", 1, 0) != 1 ||
        dynamic_recv.recv_function(client, &response, 1, 0) != 1 ||
        response != 'A'
    ) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (client != INVALID_SOCKET) {
        closesocket(client);
    }
    WaitForSingleObject(server_thread, 5000);
    CloseHandle(server_thread);
    CloseHandle(g_server_ready);
    return result;
}

int main(int argc, char **argv) {
    HMODULE module;
    unsigned int index;
    unsigned int failures = 0;
    FARPROC by_name;
    FARPROC by_ordinal;
    uintptr_t (__cdecl *fallback_test)(void);
    uintptr_t fallback_result;
    WSADATA socket_data;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s PATH_TO_PROBE_DLL\n", argv[0]);
        return 2;
    }

    module = LoadLibraryA(argv[1]);
    if (module == NULL) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }

    for (index = 0; index < ISAC_EXPORT_COUNT; ++index) {
        by_name = GetProcAddress(module, g_export_names[index]);
        by_ordinal = GetProcAddress(module, MAKEINTRESOURCEA(index + 1));
        if (by_name == NULL || by_name != by_ordinal) {
            fprintf(
                stderr,
                "Export mismatch: ordinal=%u name=%s\n",
                index + 1,
                g_export_names[index]
            );
            ++failures;
        }
    }

    if (failures != 0) {
        FreeLibrary(module);
        return 1;
    }

    /*
     * The retail original is intentionally absent in the smoke-test
     * directory. This exercises the thunk, lazy initialization, logging, and
     * safe zero return used when forwarding cannot be established.
     */
    fallback_test = (uintptr_t (__cdecl *)(void))GetProcAddress(
        module,
        "UPLAY_USER_IsOwned"
    );
    fallback_result = fallback_test();
    if (fallback_result != 0) {
        fprintf(stderr, "Expected missing-original fallback to return zero.\n");
        FreeLibrary(module);
        return 1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &socket_data) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        FreeLibrary(module);
        return 1;
    }
    if (exercise_stack_probe() != 0 || g_server_result != 2) {
        fprintf(stderr, "Stack probe loopback exercise failed.\n");
        WSACleanup();
        FreeLibrary(module);
        return 1;
    }
    WSACleanup();

    FreeLibrary(module);
    puts("uplay probe smoke test passed");
    return 0;
}
