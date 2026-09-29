#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

typedef uintptr_t (WINAPI *generic_function)(
    uintptr_t,
    uintptr_t,
    uintptr_t,
    uintptr_t
);

int main(int argc, char **argv) {
    HMODULE module;
    union {
        FARPROC generic;
        generic_function function;
    } start;
    WSADATA winsock_data;
    ADDRINFOA hints;
    PADDRINFOA addresses = NULL;
    struct sockaddr_in endpoint;
    SOCKET socket_handle;
    int result;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s PATH_TO_LOCAL_DLL\n", argv[0]);
        return 2;
    }
    module = LoadLibraryA(argv[1]);
    if (module == NULL) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    start.generic = GetProcAddress(module, "UPLAY_Start");
    if (start.generic == NULL) {
        fprintf(stderr, "UPLAY_Start is missing.\n");
        FreeLibrary(module);
        return 1;
    }
    if (start.function(0x72bu, 0u, 0u, 0u) != 0u) {
        fprintf(stderr, "UPLAY_Start did not report success.\n");
        FreeLibrary(module);
        return 1;
    }
    if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        FreeLibrary(module);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    result = getaddrinfo("localhost", "55000", &hints, &addresses);
    if (result != 0) {
        fprintf(stderr, "getaddrinfo smoke call failed: %d\n", result);
        WSACleanup();
        FreeLibrary(module);
        return 1;
    }
    freeaddrinfo(addresses);
    addresses = NULL;

    result = getaddrinfo(
        "tctd-pc.ubisoft.com",
        "27015",
        &hints,
        &addresses
    );
    if (
        result != 0 ||
        addresses == NULL ||
        addresses->ai_family != AF_INET ||
        ((const struct sockaddr_in *)addresses->ai_addr)->sin_addr.s_addr !=
            htonl(INADDR_LOOPBACK) ||
        ((const struct sockaddr_in *)addresses->ai_addr)->sin_port !=
            htons(27015u)
    ) {
        fprintf(stderr, "tctd-pc loopback rewrite failed: %d\n", result);
        if (addresses != NULL) {
            freeaddrinfo(addresses);
        }
        WSACleanup();
        FreeLibrary(module);
        return 1;
    }
    freeaddrinfo(addresses);

    addresses = NULL;
    result = getaddrinfo("TCTD-PC-ECHO.UBISOFT.COM", "51000", &hints, &addresses);
    if (result || !addresses || addresses->ai_family != AF_INET ||
        ((const struct sockaddr_in *)addresses->ai_addr)->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        ((const struct sockaddr_in *)addresses->ai_addr)->sin_port != htons(51000)) {
        fprintf(stderr, "echo ANSI loopback rewrite failed: %d\n", result);
        return 1;
    }
    freeaddrinfo(addresses);
    {
        ADDRINFOW wide_hints;
        PADDRINFOW wide_addresses = NULL;
        ZeroMemory(&wide_hints, sizeof(wide_hints));
        wide_hints.ai_family = AF_INET;
        wide_hints.ai_socktype = SOCK_STREAM;
        result = GetAddrInfoW(L"tctd-pc-echo.ubisoft.com", L"51000", &wide_hints, &wide_addresses);
        if (result || !wide_addresses ||
            ((const struct sockaddr_in *)wide_addresses->ai_addr)->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
            ((const struct sockaddr_in *)wide_addresses->ai_addr)->sin_port != htons(51000)) {
            fprintf(stderr, "echo wide loopback rewrite failed: %d\n", result);
            return 1;
        }
        FreeAddrInfoW(wide_addresses);
    }

    socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
        fprintf(stderr, "socket smoke call failed.\n");
        WSACleanup();
        FreeLibrary(module);
        return 1;
    }
    ZeroMemory(&endpoint, sizeof(endpoint));
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(1u);
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)connect(
        socket_handle,
        (const struct sockaddr *)&endpoint,
        (int)sizeof(endpoint)
    );
    closesocket(socket_handle);

    WSACleanup();
    FreeLibrary(module);
    puts("transport startup probe smoke test passed");
    return 0;
}
