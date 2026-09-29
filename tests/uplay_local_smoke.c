#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ISAC_EXPORT_COUNT 89u

static const char *const g_export_names[ISAC_EXPORT_COUNT] = {
#include "export_names.inc"
};

typedef uintptr_t (WINAPI *generic_function)(
    uintptr_t,
    uintptr_t,
    uintptr_t,
    uintptr_t
);

static generic_function get_function(HMODULE module, const char *name) {
    union {
        FARPROC generic;
        generic_function function;
    } value;

    value.generic = GetProcAddress(module, name);
    return value.function;
}

int main(int argc, char **argv) {
    HMODULE module;
    unsigned int index;
    generic_function function;
    const char *text;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s PATH_TO_LOCAL_DLL\n", argv[0]);
        return 2;
    }
    module = LoadLibraryA(argv[1]);
    if (module == NULL) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    for (index = 0u; index < ISAC_EXPORT_COUNT; ++index) {
        if (
            GetProcAddress(module, g_export_names[index]) == NULL ||
            GetProcAddress(module, g_export_names[index]) !=
                GetProcAddress(module, MAKEINTRESOURCEA(index + 1u))
        ) {
            fprintf(stderr, "Export mismatch: %s\n", g_export_names[index]);
            FreeLibrary(module);
            return 1;
        }
    }

    function = get_function(module, "UPLAY_Start");
    if (function(0x72bu, 0u, 0u, 0u) != 0u) {
        fprintf(stderr, "UPLAY_Start did not report success.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_USER_GetAccountIdUtf8");
    text = (const char *)function(0u, 0u, 0u, 0u);
    if (text == NULL || strlen(text) != 36u) {
        fprintf(stderr, "Invalid local account ID.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_USER_GetNameUtf8");
    text = (const char *)function(0u, 0u, 0u, 0u);
    if (text == NULL || strcmp(text, "ProjectISAC") != 0) {
        fprintf(stderr, "Invalid local user name.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_USER_GetTicketUtf8");
    text = (const char *)function(0u, 0u, 0u, 0u);
    if (text == NULL || strncmp(text, "project-isac-", 13u) != 0) {
        fprintf(stderr, "Invalid local ticket.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_USER_IsConnected");
    if (function(0u, 0u, 0u, 0u) != 1u) {
        fprintf(stderr, "Local user is not connected.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_USER_IsInOfflineMode");
    if (function(0u, 0u, 0u, 0u) != 0u) {
        fprintf(stderr, "Client-facing offline mode must remain false.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_USER_IsOwned");
    if (function(0x72bu, 0u, 0u, 0u) != 1u) {
        fprintf(stderr, "Local ownership check failed.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_Update");
    if (function(0u, 0u, 0u, 0u) != 1u) {
        fprintf(stderr, "Local update failed.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_USER_SetGameSession");
    if (function(0u, 1u, 2u, 3u) != 1u) {
        fprintf(stderr, "Local game-session marker failed.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_WIN_RefreshActions");
    if (function(0u, 0u, 0u, 0u) != 1u) {
        fprintf(stderr, "Local action refresh failed.\n");
        FreeLibrary(module);
        return 1;
    }
    function = get_function(module, "UPLAY_SAVE_Read");
    if (function(0u, 0u, 0u, 0u) != 0u) {
        fprintf(stderr, "Unsupported feature did not fail closed.\n");
        FreeLibrary(module);
        return 1;
    }

    FreeLibrary(module);
    puts("standalone local Uplay shim smoke test passed");
    return 0;
}
