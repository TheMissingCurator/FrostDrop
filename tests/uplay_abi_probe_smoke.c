#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

int main(int argc, char **argv) {
    HMODULE module;
    union {
        FARPROC generic;
        uintptr_t (WINAPI *function)(
            uintptr_t *,
            uintptr_t,
            uintptr_t,
            uintptr_t
        );
    } owned;
    uintptr_t output = 0u;
    uintptr_t result;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s PATH_TO_PROBE_DLL\n", argv[0]);
        return 2;
    }
    module = LoadLibraryA(argv[1]);
    if (module == NULL) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    owned.generic = GetProcAddress(module, "UPLAY_USER_IsOwned");
    if (owned.function == NULL) {
        FreeLibrary(module);
        return 1;
    }
    result = owned.function(&output, 0xabcdefu, 7u, 7u);
    FreeLibrary(module);
    if (result != 0x1234u || output != 0xabcdefu) {
        fprintf(
            stderr,
            "ABI forwarding mismatch: result=%llx output=%llx\n",
            (unsigned long long)result,
            (unsigned long long)output
        );
        return 1;
    }
    puts("uplay ABI probe smoke test passed");
    return 0;
}
