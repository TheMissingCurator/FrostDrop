#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

uintptr_t WINAPI isac_fake_owned(
    uintptr_t *output,
    uintptr_t value,
    uintptr_t third,
    uintptr_t fourth
) {
    if (output != NULL) {
        *output = value;
    }
    return (third ^ fourth) == 0u ? 0x1234u : 0x5678u;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
