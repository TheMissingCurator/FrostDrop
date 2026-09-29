#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "sdk_http_native_service.h"

int isac_sdk_http_replace_private_pointer(void *unused, uintptr_t slot,
    void *expected, void *replacement) {
    MEMORY_BASIC_INFORMATION info;
    uintptr_t base;
    (void)unused;
    if (!slot || slot % sizeof(void *) || !expected || !replacement ||
        sizeof(void *) > UINTPTR_MAX - slot ||
        VirtualQuery((const void *)slot, &info, sizeof(info)) != sizeof(info)) return 0;
    base = (uintptr_t)info.BaseAddress;
    /* Deliberately no VirtualProtect, code writes or image-backed pages. The
     * publication barrier must keep allocation/protection stable across CAS. */
    if (info.State != MEM_COMMIT || info.Type != MEM_PRIVATE || info.Protect != PAGE_READWRITE ||
        slot < base || slot - base > info.RegionSize ||
        sizeof(void *) > info.RegionSize - (slot - base)) return 0;
    return InterlockedCompareExchangePointer((PVOID volatile *)slot, replacement, expected) == expected;
}
