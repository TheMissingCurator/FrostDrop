#include <windows.h>
#include "../src/uplay_probe/sdk_http_native_service.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static MEMORY_BASIC_INFORMATION memory;
static int query_ok = 1, cas_calls;
size_t VirtualQuery(const void *p, MEMORY_BASIC_INFORMATION *info, size_t size) {
    (void)p; assert(size == sizeof(*info));
    if (!query_ok) return 0;
    *info = memory; return size;
}
PVOID InterlockedCompareExchangePointer(PVOID volatile *slot, PVOID desired, PVOID expected) {
    PVOID previous = *slot; ++cas_calls;
    if (previous == expected) *slot = desired;
    return previous;
}
int main(void) {
    int old_object, new_object, unrelated;
    void *slot = &old_object;
    const uintptr_t address = (uintptr_t)&slot;
    MEMORY_BASIC_INFORMATION valid = {&slot, sizeof(slot), MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE};
    memory = valid;
    assert(isac_sdk_http_replace_private_pointer(NULL, address, &old_object, &new_object));
    assert(slot == &new_object && cas_calls == 1);
    assert(!isac_sdk_http_replace_private_pointer(NULL, address, &old_object, &unrelated));
    assert(slot == &new_object && cas_calls == 2);
    slot = &old_object;
    query_ok = 0; assert(!isac_sdk_http_replace_private_pointer(NULL, address, slot, &new_object)); query_ok = 1;
    memory.Type = 0x1000000u; /* MEM_IMAGE */
    assert(!isac_sdk_http_replace_private_pointer(NULL, address, slot, &new_object)); memory = valid;
    memory.State = 0x2000u; /* MEM_RESERVE */
    assert(!isac_sdk_http_replace_private_pointer(NULL, address, slot, &new_object)); memory = valid;
    {
        const unsigned int forbidden[] = {1, 2, 8, 0x40, 0x104};
        size_t i;
        for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
            memory.Protect = forbidden[i];
            assert(!isac_sdk_http_replace_private_pointer(NULL, address, slot, &new_object));
        }
        memory = valid;
    }
    memory.RegionSize = sizeof(slot) - 1;
    assert(!isac_sdk_http_replace_private_pointer(NULL, address, slot, &new_object)); memory = valid;
    memory.BaseAddress = (void *)(address + sizeof(slot));
    assert(!isac_sdk_http_replace_private_pointer(NULL, address, slot, &new_object)); memory = valid;
    assert(!isac_sdk_http_replace_private_pointer(NULL, 0, slot, &new_object));
    assert(!isac_sdk_http_replace_private_pointer(NULL, address + 1, slot, &new_object));
    assert(!isac_sdk_http_replace_private_pointer(NULL, UINTPTR_MAX - 7, slot, &new_object));
    assert(!isac_sdk_http_replace_private_pointer(NULL, address, NULL, &new_object));
    assert(!isac_sdk_http_replace_private_pointer(NULL, address, slot, NULL));
    assert(cas_calls == 2 && slot == &old_object);
    puts("private writable slot: permission, bounds and compare/exchange tests passed");
    return 0;
}
