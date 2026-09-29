/* Minimal fixture declarations for sdk_http_install_win32.c only. */
#ifndef ISAC_TEST_WINDOWS_H
#define ISAC_TEST_WINDOWS_H
#include <stddef.h>
#include <stdint.h>
typedef void *PVOID;
typedef struct {
    void *BaseAddress;
    size_t RegionSize;
    uint32_t State, Protect, Type;
} MEMORY_BASIC_INFORMATION;
#define MEM_COMMIT 0x1000u
#define MEM_PRIVATE 0x20000u
#define PAGE_READWRITE 4u
size_t VirtualQuery(const void *, MEMORY_BASIC_INFORMATION *, size_t);
PVOID InterlockedCompareExchangePointer(PVOID volatile *, PVOID, PVOID);
#endif
