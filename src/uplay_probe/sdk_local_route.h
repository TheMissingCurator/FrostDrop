#ifndef ISAC_SDK_LOCAL_ROUTE_H
#define ISAC_SDK_LOCAL_ROUTE_H

/* Exact observed read-only SDK template; never scan or patch instructions.
 * Called once, before returning the first launcher export to the game.
 * Whether SDK descriptors were copied earlier remains a runtime question.
 */
#define ISAC_SDK_TEMPLATE_RVA 0x3471510u
static const char isac_sdk_original[] =
    "https://{env}public-ubiservices.ubi.com/{version}";
static const char isac_sdk_local[] = "http://127.0.0.1:55003/{version}";

/* Metadata only: never log URL contents, memory dumps, paths or credentials.
 * win32_error is captured immediately after a failed API, and is zero for
 * semantic mismatches (where GetLastError would be stale).
 */
typedef struct {
    const char *stage;
    DWORD win32_error;
    DWORD state;
    DWORD protection;
    DWORD memory_type;
    DWORD allocation_protection;
    DWORD write_protection;
    unsigned long long expected;
    unsigned long long observed;
    int mismatch_offset;
    BOOL all_zero;
    BOOL already_local;
    BOOL modified;
} ISAC_SDK_DIAGNOSTIC;

typedef void (*isac_sdk_protect_observer)(const char *phase, BYTE *target,
    SIZE_T length, DWORD requested, DWORD error);

static void isac_sdk_diagnostic_reset(ISAC_SDK_DIAGNOSTIC *result) {
    ZeroMemory(result, sizeof(*result));
    result->stage = "not-started";
    result->mismatch_offset = -1;
}

static BOOL isac_sdk_patch_template(BYTE *base, SIZE_T size, SIZE_T rva,
                                    ISAC_SDK_DIAGNOSTIC *result,
                                    isac_sdk_protect_observer observer) {
    MEMORY_BASIC_INFORMATION memory;
    DWORD old_protect, ignored;
    BYTE *target;
    SIZE_T offset, index;
    isac_sdk_diagnostic_reset(result);
    result->stage = "image-base";
    if (!base) return FALSE;
    result->stage = "image-bounds";
    if (rva > size || sizeof(isac_sdk_original) > size - rva) return FALSE;
    target = base + rva;
    result->stage = "memory-query";
    if (VirtualQuery(target, &memory, sizeof(memory)) != sizeof(memory)) {
        result->win32_error = GetLastError();
        return FALSE;
    }
    result->state = memory.State;
    result->protection = memory.Protect;
    result->memory_type = memory.Type;
    result->allocation_protection = memory.AllocationProtect;
    result->stage = "memory-state";
    if (memory.State != MEM_COMMIT) return FALSE;
    result->stage = "memory-readable";
    if (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;
    switch (memory.Protect & 0xffu) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            break;
        default: return FALSE;
    }
    result->stage = "region-bounds";
    if ((ULONG_PTR)target < (ULONG_PTR)memory.BaseAddress) return FALSE;
    offset = (ULONG_PTR)target - (ULONG_PTR)memory.BaseAddress;
    if (offset > memory.RegionSize || sizeof(isac_sdk_original) > memory.RegionSize - offset) return FALSE;
    result->stage = "template-mismatch";
    if (memcmp(target, isac_sdk_original, sizeof(isac_sdk_original)) != 0) {
        result->all_zero = TRUE;
        for (index = 0; index < sizeof(isac_sdk_original); ++index) {
            if (target[index] != 0) result->all_zero = FALSE;
            if (result->mismatch_offset < 0 && target[index] != (BYTE)isac_sdk_original[index])
                result->mismatch_offset = (int)index;
        }
        result->already_local = memcmp(target, isac_sdk_local, sizeof(isac_sdk_local)) == 0;
        return FALSE;
    }
    /* Mapped read-only views may forbid shared write access but allow a private
     * copy. Never add execute permission or remap an image to force a write.
     * Private VirtualAlloc pages do not accept PAGE_WRITECOPY.
     */
    result->stage = "memory-type";
    if (memory.Type == MEM_IMAGE || memory.Type == MEM_MAPPED)
        result->write_protection = PAGE_WRITECOPY;
    else if (memory.Type == MEM_PRIVATE)
        result->write_protection = PAGE_READWRITE;
    else
        return FALSE;
    result->stage = "protect-write";
    if (observer) observer("begin", target, sizeof(isac_sdk_original), result->write_protection, 0);
    if (!VirtualProtect(target, sizeof(isac_sdk_original), result->write_protection, &old_protect)) {
        result->win32_error = GetLastError();
        if (observer) observer("write-failed", target, sizeof(isac_sdk_original), result->write_protection, result->win32_error);
        return FALSE;
    }
    if (observer) observer("write-succeeded", target, sizeof(isac_sdk_original), result->write_protection, 0);
    ZeroMemory(target, sizeof(isac_sdk_original));
    CopyMemory(target, isac_sdk_local, sizeof(isac_sdk_local));
    result->modified = TRUE;
    result->stage = "protect-restore";
    if (!VirtualProtect(target, sizeof(isac_sdk_original), old_protect, &ignored)) {
        result->win32_error = GetLastError();
        if (observer) observer("restore-failed", target, sizeof(isac_sdk_original), old_protect, result->win32_error);
        return FALSE;
    }
    if (observer) observer("restored", target, sizeof(isac_sdk_original), old_protect, 0);
    result->stage = "ready";
    return TRUE;
}
#endif
