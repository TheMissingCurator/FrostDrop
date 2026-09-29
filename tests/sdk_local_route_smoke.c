#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static int query_mode, protect_calls, fail_protect_call;
static DWORD first_protect;
static SIZE_T test_query(LPCVOID address, PMEMORY_BASIC_INFORMATION memory, SIZE_T size) {
    SIZE_T count;
    if (query_mode == 1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    count = VirtualQuery(address, memory, size);
    if (count == sizeof(*memory)) {
        if (query_mode == 2) memory->State = MEM_RESERVE;
        if (query_mode == 3) memory->RegionSize = 1;
        if (query_mode == 4) memory->Protect = PAGE_EXECUTE;
        if (query_mode == 5) memory->Type = 0;
    }
    return count;
}
static BOOL test_protect(LPVOID address, SIZE_T size, DWORD protect, PDWORD old) {
    if (protect_calls == 0) first_protect = protect;
    if (++protect_calls == fail_protect_call) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return VirtualProtect(address, size, protect, old);
}
#define VirtualQuery test_query
#define VirtualProtect test_protect
#include "../src/uplay_probe/sdk_local_route.h"
#undef VirtualQuery
#undef VirtualProtect

static ISAC_SDK_DIAGNOSTIC result;
static char phases[8][32];
static int phase_count;
static void observer(const char *phase, BYTE *target, SIZE_T length, DWORD requested, DWORD error) {
    assert(target && length == sizeof(isac_sdk_original) && requested);
    assert(phase_count < 8);
    snprintf(phases[phase_count++], 32, "%s", phase);
    if (strcmp(phase, "write-failed") == 0) assert(error == ERROR_ACCESS_DENIED);
    /* Logging/querying may change last-error; the helper must keep the real failure. */
    SetLastError(ERROR_BUSY);
}
static void fails_at(BYTE *base, SIZE_T size, SIZE_T rva, const char *stage) {
    /* An unrelated last-error must not leak into semantic failures. */
    SetLastError(ERROR_BAD_COMMAND);
    assert(!isac_sdk_patch_template(base, size, rva, &result, NULL));
    assert(strcmp(result.stage, stage) == 0);
}

static void test_readonly_mapping(void) {
    WCHAR temp_dir[MAX_PATH], temp_file[MAX_PATH];
    HANDLE file, mapping;
    BYTE contents[4096], checked[4096], *view, *other;
    MEMORY_BASIC_INFORMATION memory;
    DWORD count, old, ordinary_error;
    assert(GetTempPathW(MAX_PATH, temp_dir));
    assert(GetTempFileNameW(temp_dir, L"sdk", 0, temp_file));
    memset(contents, 0xaa, sizeof(contents));
    memcpy(contents + 32, isac_sdk_original, sizeof(isac_sdk_original));
    file = CreateFileW(temp_file, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    assert(WriteFile(file, contents, sizeof(contents), &count, NULL) && count == sizeof(contents));
    assert(CloseHandle(file));
    file = CreateFileW(temp_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    assert(file != INVALID_HANDLE_VALUE);
    mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    assert(mapping);
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    other = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    assert(view && other);
    assert(VirtualQuery(view, &memory, sizeof(memory)) == sizeof(memory));
    assert(memory.Type == MEM_MAPPED && memory.Protect == PAGE_READONLY);
    /* Actual API rejection, not an injected failure. */
    assert(!VirtualProtect(view + 32, sizeof(isac_sdk_original), PAGE_READWRITE, &old));
    ordinary_error = GetLastError();
    assert(ordinary_error != 0);
    protect_calls = 0;
    fail_protect_call = 1;
    fails_at(view, sizeof(contents), 32, "protect-write");
    assert(result.win32_error == ERROR_ACCESS_DENIED && !result.modified);
    assert(first_protect == PAGE_WRITECOPY && protect_calls == 1);
    assert(memcmp(view, contents, sizeof(contents)) == 0);
    protect_calls = 0;
    fail_protect_call = 0;
    assert(isac_sdk_patch_template(view, sizeof(contents), 32, &result, NULL));
    assert(first_protect == PAGE_WRITECOPY && result.write_protection == PAGE_WRITECOPY);
    assert(result.memory_type == MEM_MAPPED && result.modified);
    assert(strcmp((char *)view + 32, isac_sdk_local) == 0);
    assert(view[31] == 0xaa && view[32 + sizeof(isac_sdk_original)] == 0xaa);
    for (SIZE_T i = sizeof(isac_sdk_local); i < sizeof(isac_sdk_original); ++i) assert(view[32 + i] == 0);
    assert(VirtualQuery(view, &memory, sizeof(memory)) == sizeof(memory));
    assert(memory.Protect == PAGE_READONLY);
    assert(memcmp(other, contents, sizeof(contents)) == 0);
    assert(ReadFile(file, checked, sizeof(checked), &count, NULL) && count == sizeof(checked));
    assert(memcmp(checked, contents, sizeof(contents)) == 0);
    assert(UnmapViewOfFile(view) && UnmapViewOfFile(other));
    assert(CloseHandle(mapping) && CloseHandle(file));
    assert(DeleteFileW(temp_file));
    printf("Read-only mapped view: READWRITE rejected (error %lu), WRITECOPY succeeded; file/second view unchanged.\n",
           (unsigned long)ordinary_error);
}

/* A distinct, padded constant prevents merging with the expected literal. */
static const BYTE image_template[128] = "https://{env}public-ubiservices.ubi.com/{version}";
static void test_image_mapping(void) {
    BYTE *target = (BYTE *)(ULONG_PTR)image_template;
    MEMORY_BASIC_INFORMATION memory;
    char checked[sizeof(isac_sdk_local)];
    SIZE_T count;
    assert(VirtualQuery(target, &memory, sizeof(memory)) == sizeof(memory));
    assert(memory.Type == MEM_IMAGE && memory.Protect == PAGE_READONLY);
    protect_calls = 0;
    assert(isac_sdk_patch_template(target, sizeof(image_template), 0, &result, NULL));
    assert(first_protect == PAGE_WRITECOPY && result.memory_type == MEM_IMAGE);
    /* Read through the OS: the compiler may fold direct reads of a C const
     * object to its initializer despite the deliberate protection change.
     */
    assert(ReadProcessMemory(GetCurrentProcess(), target, checked, sizeof(checked), &count));
    assert(count == sizeof(checked) && strcmp(checked, isac_sdk_local) == 0);
    assert(VirtualQuery(target, &memory, sizeof(memory)) == sizeof(memory));
    assert(memory.Protect == PAGE_READONLY);
    puts("Executable image constant: WRITECOPY succeeded and read-only protection restored.");
}

int main(void) {
    BYTE *page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    MEMORY_BASIC_INFORMATION memory;
    DWORD old;
    assert(page);
    memset(page, 0xaa, 4096);
    memcpy(page + 32, isac_sdk_original, sizeof(isac_sdk_original));
    fails_at(NULL, 4096, 32, "image-base");
    assert(result.win32_error == 0);
    fails_at(page, 4096, 4097, "image-bounds");
    fails_at(page, 4096, 4090, "image-bounds");
    fails_at(page, 4096, 33, "template-mismatch");
    assert(result.mismatch_offset == 0 && !result.all_zero && !result.already_local);
    assert(result.win32_error == 0 && !result.modified);
    query_mode = 1;
    fails_at(page, 4096, 32, "memory-query");
    assert(result.win32_error == ERROR_INVALID_PARAMETER);
    query_mode = 2;
    fails_at(page, 4096, 32, "memory-state");
    assert(result.state == MEM_RESERVE && result.win32_error == 0);
    query_mode = 3;
    fails_at(page, 4096, 32, "region-bounds");
    query_mode = 4;
    fails_at(page, 4096, 32, "memory-readable");
    query_mode = 0;
    query_mode = 5;
    fails_at(page, 4096, 32, "memory-type");
    assert(!result.modified && result.win32_error == 0);
    query_mode = 0;
    assert(VirtualProtect(page, 4096, PAGE_NOACCESS, &old));
    fails_at(page, 4096, 32, "memory-readable");
    assert(result.protection == PAGE_NOACCESS && result.win32_error == 0);
    assert(VirtualProtect(page, 4096, PAGE_READWRITE | PAGE_GUARD, &old));
    fails_at(page, 4096, 32, "memory-readable");
    assert(result.protection & PAGE_GUARD);
    assert(VirtualProtect(page, 4096, PAGE_READONLY, &old));
    protect_calls = 0;
    fail_protect_call = 1;
    fails_at(page, 4096, 32, "protect-write");
    assert(result.win32_error == ERROR_ACCESS_DENIED && !result.modified);
    assert(result.memory_type == MEM_PRIVATE && first_protect == PAGE_READWRITE && protect_calls == 1);
    assert(memcmp(page + 32, isac_sdk_original, sizeof(isac_sdk_original)) == 0);
    protect_calls = 0;
    assert(!isac_sdk_patch_template(page, 4096, 32, &result, observer));
    assert(result.win32_error == ERROR_ACCESS_DENIED && !result.modified);
    assert(phase_count == 2 && strcmp(phases[0], "begin") == 0 && strcmp(phases[1], "write-failed") == 0);
    fail_protect_call = 0;
    phase_count = 0;
    assert(isac_sdk_patch_template(page, 4096, 32, &result, observer));
    assert(phase_count == 3 && strcmp(phases[1], "write-succeeded") == 0 && strcmp(phases[2], "restored") == 0);
    assert(strcmp(result.stage, "ready") == 0 && result.modified && result.win32_error == 0);
    assert(strcmp((char *)page + 32, isac_sdk_local) == 0);
    assert(page[31] == 0xaa && page[32 + sizeof(isac_sdk_original)] == 0xaa);
    for (size_t i = sizeof(isac_sdk_local); i < sizeof(isac_sdk_original); ++i) assert(page[32 + i] == 0);
    assert(VirtualQuery(page, &memory, sizeof(memory)) == sizeof(memory));
    assert(memory.Protect == PAGE_READONLY);
    fails_at(page, 4096, 32, "template-mismatch");
    assert(result.already_local && !result.all_zero && !result.modified);
    assert(VirtualProtect(page, 4096, PAGE_READWRITE, &old));
    memset(page + 32, 0, sizeof(isac_sdk_original));
    fails_at(page, 4096, 32, "template-mismatch");
    assert(result.all_zero && !result.already_local && result.mismatch_offset == 0);
    memcpy(page + 32, isac_sdk_original, sizeof(isac_sdk_original));
    page[32 + sizeof(isac_sdk_original) - 1] = 'X';
    fails_at(page, 4096, 32, "template-mismatch");
    assert(result.mismatch_offset == sizeof(isac_sdk_original) - 1);
    memcpy(page + 32, isac_sdk_original, sizeof(isac_sdk_original));
    assert(VirtualProtect(page, 4096, PAGE_READONLY, &old));
    protect_calls = 0;
    fail_protect_call = 2;
    fails_at(page, 4096, 32, "protect-restore");
    assert(result.win32_error == ERROR_ACCESS_DENIED && result.modified);
    assert(strcmp((char *)page + 32, isac_sdk_local) == 0);
    assert(VirtualFree(page, 0, MEM_RELEASE));
    test_readonly_mapping();
    test_image_mapping();
    puts("SDK local route per-stage diagnostics and bounds/signature/protection assertions passed.");
    return 0;
}
