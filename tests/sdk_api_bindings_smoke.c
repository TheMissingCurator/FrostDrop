#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "../src/uplay_probe/sdk_api_bindings.h"
#include "../src/uplay_probe/sdk_api_code.h"

static void synthetic_image(BYTE *image) {
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_IMPORT_DESCRIPTOR *descriptor;
    uintptr_t target = 0x12345678;
    ULONGLONG name = 0x800;
    memset(image, 0, 0x4000);
    dos = (IMAGE_DOS_HEADER *)image;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x100;
    nt = (IMAGE_NT_HEADERS64 *)(image + 0x100);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(nt->OptionalHeader);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = 0x4000;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x400;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 2 * sizeof(*descriptor);
    descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(image + 0x400);
    descriptor->Name = 0x500;
    descriptor->OriginalFirstThunk = 0x600;
    descriptor->FirstThunk = 0x700;
    memcpy(image + 0x500, "kernelbase.dll", sizeof("kernelbase.dll"));
    memcpy(image + 0x600, &name, sizeof(name));
    memcpy(image + 0x700, &target, sizeof(target));
    memcpy(image + 0x802, "VirtualProtect", sizeof("VirtualProtect"));
}

int main(void) {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll"), kb = GetModuleHandleW(L"kernelbase.dll");
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    ISAC_API_BINDING result, forward;
    ISAC_API_CODE code, changed;
    BYTE *image = VirtualAlloc(NULL, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    BYTE before[0x4000];
    BYTE thunk[24] = {0xff, 0x25};
    int32_t displacement = 2;
    uintptr_t destination = 0xdeadbeef;
    DWORD old;
    assert(image && k32 && kb && nt);
    result = isac_binding_slot((uintptr_t)&__imp_VirtualProtect);
    assert(strcmp(result.status, "ok") == 0);
    assert(result.destination == (uintptr_t)GetProcAddress(k32, "VirtualProtect"));
    result = isac_binding_import(k32, "kernelbase.dll", "VirtualProtect");
    assert(strcmp(result.status, "ok") == 0);
    assert(result.destination == (uintptr_t)GetProcAddress(kb, "VirtualProtect"));
    forward = isac_binding_forward((uintptr_t)GetProcAddress(k32, "VirtualProtect"));
    if (strcmp(forward.status, "ok") == 0) {
        assert(forward.slot == result.slot && forward.destination == result.destination);
    } else {
        /* GetProcAddress need not expose the exact on-disk FF25 thunk shape.
         * Keep this unsupported shape as metadata, not a test failure/hook. */
        assert(strcmp(forward.status, "entry-not-rip-indirect") == 0);
    }
    result = isac_binding_import(kb, "ntdll.dll", "NtProtectVirtualMemory");
    assert(strcmp(result.status, "ok") == 0);
    assert(result.destination == (uintptr_t)GetProcAddress(nt, "NtProtectVirtualMemory"));
    code = isac_api_code_sample(kb, (uintptr_t)GetProcAddress(kb, "VirtualProtect"), 176);
    assert(strcmp(code.status, "ok") == 0 && code.length == 176 && code.image_size);
    changed = isac_api_code_sample(kb, code.entry, 176);
    assert(memcmp(code.bytes, changed.bytes, 176) == 0);
    assert(strcmp(isac_api_code_sample(k32, code.entry, 24).status, "entry-owner-mismatch") == 0);
    assert(strcmp(isac_api_code_sample(kb, code.entry, 177).status, "invalid-window") == 0);
    assert(strcmp(isac_api_code_sample(kb, code.entry, 0).status, "invalid-window") == 0);
    code = isac_api_code_sample(k32, (uintptr_t)GetProcAddress(k32, "VirtualProtect"), 24);
    assert(strcmp(code.status, "ok") == 0 && code.length == 24);
    code = isac_api_code_sample(nt, (uintptr_t)GetProcAddress(nt, "NtProtectVirtualMemory"), 32);
    assert(strcmp(code.status, "ok") == 0 && isac_api_wine_stub(&code));
    changed = code;
    changed.bytes[8] ^= 1;
    assert(!isac_api_wine_stub(&changed));
    puts("Named API entry windows and exact Wine dispatch-stub recognition passed without code changes.");
    puts("Live Proton API import destinations match exported references.");
    printf("Kernel32 exported entry shape: %s, rva=0x%llx, direct-alias=%d.\n", forward.status,
           (unsigned long long)((uintptr_t)GetProcAddress(k32, "VirtualProtect") - (uintptr_t)k32),
           (int)(GetProcAddress(k32, "VirtualProtect") == GetProcAddress(kb, "VirtualProtect")));

    synthetic_image(image);
    memcpy(before, image, sizeof(before));
    result = isac_binding_import((HMODULE)image, "KERNELBASE.DLL", "VirtualProtect");
    assert(strcmp(result.status, "ok") == 0 && result.slot == (uintptr_t)(image + 0x700));
    assert(result.destination == 0x12345678);
    assert(memcmp(before, image, sizeof(before)) == 0);
    assert(strcmp(isac_binding_import((HMODULE)image, "missing.dll", "VirtualProtect").status, "import-not-found") == 0);
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "Missing").status, "import-not-found") == 0);
    ((IMAGE_IMPORT_DESCRIPTOR *)(image + 0x400))->OriginalFirstThunk = 0;
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "missing-original-thunk") == 0);
    synthetic_image(image);
    *(ULONGLONG *)(image + 0x600) = IMAGE_ORDINAL_FLAG64 | 1;
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "import-not-found") == 0);
    synthetic_image(image);
    *(ULONGLONG *)(image + 0x600) = 0x5000;
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "invalid-thunk") == 0);
    synthetic_image(image);
    ((IMAGE_IMPORT_DESCRIPTOR *)(image + 0x400))->FirstThunk = 0x3fff;
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "invalid-thunk") == 0);
    synthetic_image(image);
    ((IMAGE_NT_HEADERS64 *)(image + 0x100))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0xffff;
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "invalid-import-directory") == 0);
    synthetic_image(image);
    ((IMAGE_NT_HEADERS64 *)(image + 0x100))->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "invalid-header") == 0);
    synthetic_image(image);
    ((IMAGE_DOS_HEADER *)image)->e_lfanew = 0x200000;
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "unreadable-header") == 0);
    assert(strcmp(isac_binding_slot(0).status, "unreadable-slot") == 0);
    assert(!isac_binding_read(UINTPTR_MAX - 1, before, 8));
    assert(VirtualProtect(image, 0x4000, PAGE_NOACCESS, &old));
    assert(strcmp(isac_binding_import((HMODULE)image, "kernelbase.dll", "VirtualProtect").status, "unreadable-header") == 0);
    assert(VirtualProtect(image, 0x4000, PAGE_READWRITE | PAGE_GUARD, &old));
    assert(strcmp(isac_binding_slot((uintptr_t)image).status, "unreadable-slot") == 0);
    assert(VirtualProtect(image, 0x4000, PAGE_READWRITE, &old));
    memcpy(thunk + 2, &displacement, sizeof(displacement));
    memcpy(thunk + 8, &destination, sizeof(destination));
    forward = isac_binding_forward((uintptr_t)thunk);
    assert(strcmp(forward.status, "ok") == 0 && forward.slot == (uintptr_t)(thunk + 8));
    assert(forward.destination == destination);
    thunk[0] = 0xe9;
    assert(strcmp(isac_binding_forward((uintptr_t)thunk).status, "entry-not-rip-indirect") == 0);
    memcpy(thunk, "\x48\x8d\xa4\x24\x00\x00\x00\x00\xff\x25", 10);
    memcpy(thunk + 10, &displacement, sizeof(displacement));
    memcpy(thunk + 16, &destination, sizeof(destination));
    forward = isac_binding_forward((uintptr_t)thunk);
    assert(strcmp(forward.status, "ok") == 0 && forward.slot == (uintptr_t)(thunk + 16));
    assert(forward.destination == destination);
    thunk[3] = 0x25; /* Not the exact known no-op: no permissive pattern search. */
    assert(strcmp(isac_binding_forward((uintptr_t)thunk).status, "entry-not-rip-indirect") == 0);
    assert(VirtualFree(image, 0, MEM_RELEASE));
    puts("Binding readers: bounds, malformed imports, ordinal/missing names, redacted thunk metadata and no mutations passed.");
    return 0;
}
