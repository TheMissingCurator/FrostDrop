#ifndef ISAC_SDK_API_BINDINGS_H
#define ISAC_SDK_API_BINDINGS_H

/* Read-only x64 import/thunk metadata. Never call a discovered destination,
 * change an IAT slot, dump code bytes, or retry a protection operation. */
typedef struct {
    const char *status;
    uintptr_t slot;
    uintptr_t destination;
} ISAC_API_BINDING;

/* This is the exact MinGW import symbol used by the compiled SDK call. */
extern BOOL (WINAPI *__imp_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

static BOOL isac_binding_read(uintptr_t address, void *output, SIZE_T length) {
    uintptr_t cursor = address;
    SIZE_T left = length;
    unsigned int regions = 0;
    if (!address || length > UINTPTR_MAX - address) return FALSE;
    while (left && regions++ < 8) {
        MEMORY_BASIC_INFORMATION memory;
        uintptr_t end;
        SIZE_T part;
        DWORD protection;
        if (VirtualQuery((void *)cursor, &memory, sizeof(memory)) != sizeof(memory)) return FALSE;
        protection = memory.Protect & 0xffu;
        if (memory.State != MEM_COMMIT || (memory.Protect & PAGE_GUARD) ||
            (protection != PAGE_READONLY && protection != PAGE_READWRITE &&
             protection != PAGE_WRITECOPY && protection != PAGE_EXECUTE_READ &&
             protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)) return FALSE;
        if (memory.RegionSize > UINTPTR_MAX - (uintptr_t)memory.BaseAddress) return FALSE;
        end = (uintptr_t)memory.BaseAddress + memory.RegionSize;
        if (cursor < (uintptr_t)memory.BaseAddress || cursor >= end) return FALSE;
        part = left < end - cursor ? left : end - cursor;
        cursor += part;
        left -= part;
    }
    if (left) return FALSE;
    memcpy(output, (const void *)address, length);
    return TRUE;
}

static BOOL isac_binding_image_read(uintptr_t base, SIZE_T size, SIZE_T rva,
                                    void *output, SIZE_T length) {
    return rva <= size && length <= size - rva && rva <= UINTPTR_MAX - base &&
        isac_binding_read(base + rva, output, length);
}

static BOOL isac_binding_name(uintptr_t base, SIZE_T size, SIZE_T rva,
                              const char *expected, BOOL ignore_case) {
    char name[64];
    SIZE_T length = strlen(expected) + 1;
    if (length > sizeof(name) || !isac_binding_image_read(base, size, rva, name, length)) return FALSE;
    if (name[length - 1] != 0) return FALSE;
    return ignore_case ? lstrcmpiA(name, expected) == 0 : strcmp(name, expected) == 0;
}

static ISAC_API_BINDING isac_binding_slot(uintptr_t slot) {
    ISAC_API_BINDING result = {"unreadable-slot", slot, 0};
    if (isac_binding_read(slot, &result.destination, sizeof(result.destination)))
        result.status = result.destination ? "ok" : "null-destination";
    return result;
}

static ISAC_API_BINDING isac_binding_import(HMODULE module, const char *dll, const char *symbol) {
    uintptr_t base = (uintptr_t)module;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY directory;
    ISAC_API_BINDING result = {"unreadable-header", 0, 0};
    SIZE_T size;
    unsigned int index;
    if (!isac_binding_read(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < (LONG)sizeof(dos) || dos.e_lfanew > 0x100000 ||
        (uintptr_t)dos.e_lfanew > UINTPTR_MAX - base ||
        !isac_binding_read(base + dos.e_lfanew, &nt, sizeof(nt))) return result;
    result.status = "invalid-header";
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(nt.OptionalHeader) ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return result;
    size = nt.OptionalHeader.SizeOfImage;
    if (size < sizeof(nt) || (SIZE_T)dos.e_lfanew > size - sizeof(nt) || size > UINTPTR_MAX - base) return result;
    directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    result.status = "import-not-found";
    if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) return result;
    result.status = "invalid-import-directory";
    if (directory.VirtualAddress > size || directory.Size > size - directory.VirtualAddress) return result;
    for (index = 0; index < 256 && index < directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); ++index) {
        IMAGE_IMPORT_DESCRIPTOR descriptor;
        unsigned int thunk;
        SIZE_T descriptor_rva = directory.VirtualAddress + index * sizeof(descriptor);
        if (!isac_binding_image_read(base, size, descriptor_rva, &descriptor, sizeof(descriptor))) return result;
        if (!descriptor.Name) break;
        if (!isac_binding_name(base, size, descriptor.Name, dll, TRUE)) continue;
        result.status = "missing-original-thunk";
        if (!descriptor.OriginalFirstThunk || !descriptor.FirstThunk) return result;
        result.status = "invalid-thunk";
        for (thunk = 0; thunk < 8192; ++thunk) {
            ULONGLONG entry;
            SIZE_T name_rva = (SIZE_T)descriptor.OriginalFirstThunk + thunk * sizeof(entry);
            SIZE_T slot_rva = (SIZE_T)descriptor.FirstThunk + thunk * sizeof(entry);
            if (!isac_binding_image_read(base, size, name_rva, &entry, sizeof(entry))) return result;
            if (!entry) break;
            if (entry & IMAGE_ORDINAL_FLAG64) continue;
            if (entry > size || sizeof(WORD) > size - entry) return result;
            if (!isac_binding_name(base, size, (SIZE_T)entry + sizeof(WORD), symbol, FALSE)) continue;
            if (slot_rva > size || sizeof(uintptr_t) > size - slot_rva) return result;
            return isac_binding_slot(base + slot_rva);
        }
        result.status = thunk == 8192 ? "thunk-limit" : "import-not-found";
        return result;
    }
    result.status = index == 256 ? "descriptor-limit" : "import-not-found";
    return result;
}

/* Decode FF 25 disp32, optionally after the exact 8-byte hotpatch no-op in
 * the installed Proton kernel32 export. No arbitrary NOP skipping or scan. */
static ISAC_API_BINDING isac_binding_forward(uintptr_t entry) {
    static const BYTE hotpatch[8] = {0x48, 0x8d, 0xa4, 0x24, 0, 0, 0, 0};
    BYTE bytes[14];
    SIZE_T offset = 0;
    int32_t displacement;
    uintptr_t next, slot;
    ISAC_API_BINDING result = {"unreadable-entry", 0, 0};
    if (!isac_binding_read(entry, bytes, 6)) return result;
    result.status = "entry-not-rip-indirect";
    if (bytes[0] != 0xff || bytes[1] != 0x25) {
        if (!isac_binding_read(entry, bytes, sizeof(bytes))) return result;
        if (memcmp(bytes, hotpatch, sizeof(hotpatch)) != 0 || bytes[8] != 0xff || bytes[9] != 0x25) return result;
        offset = sizeof(hotpatch);
    }
    memcpy(&displacement, bytes + offset + 2, sizeof(displacement));
    next = entry + offset + 6;
    result.status = "invalid-forward-slot";
    if (displacement < 0) {
        uintptr_t distance = (uintptr_t)(-(int64_t)displacement);
        if (distance > next) return result;
        slot = next - distance;
    } else {
        if ((uintptr_t)displacement > UINTPTR_MAX - next) return result;
        slot = next + displacement;
    }
    return isac_binding_slot(slot);
}

#endif
