#ifndef ISAC_SDK_API_CODE_H
#define ISAC_SDK_API_CODE_H

/* Small allowlisted Wine API entry windows only. No game code, patching,
 * breakpoint installation, arbitrary branch following or API retries. */
#define ISAC_API_CODE_MAX 176u
typedef struct {
    const char *status;
    uintptr_t entry, allocation, rva;
    DWORD timestamp, image_size;
    SIZE_T length;
    BYTE bytes[ISAC_API_CODE_MAX];
} ISAC_API_CODE;

static ISAC_API_CODE isac_api_code_sample(HMODULE module, uintptr_t entry, SIZE_T length) {
    ISAC_API_CODE result;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    MEMORY_BASIC_INFORMATION memory;
    DWORD protection;
    ZeroMemory(&result, sizeof(result));
    result.status = "invalid-window";
    result.entry = entry;
    if (!module || !entry || !length || length > sizeof(result.bytes)) return result;
    result.status = "entry-owner-mismatch";
    if (VirtualQuery((void *)entry, &memory, sizeof(memory)) != sizeof(memory) ||
        memory.AllocationBase != module || memory.Type != MEM_IMAGE || entry < (uintptr_t)module) return result;
    result.allocation = (uintptr_t)module;
    result.rva = entry - result.allocation;
    result.status = "entry-not-executable";
    protection = memory.Protect & 0xffu;
    if (protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE &&
        protection != PAGE_EXECUTE_WRITECOPY) return result;
    result.status = "invalid-code-image";
    if (!isac_binding_read((uintptr_t)module, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < (LONG)sizeof(dos) || dos.e_lfanew > 0x100000 ||
        (uintptr_t)dos.e_lfanew > UINTPTR_MAX - (uintptr_t)module ||
        !isac_binding_read((uintptr_t)module + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return result;
    result.timestamp = nt.FileHeader.TimeDateStamp;
    result.image_size = nt.OptionalHeader.SizeOfImage;
    if (result.rva > result.image_size || length > result.image_size - result.rva) return result;
    result.status = "unreadable-code";
    if (!isac_binding_read(entry, result.bytes, length)) return result;
    result.length = length;
    result.status = "ok";
    return result;
}

static BOOL isac_api_wine_stub(const ISAC_API_CODE *code) {
    static const BYTE load[] = {0x4c, 0x8b, 0xd1, 0xb8};
    static const BYTE test[] = {0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01};
    return code->length == 32 && strcmp(code->status, "ok") == 0 &&
        memcmp(code->bytes, load, sizeof(load)) == 0 &&
        memcmp(code->bytes + 8, test, sizeof(test)) == 0 &&
        code->bytes[16] == 0x75 && code->bytes[17] == 3 && code->bytes[18] == 0x0f &&
        code->bytes[19] == 0x05 && code->bytes[20] == 0xc3 &&
        code->bytes[21] == 0xeb && code->bytes[22] == 1 && code->bytes[23] == 0xc3 &&
        memcmp(code->bytes + 24, "\xff\x14\x25\x00\x10\xfe\x7f\xc3", 8) == 0;
}

#endif
