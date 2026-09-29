#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "stack_probe.h"

#define ISAC_EXPORT_COUNT 89u
#define ISAC_LOG_FILENAME L"project-isac-uplay-probe.log"
#define ISAC_STACK_LOG_FILENAME L"project-isac-stack-probe.log"
#define ISAC_CODE_LOG_FILENAME L"project-isac-code-probe.log"
#define ISAC_DISPATCH_LOG_FILENAME L"project-isac-dispatch-probe.log"
#define ISAC_PLAINTEXT_LOG_FILENAME L"project-isac-plaintext-probe.log"
#define ISAC_ABI_LOG_FILENAME L"project-isac-uplay-abi-probe.log"
#define ISAC_ORIGINAL_FILENAME L"uplay_r1_loader64_isac_original.dll"
#define ISAC_ABI_SAMPLES_PER_FUNCTION 16u
#define ISAC_ABI_MAX_DEPTH 8u
#define ISAC_ABI_ARGUMENTS 8u
#define ISAC_ABI_STRING_LIMIT 4096u
#define ISAC_ABI_MAX_CALLER_WINDOWS 128u
#define ISAC_ABI_CALLER_PREFIX 512u
#define ISAC_ABI_CALLER_FALLBACK_PREFIX 256u
#define ISAC_ABI_CALLER_SUFFIX 64u
#define ISAC_ABI_CALLER_WINDOW_MAX \
    (ISAC_ABI_CALLER_PREFIX + ISAC_ABI_CALLER_SUFFIX)

static HMODULE g_self;
static HMODULE g_original;
static INIT_ONCE g_initialize_once = INIT_ONCE_STATIC_INIT;
static SRWLOCK g_log_lock = SRWLOCK_INIT;
static SRWLOCK g_abi_caller_lock = SRWLOCK_INIT;
static FARPROC g_targets[ISAC_EXPORT_COUNT];
static volatile LONG g_seen[ISAC_EXPORT_COUNT];
static volatile LONG g_abi_samples[ISAC_EXPORT_COUNT];
static volatile LONG g_abi_depth_error_logged;
static WCHAR g_log_path[MAX_PATH];
static WCHAR g_abi_log_path[MAX_PATH];
static BOOL g_abi_enabled;
static DWORD g_abi_tls_index = TLS_OUT_OF_INDEXES;

typedef struct isac_abi_caller_key {
    unsigned int index;
    uintptr_t return_rva;
} isac_abi_caller_key;

static isac_abi_caller_key
    g_abi_caller_keys[ISAC_ABI_MAX_CALLER_WINDOWS];
static unsigned int g_abi_caller_key_count;

static const char *const g_export_names[ISAC_EXPORT_COUNT] = {
#include "export_names.inc"
};

typedef struct isac_abi_frame {
    PVOID original_return;
    unsigned int index;
    LONG sample;
    uintptr_t arguments[ISAC_ABI_ARGUMENTS];
    BYTE argument_valid[ISAC_ABI_ARGUMENTS];
    uintptr_t first_words[ISAC_ABI_ARGUMENTS];
    BYTE first_word_valid[ISAC_ABI_ARGUMENTS];
} isac_abi_frame;

typedef struct isac_abi_thread_state {
    unsigned int depth;
    isac_abi_frame frames[ISAC_ABI_MAX_DEPTH];
} isac_abi_thread_state;

static BOOL replace_filename(
    const WCHAR *path,
    const WCHAR *filename,
    WCHAR output[MAX_PATH]
) {
    DWORD length = lstrlenW(path);
    DWORD filename_length = lstrlenW(filename);
    DWORD directory_length = length;

    while (directory_length > 0) {
        WCHAR character = path[directory_length - 1];
        if (character == L'\\' || character == L'/') {
            break;
        }
        --directory_length;
    }

    if (directory_length + filename_length + 1 > MAX_PATH) {
        return FALSE;
    }

    CopyMemory(output, path, directory_length * sizeof(WCHAR));
    CopyMemory(
        output + directory_length,
        filename,
        (filename_length + 1) * sizeof(WCHAR)
    );
    return TRUE;
}

static BOOL environment_enabled(const WCHAR *name) {
    WCHAR value[2];
    DWORD length = GetEnvironmentVariableW(name, value, 2u);

    return length == 1u && value[0] == L'1';
}

static BOOL readable_pointer(uintptr_t value, BOOL *writable) {
    MEMORY_BASIC_INFORMATION memory;
    DWORD protection;

    *writable = FALSE;
    if (
        value < 0x10000u ||
        VirtualQuery((const void *)value, &memory, sizeof(memory)) !=
            sizeof(memory) ||
        memory.State != MEM_COMMIT ||
        (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0u
    ) {
        return FALSE;
    }
    protection = memory.Protect & 0xffu;
    *writable =
        protection == PAGE_READWRITE ||
        protection == PAGE_WRITECOPY ||
        protection == PAGE_EXECUTE_READWRITE ||
        protection == PAGE_EXECUTE_WRITECOPY;
    return
        protection == PAGE_READONLY ||
        protection == PAGE_READWRITE ||
        protection == PAGE_WRITECOPY ||
        protection == PAGE_EXECUTE_READ ||
        protection == PAGE_EXECUTE_READWRITE ||
        protection == PAGE_EXECUTE_WRITECOPY;
}

static BOOL read_process_word(uintptr_t address, uintptr_t *value) {
    SIZE_T copied = 0u;

    return ReadProcessMemory(
            GetCurrentProcess(),
            (const void *)address,
            value,
            sizeof(*value),
            &copied
        ) && copied == sizeof(*value);
}

static BOOL bounded_utf8_length(uintptr_t address, DWORD *length) {
    BYTE bytes[256];
    DWORD total = 0u;

    if (address < 0x10000u) {
        return FALSE;
    }
    while (total < ISAC_ABI_STRING_LIMIT) {
        SIZE_T copied = 0u;
        DWORD request = ISAC_ABI_STRING_LIMIT - total;
        DWORD index;

        if (request > sizeof(bytes)) {
            request = sizeof(bytes);
        }
        if (!ReadProcessMemory(
                GetCurrentProcess(),
                (const void *)(address + total),
                bytes,
                request,
                &copied
            ) || copied == 0u) {
            return FALSE;
        }
        for (index = 0u; index < (DWORD)copied; ++index) {
            BYTE value = bytes[index];

            if (value == 0u) {
                *length = total + index;
                return TRUE;
            }
            if (value < 0x20u && value != '\t') {
                return FALSE;
            }
        }
        total += (DWORD)copied;
        if ((DWORD)copied != request) {
            return FALSE;
        }
    }
    return FALSE;
}

static void describe_abi_value(
    char *output,
    size_t capacity,
    uintptr_t value,
    BOOL include_scalar_value
) {
    BOOL writable;
    DWORD string_length;

    if (value == 0u) {
        snprintf(output, capacity, "null");
    } else if (readable_pointer(value, &writable)) {
        if (bounded_utf8_length(value, &string_length)) {
            snprintf(
                output,
                capacity,
                "%s-utf8:length=%lu",
                writable ? "writable" : "readable",
                (unsigned long)string_length
            );
        } else {
            snprintf(
                output,
                capacity,
                "%s-pointer",
                writable ? "writable" : "readable"
            );
        }
    } else if (
        value <= 0xffffffffu ||
        (value & ~(uintptr_t)0xffffffffu) ==
            ~(uintptr_t)0xffffffffu
    ) {
        if (include_scalar_value || value <= 0xffffu) {
            snprintf(
                output,
                capacity,
                "scalar32:0x%08lx",
                (unsigned long)(value & 0xffffffffu)
            );
        } else {
            snprintf(output, capacity, "scalar32:redacted");
        }
    } else {
        snprintf(output, capacity, "opaque-nonpointer");
    }
}

static BOOL main_image_rva(PVOID address, uintptr_t *rva) {
    const BYTE *base = (const BYTE *)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    const BYTE *value = (const BYTE *)address;

    if (base == NULL || address == NULL) {
        return FALSE;
    }
    dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return FALSE;
    }
    nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    if (value < base || value >= base + nt->OptionalHeader.SizeOfImage) {
        return FALSE;
    }
    *rva = (uintptr_t)(value - base);
    return TRUE;
}

static void append_abi_line(const char *line) {
    HANDLE file;
    DWORD written;
    DWORD length;

    if (!g_abi_enabled || g_abi_log_path[0] == L'\0' || line == NULL) {
        return;
    }
    length = (DWORD)strlen(line);
    AcquireSRWLockExclusive(&g_log_lock);
    file = CreateFileW(
        g_abi_log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file != INVALID_HANDLE_VALUE) {
        WriteFile(file, line, length, &written, NULL);
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&g_log_lock);
}

static void append_log_line(const char *event, const char *name) {
    char line[320];
    int line_length;
    HANDLE file;
    DWORD written;

    if (g_log_path[0] == L'\0') {
        return;
    }

    line_length = snprintf(
        line,
        sizeof(line),
        "%s tick_ms=%llu process=%lu thread=%lu function=%s\r\n",
        event,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        name != NULL ? name : "-"
    );
    if (line_length <= 0) {
        return;
    }
    if ((size_t)line_length >= sizeof(line)) {
        line_length = (int)sizeof(line) - 1;
    }

    AcquireSRWLockExclusive(&g_log_lock);
    file = CreateFileW(
        g_log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file != INVALID_HANDLE_VALUE) {
        WriteFile(file, line, (DWORD)line_length, &written, NULL);
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&g_log_lock);
}

static BOOL reserve_abi_caller_window(
    unsigned int index,
    uintptr_t return_rva
) {
    unsigned int entry;
    BOOL reserved = FALSE;

    AcquireSRWLockExclusive(&g_abi_caller_lock);
    for (entry = 0u; entry < g_abi_caller_key_count; ++entry) {
        if (
            g_abi_caller_keys[entry].index == index &&
            g_abi_caller_keys[entry].return_rva == return_rva
        ) {
            ReleaseSRWLockExclusive(&g_abi_caller_lock);
            return FALSE;
        }
    }
    if (g_abi_caller_key_count < ISAC_ABI_MAX_CALLER_WINDOWS) {
        g_abi_caller_keys[g_abi_caller_key_count].index = index;
        g_abi_caller_keys[g_abi_caller_key_count].return_rva = return_rva;
        ++g_abi_caller_key_count;
        reserved = TRUE;
    }
    ReleaseSRWLockExclusive(&g_abi_caller_lock);
    return reserved;
}

/*
 * Capture bounded executable bytes around each unique main-image return site.
 * The unwind entry supplies a real instruction boundary whenever the caller is
 * short enough; large functions fall back to a bounded prefix before the
 * return site. Only normalized RVAs and executable bytes are recorded.
 */
static void capture_abi_caller_window(
    unsigned int index,
    PVOID original_return,
    uintptr_t return_rva
) {
    const BYTE *main_base = (const BYTE *)GetModuleHandleW(NULL);
    DWORD64 unwind_image_base = 0u;
    PRUNTIME_FUNCTION runtime_function;
    uintptr_t function_start_rva = 0u;
    uintptr_t start_rva;
    uintptr_t end_rva;
    BOOL exact_start = FALSE;
    BYTE bytes[ISAC_ABI_CALLER_WINDOW_MAX];
    SIZE_T copied = 0u;
    char line[1600];
    size_t offset;
    SIZE_T byte;

    if (
        main_base == NULL ||
        !reserve_abi_caller_window(index, return_rva)
    ) {
        return;
    }
    runtime_function = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)original_return,
        &unwind_image_base,
        NULL
    );
    if (
        runtime_function != NULL &&
        unwind_image_base == (DWORD64)(uintptr_t)main_base &&
        runtime_function->BeginAddress <= return_rva &&
        return_rva < runtime_function->EndAddress
    ) {
        function_start_rva = runtime_function->BeginAddress;
        if (return_rva - function_start_rva <= ISAC_ABI_CALLER_PREFIX) {
            start_rva = function_start_rva;
            exact_start = TRUE;
        } else {
            start_rva = return_rva - ISAC_ABI_CALLER_FALLBACK_PREFIX;
        }
        end_rva = return_rva + ISAC_ABI_CALLER_SUFFIX;
        if (end_rva > runtime_function->EndAddress) {
            end_rva = runtime_function->EndAddress;
        }
    } else {
        start_rva = return_rva > ISAC_ABI_CALLER_FALLBACK_PREFIX
            ? return_rva - ISAC_ABI_CALLER_FALLBACK_PREFIX
            : 0u;
        end_rva = return_rva + ISAC_ABI_CALLER_SUFFIX;
    }
    if (
        end_rva <= start_rva ||
        end_rva - start_rva > sizeof(bytes) ||
        !ReadProcessMemory(
            GetCurrentProcess(),
            main_base + start_rva,
            bytes,
            end_rva - start_rva,
            &copied
        ) ||
        copied != end_rva - start_rva
    ) {
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "UPLAY_ABI_CODE tick_ms=%llu process=%lu thread=%lu function=%s "
        "return_rva=0x%llx function_start_rva=0x%llx start_rva=0x%llx "
        "exact_start=%s length=%lu bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        g_export_names[index],
        (unsigned long long)return_rva,
        (unsigned long long)function_start_rva,
        (unsigned long long)start_rva,
        exact_start ? "yes" : "no",
        (unsigned long)copied
    );
    for (byte = 0u; byte < copied && offset + 2u < sizeof(line); ++byte) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            bytes[byte]
        );

        if (written != 2) {
            return;
        }
        offset += 2u;
    }
    if (byte != copied || offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_abi_line(line);
}

static BOOL abi_target(unsigned int index) {
    switch (index) {
        case 2u:   /* UPLAY_ACH_GetAchievements */
        case 6u:   /* UPLAY_AVATAR_Get */
        case 7u:   /* UPLAY_AVATAR_Release */
        case 10u:  /* UPLAY_FRIENDS_GetFriendList */
        case 11u:  /* UPLAY_FRIENDS_Init */
        case 20u:  /* UPLAY_GetLastError */
        case 21u:  /* UPLAY_GetNextEvent */
        case 22u:  /* UPLAY_GetOverlappedOperationResult */
        case 23u:  /* UPLAY_HasOverlappedOperationCompleted */
        case 28u:  /* UPLAY_INSTALLER_Init */
        case 41u:  /* UPLAY_PARTY_Init */
        case 44u:  /* UPLAY_PARTY_IsInParty */
        case 50u:  /* UPLAY_PRESENCE_SetPresence */
        case 52u:  /* UPLAY_Quit */
        case 62u:  /* UPLAY_Start */
        case 65u:  /* UPLAY_USER_GetAccountIdUtf8 */
        case 73u:  /* UPLAY_USER_GetNameUtf8 */
        case 74u:  /* UPLAY_USER_GetTicketUtf8 */
        case 75u:  /* UPLAY_USER_IsConnected */
        case 76u:  /* UPLAY_USER_IsInOfflineMode */
        case 77u:  /* UPLAY_USER_IsOwned */
        case 80u:  /* UPLAY_USER_SetGameSession */
        case 81u:  /* UPLAY_Update */
        case 83u:  /* UPLAY_WIN_GetRewards */
        case 85u:  /* UPLAY_WIN_RefreshActions */
            return TRUE;
        default:
            return FALSE;
    }
}

static isac_abi_thread_state *abi_thread_state(void) {
    isac_abi_thread_state *state;

    if (g_abi_tls_index == TLS_OUT_OF_INDEXES) {
        return NULL;
    }
    state = (isac_abi_thread_state *)TlsGetValue(g_abi_tls_index);
    if (state != NULL) {
        return state;
    }
    state = (isac_abi_thread_state *)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(*state)
    );
    if (state == NULL || !TlsSetValue(g_abi_tls_index, state)) {
        if (state != NULL) {
            HeapFree(GetProcessHeap(), 0u, state);
        }
        return NULL;
    }
    return state;
}

/*
 * The assembly thunk passes register arguments as a four-word array and the
 * unmodified entry stack. Only value shapes, output mutation flags, and
 * string lengths are recorded; pointed-to bytes and raw pointer values are
 * never written to disk.
 */
BOOL isac_abi_enter(
    unsigned int index,
    PVOID original_return,
    const uintptr_t *register_arguments,
    const BYTE *original_stack
) {
    isac_abi_thread_state *state;
    isac_abi_frame *frame;
    LONG sample;
    uintptr_t caller_rva;
    BOOL caller_in_main;
    unsigned int argument;
    char line[1536];
    size_t offset;

    if (
        !g_abi_enabled ||
        index >= ISAC_EXPORT_COUNT ||
        !abi_target(index) ||
        register_arguments == NULL ||
        original_stack == NULL
    ) {
        return FALSE;
    }
    sample = InterlockedIncrement(&g_abi_samples[index]);
    if (sample > (LONG)ISAC_ABI_SAMPLES_PER_FUNCTION) {
        return FALSE;
    }
    state = abi_thread_state();
    if (state == NULL || state->depth >= ISAC_ABI_MAX_DEPTH) {
        if (
            InterlockedCompareExchange(&g_abi_depth_error_logged, 1, 0) == 0
        ) {
            append_abi_line(
                "UPLAY_ABI_ERROR reason=tls-allocation-or-depth\r\n"
            );
        }
        return FALSE;
    }
    frame = &state->frames[state->depth++];
    ZeroMemory(frame, sizeof(*frame));
    frame->original_return = original_return;
    frame->index = index;
    frame->sample = sample;
    for (argument = 0u; argument < 4u; ++argument) {
        frame->arguments[argument] = register_arguments[argument];
        frame->argument_valid[argument] = 1u;
    }
    for (argument = 4u; argument < ISAC_ABI_ARGUMENTS; ++argument) {
        uintptr_t value;
        uintptr_t address = (uintptr_t)original_stack + 40u +
            (argument - 4u) * sizeof(uintptr_t);

        if (read_process_word(address, &value)) {
            frame->arguments[argument] = value;
            frame->argument_valid[argument] = 1u;
        }
    }
    for (argument = 0u; argument < ISAC_ABI_ARGUMENTS; ++argument) {
        BOOL writable;

        if (
            frame->argument_valid[argument] &&
            readable_pointer(frame->arguments[argument], &writable) &&
            read_process_word(
                frame->arguments[argument],
                &frame->first_words[argument]
            )
        ) {
            frame->first_word_valid[argument] = 1u;
        }
    }

    caller_in_main = main_image_rva(original_return, &caller_rva);
    if (caller_in_main) {
        capture_abi_caller_window(index, original_return, caller_rva);
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "UPLAY_ABI_CALL tick_ms=%llu process=%lu thread=%lu function=%s "
        "sample=%ld caller=%s",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        g_export_names[index],
        sample,
        caller_in_main ? "main-image" : "other-image"
    );
    if (caller_in_main && offset < sizeof(line)) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            ":0x%llx",
            (unsigned long long)caller_rva
        );
        if (written > 0 && (size_t)written < sizeof(line) - offset) {
            offset += (size_t)written;
        }
    }
    for (
        argument = 0u;
        argument < ISAC_ABI_ARGUMENTS && offset < sizeof(line);
        ++argument
    ) {
        char description[96];
        int written;

        if (frame->argument_valid[argument]) {
            describe_abi_value(
                description,
                sizeof(description),
                frame->arguments[argument],
                FALSE
            );
        } else {
            snprintf(description, sizeof(description), "unreadable");
        }
        written = snprintf(
            line + offset,
            sizeof(line) - offset,
            " arg%u=%s",
            argument,
            description
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            offset = sizeof(line);
            break;
        }
        offset += (size_t)written;
    }
    if (offset + 2u < sizeof(line)) {
        line[offset++] = '\r';
        line[offset++] = '\n';
        line[offset] = '\0';
        append_abi_line(line);
    }
    return TRUE;
}

PVOID isac_abi_leave(
    uintptr_t return_rax,
    uintptr_t return_rdx,
    uint64_t return_xmm0
) {
    isac_abi_thread_state *state = abi_thread_state();
    isac_abi_frame *frame;
    PVOID original_return;
    char rax_description[96];
    char rdx_description[96];
    char line[1536];
    size_t offset;
    unsigned int argument;

    if (state == NULL || state->depth == 0u) {
        append_abi_line("UPLAY_ABI_ERROR reason=return-without-entry\r\n");
        return NULL;
    }
    frame = &state->frames[--state->depth];
    original_return = frame->original_return;
    describe_abi_value(
        rax_description,
        sizeof(rax_description),
        return_rax,
        TRUE
    );
    describe_abi_value(
        rdx_description,
        sizeof(rdx_description),
        return_rdx,
        FALSE
    );
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "UPLAY_ABI_RETURN tick_ms=%llu process=%lu thread=%lu function=%s "
        "sample=%ld rax=%s rdx=%s xmm0_nonzero=%s",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        g_export_names[frame->index],
        frame->sample,
        rax_description,
        rdx_description,
        return_xmm0 != 0u ? "yes" : "no"
    );
    for (
        argument = 0u;
        argument < ISAC_ABI_ARGUMENTS && offset < sizeof(line);
        ++argument
    ) {
        uintptr_t after_word;
        BOOL after_valid;
        DWORD direct_length;
        DWORD nested_length;
        BOOL direct_string;
        BOOL nested_string = FALSE;
        int written;

        if (!frame->first_word_valid[argument]) {
            continue;
        }
        after_valid = read_process_word(
            frame->arguments[argument],
            &after_word
        );
        direct_string = bounded_utf8_length(
            frame->arguments[argument],
            &direct_length
        );
        if (after_valid) {
            nested_string = bounded_utf8_length(after_word, &nested_length);
        }
        if (direct_string) {
            written = snprintf(
                line + offset,
                sizeof(line) - offset,
                " arg%u_word_changed=%s,direct_utf8_length=%lu",
                argument,
                after_valid && after_word != frame->first_words[argument]
                    ? "yes"
                    : "no",
                (unsigned long)direct_length
            );
        } else {
            written = snprintf(
                line + offset,
                sizeof(line) - offset,
                " arg%u_word_changed=%s",
                argument,
                after_valid && after_word != frame->first_words[argument]
                    ? "yes"
                    : "no"
            );
        }
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            offset = sizeof(line);
            break;
        }
        offset += (size_t)written;
        if (nested_string && offset < sizeof(line)) {
            written = snprintf(
                line + offset,
                sizeof(line) - offset,
                ",nested_utf8_length=%lu",
                (unsigned long)nested_length
            );
            if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
                offset = sizeof(line);
                break;
            }
            offset += (size_t)written;
        }
    }
    if (offset + 2u < sizeof(line)) {
        line[offset++] = '\r';
        line[offset++] = '\n';
        line[offset] = '\0';
        append_abi_line(line);
    }
    ZeroMemory(frame, sizeof(*frame));
    return original_return;
}

static BOOL CALLBACK initialize_probe(
    PINIT_ONCE once,
    PVOID parameter,
    PVOID *context
) {
    WCHAR self_path[MAX_PATH];
    WCHAR original_path[MAX_PATH];
    WCHAR stack_log_path[MAX_PATH];
    WCHAR code_log_path[MAX_PATH];
    WCHAR dispatch_log_path[MAX_PATH];
    WCHAR plaintext_log_path[MAX_PATH];
    DWORD length;
    unsigned int index;

    (void)once;
    (void)parameter;
    (void)context;

    length = GetModuleFileNameW(g_self, self_path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return TRUE;
    }

    if (!replace_filename(self_path, ISAC_LOG_FILENAME, g_log_path)) {
        g_log_path[0] = L'\0';
    }
    g_abi_enabled = environment_enabled(L"ISAC_UPLAY_ABI_PROBE");
#ifdef ISAC_RETAIL_ONLY
    /* Retail startup baseline observes export names only, not return values,
     * arguments, caller code, tickets or any optional legacy instrumentation. */
    g_abi_enabled = FALSE;
#endif
    if (g_abi_enabled) {
        if (!replace_filename(
                self_path,
                ISAC_ABI_LOG_FILENAME,
                g_abi_log_path
            )) {
            g_abi_log_path[0] = L'\0';
            g_abi_enabled = FALSE;
        } else {
            g_abi_tls_index = TlsAlloc();
            if (g_abi_tls_index == TLS_OUT_OF_INDEXES) {
                append_abi_line(
                    "UPLAY_ABI_ERROR reason=tls-index-allocation\r\n"
                );
                g_abi_enabled = FALSE;
            } else {
                append_abi_line(
                    "UPLAY_ABI_READY max-samples-per-function=16 "
                    "max-caller-windows=128 caller-code=bounded "
                    "arguments=shape-only pointed-bytes=disabled "
                    "raw-pointers=disabled strings=length-only\r\n"
                );
            }
        }
    }
    if (
        replace_filename(
            self_path,
            ISAC_STACK_LOG_FILENAME,
            stack_log_path
        ) &&
        replace_filename(
            self_path,
            ISAC_CODE_LOG_FILENAME,
            code_log_path
        ) &&
        replace_filename(
            self_path,
            ISAC_DISPATCH_LOG_FILENAME,
            dispatch_log_path
        ) &&
        replace_filename(
            self_path,
            ISAC_PLAINTEXT_LOG_FILENAME,
            plaintext_log_path
        )
    ) {
        isac_stack_probe_initialize(
            stack_log_path,
            code_log_path,
            dispatch_log_path,
            plaintext_log_path
        );
    }
    if (!replace_filename(
            self_path,
            ISAC_ORIGINAL_FILENAME,
            original_path
        )) {
        append_log_line("PROBE_PATH_ERROR", NULL);
        return TRUE;
    }

    g_original = LoadLibraryW(original_path);
    if (g_original == NULL) {
        append_log_line("ORIGINAL_LOAD_FAILED", NULL);
        return TRUE;
    }

    for (index = 0; index < ISAC_EXPORT_COUNT; ++index) {
        g_targets[index] = GetProcAddress(g_original, g_export_names[index]);
        if (g_targets[index] == NULL) {
            append_log_line("ORIGINAL_EXPORT_MISSING", g_export_names[index]);
        }
    }

    append_log_line("PROBE_READY", NULL);
#ifdef ISAC_RETAIL_ONLY
    append_log_line("RETAIL_FORWARD_ONLY service-name-observer=opt-in-type5", NULL);
#endif
    return TRUE;
}

/*
 * Called by the assembly thunks. The thunks preserve all Windows x64 integer
 * and floating-point argument registers, so no knowledge of Ubisoft's
 * function signatures is required. Only the function index is observed.
 */
FARPROC isac_resolve_and_log(unsigned int index) {
    InitOnceExecuteOnce(&g_initialize_once, initialize_probe, NULL, NULL);

    if (index >= ISAC_EXPORT_COUNT) {
        return NULL;
    }

    if (InterlockedCompareExchange(&g_seen[index], 1, 0) == 0) {
        append_log_line("FIRST_CALL", g_export_names[index]);
    }
    return g_targets[index];
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = instance;
        DisableThreadLibraryCalls(instance);
    } else if (reason == DLL_PROCESS_DETACH && reserved == NULL) {
        if (g_abi_tls_index != TLS_OUT_OF_INDEXES) {
            isac_abi_thread_state *state =
                (isac_abi_thread_state *)TlsGetValue(g_abi_tls_index);

            if (state != NULL) {
                HeapFree(GetProcessHeap(), 0u, state);
            }
            TlsFree(g_abi_tls_index);
            g_abi_tls_index = TLS_OUT_OF_INDEXES;
        }
        isac_stack_probe_shutdown();
    }
    return TRUE;
}
