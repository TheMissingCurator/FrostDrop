#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "stack_probe.h"
#ifdef ISAC_SDK_ADAPTER_BUILD
#include "sdk_http_live.h"
#endif

#define ISAC_EXPORT_COUNT 89u
#define ISAC_LOG_FILENAME L"project-isac-uplay-local.log"
#define ISAC_STACK_LOG_FILENAME L"project-isac-stack-probe.log"
#define ISAC_CODE_LOG_FILENAME L"project-isac-code-probe.log"
#define ISAC_DISPATCH_LOG_FILENAME L"project-isac-dispatch-probe.log"
#define ISAC_PLAINTEXT_LOG_FILENAME L"project-isac-plaintext-probe.log"

static HMODULE g_self;
static INIT_ONCE g_initialize_once = INIT_ONCE_STATIC_INIT;
static SRWLOCK g_log_lock = SRWLOCK_INIT;
static volatile LONG g_seen[ISAC_EXPORT_COUNT];
static WCHAR g_log_path[MAX_PATH];

static const char g_account_id[] =
    "49534143-0000-4000-8000-000000000001";
static const char g_user_name[] = "ProjectISAC";
static const char g_ticket[] =
    "project-isac-local-ticket-v1";

static const char *const g_export_names[ISAC_EXPORT_COUNT] = {
#include "export_names.inc"
};

static BOOL replace_filename(
    const WCHAR *path,
    const WCHAR *filename,
    WCHAR output[MAX_PATH]
) {
    DWORD length = lstrlenW(path);
    DWORD filename_length = lstrlenW(filename);
    DWORD directory_length = length;

    while (directory_length > 0u) {
        WCHAR character = path[directory_length - 1u];
        if (character == L'\\' || character == L'/') {
            break;
        }
        --directory_length;
    }
    if (directory_length + filename_length + 1u > MAX_PATH) {
        return FALSE;
    }
    CopyMemory(output, path, directory_length * sizeof(WCHAR));
    CopyMemory(
        output + directory_length,
        filename,
        (filename_length + 1u) * sizeof(WCHAR)
    );
    return TRUE;
}

static void append_log_line(const char *event, const char *name) {
    char line[320];
    int length;
    HANDLE file;
    DWORD written;

    if (g_log_path[0] == L'\0') {
        return;
    }
    length = snprintf(
        line,
        sizeof(line),
        "%s tick_ms=%llu process=%lu thread=%lu function=%s\r\n",
        event,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        name != NULL ? name : "-"
    );
    if (length <= 0) {
        return;
    }
    if ((size_t)length >= sizeof(line)) {
        length = (int)sizeof(line) - 1;
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
        WriteFile(file, line, (DWORD)length, &written, NULL);
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&g_log_lock);
}

static BOOL CALLBACK initialize_local(
    PINIT_ONCE once,
    PVOID parameter,
    PVOID *context
) {
    WCHAR self_path[MAX_PATH];
    WCHAR stack_log_path[MAX_PATH];
    WCHAR code_log_path[MAX_PATH];
    WCHAR dispatch_log_path[MAX_PATH];
    WCHAR plaintext_log_path[MAX_PATH];
    DWORD length;

    (void)once;
    (void)parameter;
    (void)context;
    length = GetModuleFileNameW(g_self, self_path, MAX_PATH);
    if (
        length == 0u ||
        length >= MAX_PATH ||
        !replace_filename(self_path, ISAC_LOG_FILENAME, g_log_path)
    ) {
        g_log_path[0] = L'\0';
        return TRUE;
    }
    append_log_line("LOCAL_SHIM_READY", NULL);
#ifdef ISAC_SDK_ADAPTER_BUILD
    {
        char mode[8];
        if (GetEnvironmentVariableA("ISAC_SDK_ADAPTER", mode, sizeof(mode)) == 1 && mode[0] == '1') {
            isac_sdk_adapter_bootstrap(append_log_line);
            /* No legacy template patch or competing Windows debug-register probes. */
            return TRUE;
        }
        /* Existing modes retain their original behavior when not opted in. */
    }
#endif
    if (
        replace_filename(
            self_path,
            ISAC_STACK_LOG_FILENAME,
            stack_log_path
        ) &&
        replace_filename(self_path, ISAC_CODE_LOG_FILENAME, code_log_path) &&
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
    return TRUE;
}

/*
 * The generated assembly wrappers normalize the first four integer argument
 * slots. The local implementation only consumes arguments for exports whose
 * observed contract requires them; unused volatile-register values are
 * intentionally ignored.
 */
uintptr_t isac_local_dispatch(
    unsigned int index,
    uintptr_t argument0,
    uintptr_t argument1,
    uintptr_t argument2,
    uintptr_t argument3
) {
    (void)argument0;
    (void)argument1;
    (void)argument2;
    (void)argument3;
    InitOnceExecuteOnce(&g_initialize_once, initialize_local, NULL, NULL);
    if (index >= ISAC_EXPORT_COUNT) {
        return 0u;
    }
    if (InterlockedCompareExchange(&g_seen[index], 1, 0) == 0) {
        append_log_line("LOCAL_FIRST_CALL", g_export_names[index]);
    }

    switch (index) {
        case 7u:   /* UPLAY_AVATAR_Release */
        case 11u:  /* UPLAY_FRIENDS_Init */
        case 41u:  /* UPLAY_PARTY_Init */
        case 50u:  /* UPLAY_PRESENCE_SetPresence */
        case 62u:  /* UPLAY_Start: zero is success */
        case 65u:  /* handled below */
        case 73u:  /* handled below */
        case 74u:  /* handled below */
        case 75u:  /* UPLAY_USER_IsConnected */
        case 77u:  /* UPLAY_USER_IsOwned */
        case 80u:  /* UPLAY_USER_SetGameSession */
        case 81u:  /* UPLAY_Update */
        case 85u:  /* UPLAY_WIN_RefreshActions */
            break;
        default:
            return 0u;
    }

    switch (index) {
        case 62u:
            return 0u;
        case 65u:
            return (uintptr_t)g_account_id;
        case 73u:
            return (uintptr_t)g_user_name;
        case 74u:
            return (uintptr_t)g_ticket;
        default:
            return 1u;
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = instance;
        DisableThreadLibraryCalls(instance);
    } else if (reason == DLL_PROCESS_DETACH && reserved == NULL) {
        isac_stack_probe_shutdown();
    }
    return TRUE;
}
