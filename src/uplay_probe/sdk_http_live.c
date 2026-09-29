#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>
#include "sdk_http_native_service.h"
#include "sdk_http_live.h"
#include "sdk_http_live_anchors.inc"

#define READY_MAGIC UINT64_C(0x4953414300010001)
#define DONE_MAGIC  UINT64_C(0x4953414300010002)
#define FAIL_MAGIC  UINT64_C(0x4953414300010003)
#define ACK_MAGIC   UINT64_C(0x49534143000100aa)
#define POOL_SIZE 8u
extern void isac_sdk_adapter_entry(void);
uintptr_t isac_sdk_adapter_resume;
static uintptr_t game_base;
static int attested, stopped_install;
static unsigned int used;
static isac_sdk_http_service *pool[POOL_SIZE];
static isac_sdk_http_publication current_event;
static void (*logger)(const char *, const char *);

static uintptr_t rendezvous(uintptr_t magic, uintptr_t pc, uintptr_t entry, uintptr_t base) {
    register uintptr_t r8 __asm__("r8") = base;
    __asm__ volatile ("int3" : "+a"(magic) : "c"(pc), "d"(entry), "r"(r8) : "memory");
    return magic;
}
static _Noreturn void fatal(const char *reason) {
    if (stopped_install) (void)rendezvous(FAIL_MAGIC, 1, 0, 0);
    if (logger) logger("SDK_ADAPTER_ERROR", reason);
    TerminateProcess(GetCurrentProcess(), 0x4954);
    for (;;) Sleep(INFINITE);
}
static int read_memory(void *unused, uintptr_t address, void *output, size_t length) {
    SIZE_T copied = 0; (void)unused;
    if (!address || length > UINTPTR_MAX - address) return 0;
    /* During the held stop these ranges were checked by the debugger. Avoid
     * Wine RPC/heap/VM locks while its other threads/processes are stopped. */
    if (stopped_install) {
        int allowed = (address >= game_base && address - game_base < 0x07311000u &&
            length <= 0x07311000u - (address - game_base));
        uintptr_t original = *(uintptr_t *)(current_event.wrapper + 16);
        const uintptr_t starts[] = {current_event.facade, current_event.wrapper, original};
        const size_t sizes[] = {0x98, 0x18, 0x30};
        size_t i;
        for (i = 0; i < 3; ++i)
            if (address >= starts[i] && address - starts[i] <= sizes[i] &&
                length <= sizes[i] - (address - starts[i])) allowed = 1;
        if (!allowed) return 0;
        memcpy(output, (const void *)address, length); return 1;
    }
    return ReadProcessMemory(GetCurrentProcess(), (const void *)address, output, length, &copied) && copied == length;
}
static int file_hash_ok(void) {
    static const unsigned char expected[32] = {
        0x31,0xc7,0x4a,0xbf,0xed,0xb5,0x2f,0xa2,0xef,0x83,0x42,0xe8,0xf4,0x34,0xd7,0x66,
        0x18,0x4e,0xca,0x32,0xd8,0x5e,0xa9,0x41,0x9b,0xcb,0xb4,0x6c,0x09,0xa6,0xe3,0x79};
    WCHAR path[MAX_PATH]; unsigned char buffer[8192], digest[32];
    BCRYPT_ALG_HANDLE algorithm = NULL; BCRYPT_HASH_HANDLE hash = NULL;
    HANDLE file = INVALID_HANDLE_VALUE; DWORD count, n; int ok = 0;
    n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE || BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0 ||
        BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) < 0) goto done;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &count, NULL)) goto done;
        if (!count) break;
        if (BCryptHashData(hash, buffer, count, 0) < 0) goto done;
    }
    ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0 && !memcmp(digest, expected, sizeof(digest));
done:
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return ok;
}
static void *acquire(void *unused) { (void)unused; return attested ? &attested : NULL; }
static int ready(void *lease) { return lease == &attested && attested; }
static int unused_drain(void *lease, void *original) { (void)lease; (void)original; return 0; }
static void release(void *lease) { if (lease != &attested) fatal("lease-identity"); }
static int admit(void *unused, const isac_sdk_http_publication *event) {
    (void)unused; return stopped_install && !memcmp(event, &current_event, sizeof(*event));
}
static int replace_slot(void *unused, uintptr_t slot, void *expected, void *replacement) {
    (void)unused;
    if (!stopped_install || slot != current_event.wrapper + 16) return 0;
    /* The debugger has checked this exact private RW slot while all other
     * threads are held. No VirtualQuery/RPC or allocation at this stop. */
    return __atomic_compare_exchange_n((void **)slot, &expected, replacement, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

void isac_sdk_adapter_at_publication(uintptr_t facade, uintptr_t owner_slot, uintptr_t wrapper) {
    isac_sdk_http_install_api installer = {admit, replace_slot, NULL};
    isac_sdk_http_service *service;
    current_event = (isac_sdk_http_publication){game_base, game_base + 0x20fa7ffu, facade, owner_slot, wrapper};
    stopped_install = 1;
    if (!attested || used >= POOL_SIZE) fatal("epoch-limit");
    service = pool[used++];
    if (!isac_sdk_http_service_bind(service, *(void **)(wrapper + 16)) ||
        !isac_sdk_http_service_install(service, &installer, &current_event)) fatal("publication-refused");
    stopped_install = 0;
    if (rendezvous(DONE_MAGIC, used, wrapper, game_base) != ACK_MAGIC) fatal("completion-not-acknowledged");
}

void isac_sdk_adapter_bootstrap(void (*log)(const char *, const char *)) {
    isac_sdk_http_service_api api = {0};
    unsigned char observed[32]; size_t i; uintptr_t root;
    const uintptr_t tables[3] = {0x346d738, 0x346d750, 0x346d720};
    const unsigned int methods[3] = {0, 1, 4};
    const uintptr_t entries[3][3] = {
        {0x212ff80,0x217a5e0,0x2153e30}, {0x212ffe0,0x217a5f0,0x2153e70}, {0x212fe60,0x217a5d0,0x2153df0}};
    logger = log; game_base = (uintptr_t)GetModuleHandleW(NULL);
    if (!game_base || !file_hash_ok()) fatal("unsupported-game-file");
    for (i = 0; i < sizeof(live_anchors) / sizeof(live_anchors[0]); ++i)
        if (!read_memory(NULL, game_base + live_anchors[i].rva, observed, sizeof(observed)) ||
            memcmp(observed, live_anchors[i].bytes, sizeof(observed))) fatal("live-code-anchor-mismatch");
    if (!read_memory(NULL, game_base + 0x4849630, &root, sizeof(root)) || root)
        fatal("too-late-sdk-root-already-exists");
#define BIND(field, rva) do { uintptr_t pointer = game_base + (rva); memcpy(&(field), &pointer, sizeof(pointer)); } while (0)
    BIND(api.request.string_from_utf8, 0x211abe0); BIND(api.request.string_destroy, 0x3c160);
    BIND(api.request.url_parse, 0x211b490); BIND(api.request.url_assign, 0x2127390);
    BIND(api.request.url_format, 0x217db90); BIND(api.request.url_destroy, 0x21240f0);
    api.request.read = read_memory;
    for (i = 0; i < 3; ++i) {
        api.request.classes[i].address = game_base + tables[i]; api.request.classes[i].method_id = methods[i];
        BIND(api.request.classes[i].entries.destroy, entries[i][0]);
        BIND(api.request.classes[i].entries.method, entries[i][1]);
        BIND(api.request.classes[i].entries.clone, entries[i][2]);
    }
    api.future.string_from_utf8 = api.request.string_from_utf8; api.future.string_destroy = api.request.string_destroy;
    BIND(api.future.future_construct, 0x2104ba0); BIND(api.future.future_complete, 0x21e3640);
    BIND(api.future.future_copy, 0x2104af0); BIND(api.future.future_destroy, 0x212d970);
    api.future.read = read_memory; api.future.future_vtable = game_base + 0x346d030;
    api.future.state_vtable = game_base + 0x346c388; api.future.response_vtable = game_base + 0x3475c50;
    api.original_vtable = game_base + 0x346d628; api.wrapper_vtable = game_base + 0x346cf68;
    BIND(api.dispatch, 0x21dbad0); BIND(api.destroy, 0x212fe30);
#undef BIND
    api.acquire_transport = acquire; api.transport_ready = ready; api.drain_transport = unused_drain;
    api.release_transport = release; api.transport_process_lifetime = 1; api.fatal = fatal;
    isac_sdk_adapter_resume = game_base + 0x20fa804;
    if (logger) logger("SDK_ADAPTER_WAITING", "linux-debugger-required");
    if (rendezvous(READY_MAGIC, game_base + 0x20fa7ff, (uintptr_t)isac_sdk_adapter_entry, game_base) != ACK_MAGIC)
        fatal("debugger-not-acknowledged");
    attested = 1;
    for (i = 0; i < POOL_SIZE; ++i) {
        pool[i] = isac_sdk_http_service_reserve(&api);
        if (!pool[i]) fatal("adapter-reservation-failed");
    }
    if (logger) logger("SDK_ADAPTER_ARMED", "external-ip-isolated,epochs=8,template-patch=off");
}
