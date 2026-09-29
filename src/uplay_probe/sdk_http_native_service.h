#ifndef ISAC_SDK_HTTP_NATIVE_SERVICE_H
#define ISAC_SDK_HTTP_NATIVE_SERVICE_H

#include "sdk_http_native_result.h"

typedef struct isac_sdk_http_service isac_sdk_http_service;
typedef struct {
    void *(ISAC_SDK_CALL *destroy)(isac_sdk_http_service *, unsigned int flags);
    isac_sdk_http_future *(ISAC_SDK_CALL *dispatch)(isac_sdk_http_service *,
        isac_sdk_http_future *, const void *request, const void *options);
} isac_sdk_http_service_vtable;

/* Live capabilities, NOT a resolver. Addresses/entries must be verified for the
 * loaded build before use. The retained original is never used as fallback. */
typedef struct {
    isac_sdk_request_api request;
    isac_sdk_future_api future;
    uintptr_t original_vtable, wrapper_vtable;
    isac_sdk_http_future *(ISAC_SDK_CALL *dispatch)(void *original,
        isac_sdk_http_future *, const void *, const void *);
    void *(ISAC_SDK_CALL *destroy)(void *original, unsigned int flags);

    /* Mandatory real enforcement, not environment flags or a URL check.
     * acquire pins a transport policy excluding external IP destinations,
     * including DNS/proxies/redirects/retries and already-open connections.
     * It must remain enforced for queued work until drain succeeds, even if
     * ready later reports false. A shared lease may back multiple services.
     * Initial requests are separately restricted to 127.0.0.1:55003. */
    void *(*acquire_transport)(void *context);
    int (*transport_ready)(void *lease);
    int (*drain_transport)(void *lease, void *original);
    void (*release_transport)(void *lease);
    void *transport_context;
    /* A kernel restriction retained until process exit needs no per-service
     * drain before lease release: release cannot relax it for queued work. */
    int transport_process_lifetime;

    /* Must terminate/otherwise never return; abort() is a final backstop.
     * Receives only a fixed reason, never URLs/tickets/body bytes. */
    void (*fatal)(const char *reason);
} isac_sdk_http_service_api;

/* Prepare does not take ownership of original. It acquires an enforced lease
 * and creates an ABI interface. Install commits ownership; discard releases
 * only adapter/lease, leaving original owned by its existing wrapper.
 * Prepared objects must not be dispatched or deleted through their vtable. */
isac_sdk_http_service *isac_sdk_http_service_prepare(
    const isac_sdk_http_service_api *api, void *original);
/* Reserve storage BEFORE stopping other threads. Bind exactly once at the
 * authenticated publication event; avoids allocator locks in the stopped path. */
isac_sdk_http_service *isac_sdk_http_service_reserve(const isac_sdk_http_service_api *api);
int isac_sdk_http_service_bind(isac_sdk_http_service *reserved, void *original);
void isac_sdk_http_service_discard(isac_sdk_http_service *prepared);

/* Register snapshot at RVA 0x20fa7ff: after concrete state binding, before
 * facade+0x50 publication. This snapshot is NOT proof of exclusion by itself.
 * The caller must hold the actual initialization/publication barrier and pin
 * these objects until install returns. Never synthesize it from polled slots. */
typedef struct {
    uintptr_t image_base, instruction, facade, owner_slot, wrapper;
} isac_sdk_http_publication;
typedef struct {
    /* Must authenticate the live stopped initialization event and exclusion;
     * fail unless the loaded build and all supplied capabilities are verified.
     * No production capture/barrier implementation exists yet. */
    int (*admit)(void *context, const isac_sdk_http_publication *event);
    /* Must replace ONLY an already writable private aligned pointer slot,
     * compare against expected, and return 0 with memory untouched on failure.
     * Must not change page protections, patch code or touch a shared vtable. */
    int (*replace_private_pointer)(void *context, uintptr_t slot,
        void *expected, void *replacement);
    void *context;
} isac_sdk_http_install_api;

/* Transfers original to adapter and adapter to wrapper only on success.
 * On refusal: no slot write, caller must discard prepared. No polling/retry. */
int isac_sdk_http_service_install(isac_sdk_http_service *prepared,
    const isac_sdk_http_install_api *installer,
    const isac_sdk_http_publication *event);

#ifdef _WIN32
/* Implements only the checked data-slot write, NOT the missing admission or
 * transport enforcement. It cannot make a polled/live slot safe to replace. */
int isac_sdk_http_replace_private_pointer(void *unused, uintptr_t slot,
    void *expected, void *replacement);
#endif
#endif
