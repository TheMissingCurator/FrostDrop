#include "sdk_http_native_service.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

struct isac_sdk_http_service {
    const isac_sdk_http_service_vtable *vtable; /* ABI slot zero */
    isac_sdk_http_service_api api;
    void *original, *lease;
    isac_http_adapter *core;
    atomic_uint active;
    int installed;
};
_Static_assert(offsetof(isac_sdk_http_service, vtable) == 0, "service ABI");
_Static_assert(sizeof(isac_sdk_http_service_vtable) == 16, "two-slot service ABI");

static _Noreturn void fatal(isac_sdk_http_service *s, const char *reason) {
    s->api.fatal(reason);
    abort();
}
static int read_at(isac_sdk_http_service *s, uintptr_t base, size_t offset,
                   void *out, size_t length) {
    if (!base || offset > UINTPTR_MAX - base || length > UINTPTR_MAX - (base + offset)) return 0;
    return s->api.request.read(s->api.request.read_context, base + offset, out, length);
}
static int original_valid(isac_sdk_http_service *s) {
    uintptr_t table;
    /* Function pointers are copied as their exact types, not cast from data. */
    isac_sdk_http_future *(ISAC_SDK_CALL *dispatch)(void *, isac_sdk_http_future *, const void *, const void *);
    void *(ISAC_SDK_CALL *destroy)(void *, unsigned int);
    return read_at(s, (uintptr_t)s->original, 0, &table, sizeof(table)) &&
        table == s->api.original_vtable &&
        read_at(s, table, 0, &destroy, sizeof(destroy)) && destroy == s->api.destroy &&
        read_at(s, table, 8, &dispatch, sizeof(dispatch)) && dispatch == s->api.dispatch;
}
static int describe(void *p, const void *r, char *buf, size_t cap, isac_http_request_view *view) {
    isac_sdk_http_service *s = p;
    return isac_sdk_request_describe(&s->api.request, r, buf, cap, view);
}
static void *clone(void *p, const void *r) {
    return isac_sdk_request_clone(&((isac_sdk_http_service *)p)->api.request, r);
}
static int replace_url(void *p, void *r, const char *url, size_t length) {
    return isac_sdk_request_replace_url(&((isac_sdk_http_service *)p)->api.request, r, url, length);
}
static void destroy_request(void *p, void *r) {
    isac_sdk_http_service *s = p;
    if (!isac_sdk_request_destroy(&s->api.request, r)) fatal(s, "request-release-failed");
}
static int failure(void *p, void *out, isac_http_status reason) {
    return isac_sdk_http_failure(&((isac_sdk_http_service *)p)->api.future, out, reason);
}
static int send_local(void *p, void *out, const void *r, const void *options) {
    isac_sdk_http_service *s = p;
    char source[ISAC_HTTP_URL_LIMIT + 1], canonical[ISAC_HTTP_URL_LIMIT + sizeof(ISAC_HTTP_LOCAL_ORIGIN)];
    isac_http_request_view view;
    isac_sdk_http_future *returned;
    /* Recheck the actual rebuilt clone, not just the input route. A production
     * URL also passes route(), hence require exact equality with local output. */
    if (!s->installed || !s->api.transport_ready(s->lease) || !original_valid(s) ||
        !describe(s, r, source, sizeof(source), &view) ||
        isac_http_route(view.method, view.url, view.url_length, canonical, sizeof(canonical)) != ISAC_HTTP_OK ||
        strlen(canonical) != view.url_length || memcmp(canonical, view.url, view.url_length)) return 0;
    /* Native dispatch owns its queued clone/options references before return.
     * Do not reinterpret its normal pending future as a failed operation.
     * Once called, it may have published output/queued work: never invoke a
     * failure constructor over that output or retry through another sender. */
    returned = s->api.dispatch(s->original, out, r, options);
    if (returned != out) fatal(s, "native-dispatch-return-mismatch");
    return 1;
}
static void release_context(void *p) {
    isac_sdk_http_service *s = p;
    if (s->installed) {
        if (!s->api.transport_process_lifetime && !s->api.drain_transport(s->lease, s->original))
            fatal(s, "transport-drain-failed");
        s->api.destroy(s->original, 1u); /* Original uses SDK allocation. */
        s->original = NULL;
        s->installed = 0;
    }
    s->api.release_transport(s->lease); /* Last: includes queued-work lifetime. */
    s->lease = NULL;
}
static isac_sdk_http_future *(ISAC_SDK_CALL dispatch_service)(isac_sdk_http_service *s,
    isac_sdk_http_future *out, const void *request, const void *options) {
    isac_http_status status;
    if (!s->installed || !out) fatal(s, "invalid-service-dispatch");
    atomic_fetch_add_explicit(&s->active, 1u, memory_order_acq_rel);
    status = isac_http_adapter_dispatch(s->core, out, request, options);
    atomic_fetch_sub_explicit(&s->active, 1u, memory_order_acq_rel);
    if (status == ISAC_HTTP_RESULT_FAILED) fatal(s, "failure-result-unavailable");
    return out;
}
static void *(ISAC_SDK_CALL destroy_service)(isac_sdk_http_service *s, unsigned int flags) {
    /* Owner MUST exclude new dispatches before teardown, as for the SDK
     * interface. This count detects in-flight misuse; it is not that barrier. */
    if (!s->installed || atomic_load_explicit(&s->active, memory_order_acquire))
        fatal(s, "service-teardown-not-quiescent");
    isac_http_adapter_destroy(s->core);
    s->core = NULL;
    if (flags & 1u) { free(s); return NULL; } /* Adapter uses our allocator. */
    return s;
}
static const isac_sdk_http_service_vtable vtable = {destroy_service, dispatch_service};

static isac_sdk_http_service *prepare(const isac_sdk_http_service_api *api, void *original) {
    static const isac_http_binding binding = {describe, clone, replace_url, send_local,
        destroy_request, failure, release_context};
    isac_sdk_http_service *s;
    if (!api || !api->request.read || !api->dispatch || !api->destroy ||
        !api->original_vtable || !api->wrapper_vtable || !api->acquire_transport ||
        !api->transport_ready || !api->drain_transport || !api->release_transport || !api->fatal ||
        !api->future.read || !api->future.string_from_utf8 || !api->future.string_destroy ||
        !api->future.future_construct || !api->future.future_complete || !api->future.future_copy ||
        !api->future.future_destroy || !api->future.future_vtable || !api->future.state_vtable ||
        !api->future.response_vtable || !api->request.string_from_utf8 || !api->request.string_destroy ||
        !api->request.url_parse || !api->request.url_format || !api->request.url_assign || !api->request.url_destroy)
        return NULL;
    s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->vtable = &vtable; s->api = *api; s->original = original;
    atomic_init(&s->active, 0u);
    if (original && !original_valid(s)) { free(s); return NULL; }
    s->lease = api->acquire_transport(api->transport_context);
    if (!s->lease) { free(s); return NULL; }
    if (!api->transport_ready(s->lease)) { api->release_transport(s->lease); free(s); return NULL; }
    s->core = isac_http_adapter_create(&binding, s);
    if (!s->core) { api->release_transport(s->lease); free(s); return NULL; }
    return s;
}
isac_sdk_http_service *isac_sdk_http_service_prepare(const isac_sdk_http_service_api *api, void *original) {
    return original ? prepare(api, original) : NULL;
}
isac_sdk_http_service *isac_sdk_http_service_reserve(const isac_sdk_http_service_api *api) {
    return prepare(api, NULL);
}
int isac_sdk_http_service_bind(isac_sdk_http_service *s, void *original) {
    if (!s || s->installed || s->original || !original) return 0;
    s->original = original;
    if (original_valid(s)) return 1;
    s->original = NULL;
    return 0;
}
void isac_sdk_http_service_discard(isac_sdk_http_service *s) {
    if (!s) return;
    if (s->installed) fatal(s, "discard-installed-service");
    isac_http_adapter_destroy(s->core);
    free(s);
}
int isac_sdk_http_service_install(isac_sdk_http_service *s,
    const isac_sdk_http_install_api *installer, const isac_sdk_http_publication *event) {
    uintptr_t table, back_pointer, slot_value, original;
    if (!s || s->installed || !installer || !event || !installer->admit ||
        !installer->replace_private_pointer || !event->image_base || !event->facade || !event->wrapper ||
        event->image_base > UINTPTR_MAX - 0x20fa7ffu ||
        event->instruction != event->image_base + 0x20fa7ffu ||
        event->facade > UINTPTR_MAX - 0x50u || event->owner_slot != event->facade + 0x50u ||
        !installer->admit(installer->context, event) || !s->api.transport_ready(s->lease) || !original_valid(s) ||
        !read_at(s, event->owner_slot, 0, &slot_value, sizeof(slot_value)) || slot_value ||
        !read_at(s, event->wrapper, 0, &table, sizeof(table)) || table != s->api.wrapper_vtable ||
        !read_at(s, event->wrapper, 8, &back_pointer, sizeof(back_pointer)) || back_pointer != event->facade ||
        !read_at(s, event->wrapper, 16, &original, sizeof(original)) || original != (uintptr_t)s->original)
        return 0;
    /* The held publication barrier excludes dispatch/teardown through this
     * unpublished wrapper. No facade slot or shared vtable is modified. */
    if (!installer->replace_private_pointer(installer->context, event->wrapper + 16, s->original, s)) return 0;
    s->installed = 1;
    return 1;
}
