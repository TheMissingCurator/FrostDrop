#include "../src/uplay_probe/sdk_http_native_service.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Service glue fixtures only. Actual request/result implementations have their
 * own suites; these stand-ins deliberately never execute retail SDK code. */
typedef struct { isac_http_method method; char url[256]; int body; } request;
static int leases, sends, drops, clones, originals_destroyed, drained, failures;
static int allow_lease = 1, ready = 1, admission = 1, allow_write = 1, corrupt_rewrite;
static int descriptor_generation;
static int permanent_policy;
static const char *fatal_case;
static request queued;
static const void *expected_options;
static void *expected_original;
static isac_http_status last_failure;
static int checked_read(void *p, uintptr_t addr, void *out, size_t n) {
    (void)p; if (!addr || n > UINTPTR_MAX - addr) return 0;
    memcpy(out, (const void *)addr, n); return 1;
}
int isac_sdk_request_describe(const isac_sdk_request_api *a, const void *p,
    char *buf, size_t cap, isac_http_request_view *view) {
    const request *r = p; (void)a;
    if (strlen(r->url) >= cap) return 0;
    strcpy(buf, r->url); view->url = buf; view->url_length = strlen(buf); view->method = r->method;
    return 1;
}
void *isac_sdk_request_clone(const isac_sdk_request_api *a, const void *r) {
    request *copy = malloc(sizeof(*copy)); (void)a; assert(copy);
    *copy = *(const request *)r; ++clones; return copy;
}
int isac_sdk_request_replace_url(const isac_sdk_request_api *a, void *p, const char *url, size_t n) {
    request *r = p; (void)a; assert(n < sizeof(r->url));
    if (!corrupt_rewrite) strcpy(r->url, url);
    return 1;
}
int isac_sdk_request_destroy(const isac_sdk_request_api *a, void *p) {
    (void)a; free(p); ++drops; return 1;
}
int isac_sdk_http_failure(const isac_sdk_future_api *a, isac_sdk_http_future *out, isac_http_status reason) {
    if (fatal_case && strcmp(fatal_case, "result") == 0) return 0;
    (void)a; out->vtable = 3; out->state = NULL; out->response = NULL;
    ++failures; last_failure = reason; return 1;
}
static void *(ISAC_SDK_CALL string_make)(isac_sdk_string *s, const char *p) { (void)p; return s; }
static void (ISAC_SDK_CALL string_drop)(isac_sdk_string *s) { (void)s; }
static void *(ISAC_SDK_CALL url_parse)(isac_sdk_url *u, const isac_sdk_string *s) { (void)s; return u; }
static void *(ISAC_SDK_CALL url_assign)(isac_sdk_url *u, const isac_sdk_url *s) { (void)s; return u; }
static isac_sdk_string *(ISAC_SDK_CALL url_format)(const isac_sdk_url *u, isac_sdk_string *s) { (void)u; return s; }
static void (ISAC_SDK_CALL url_drop)(isac_sdk_url *u) { (void)u; }
static void *(ISAC_SDK_CALL future_make)(isac_sdk_http_future *f, const isac_sdk_string *s) { (void)s; return f; }
static void (ISAC_SDK_CALL future_complete)(isac_sdk_http_future *f, const isac_sdk_error *e) { (void)f; (void)e; }
static void *(ISAC_SDK_CALL future_copy)(isac_sdk_http_future *f, const isac_sdk_http_future *s) { (void)s; return f; }
static void *(ISAC_SDK_CALL future_drop)(isac_sdk_http_future *f, unsigned int flags) { (void)flags; return f; }
static void *lease_acquire(void *p) { (void)p; if (!allow_lease) return NULL; ++leases; return &leases; }
static int lease_ready(void *p) { assert(p == &leases && leases > 0); return ready; }
static int lease_drain(void *p, void *original) {
    assert(p == &leases && leases > 0 && original == expected_original);
    if (fatal_case && strcmp(fatal_case, "drain") == 0) return 0;
    ++drained; return 1;
}
static void lease_release(void *p) { assert(p == &leases && leases > 0); --leases; }
static void must_not_fail(const char *message) {
    if (fatal_case) {
        assert(leases == 1 && !originals_destroyed);
        if (strcmp(fatal_case, "result") == 0) {
            assert(strcmp(message, "failure-result-unavailable") == 0 && !sends);
        } else if (strcmp(fatal_case, "return") == 0) {
            assert(strcmp(message, "native-dispatch-return-mismatch") == 0 && sends == 1 && !failures);
        } else {
            assert(strcmp(fatal_case, "drain") == 0 && strcmp(message, "transport-drain-failed") == 0);
        }
        puts("fatal boundary stopped without external fallback"); exit(77);
    }
    fprintf(stderr, "unexpected fatal: %s\n", message); abort();
}
static isac_sdk_http_future *(ISAC_SDK_CALL native_send)(void *original, isac_sdk_http_future *out,
    const void *p, const void *options) {
    const request *r = p;
    assert(leases > 0 && ready && original == expected_original && options == expected_options);
    assert(strncmp(r->url, ISAC_HTTP_LOCAL_ORIGIN "/", sizeof(ISAC_HTTP_LOCAL_ORIGIN)) == 0);
    queued = *r; /* Simulate native job retaining an independent request. */
    ++sends; out->vtable = 0; out->state = &queued; out->response = NULL;
    if (fatal_case && strcmp(fatal_case, "return") == 0) return NULL;
    return out; /* Pending future is valid, not a transport failure. */
}
static void *(ISAC_SDK_CALL native_delete)(void *original, unsigned int flags) {
    assert(original == expected_original && flags == 1 && leases > 0);
    if (!permanent_policy) assert(drained == originals_destroyed + 1);
    ++originals_destroyed; return original;
}
static int admit(void *p, const isac_sdk_http_publication *event) { (void)p; (void)event; return admission; }
static int replace_slot(void *p, uintptr_t slot, void *expected, void *replacement) {
    void *current; (void)p; memcpy(&current, (const void *)slot, sizeof(current));
    if (!allow_write || current != expected) return 0;
    memcpy((void *)slot, &replacement, sizeof(replacement)); return 1;
}
static const isac_sdk_http_service_vtable *service_table(isac_sdk_http_service *s) {
    const isac_sdk_http_service_vtable *v; memcpy(&v, s, sizeof(v)); return v;
}
int main(int argc, char **argv) {
    struct {
        void *(ISAC_SDK_CALL *destroy)(void *, unsigned int);
        isac_sdk_http_future *(ISAC_SDK_CALL *send)(void *, isac_sdk_http_future *, const void *, const void *);
    } original_table = {native_delete, native_send};
    uintptr_t original = (uintptr_t)&original_table, facade[20] = {0};
    uintptr_t wrapper[3] = {0x9876, (uintptr_t)facade, (uintptr_t)&original};
    isac_sdk_http_publication event = {0x140000000, 0x1420fa7ff,
        (uintptr_t)facade, (uintptr_t)&facade[10], (uintptr_t)wrapper};
    isac_sdk_http_install_api installer = {admit, replace_slot, NULL};
    isac_sdk_http_service_api api = {0};
    isac_sdk_http_service *service;
    isac_sdk_http_future out;
    request r = {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com/v3/profiles/sessions", 42};
    request saved = r;
    int options = 123;
    expected_original = &original; expected_options = &options;
    api.request.string_from_utf8 = string_make; api.request.string_destroy = string_drop;
    api.request.url_parse = url_parse; api.request.url_assign = url_assign;
    api.request.url_format = url_format; api.request.url_destroy = url_drop; api.request.read = checked_read;
    api.future.string_from_utf8 = string_make; api.future.string_destroy = string_drop;
    api.future.future_construct = future_make; api.future.future_complete = future_complete;
    api.future.future_copy = future_copy; api.future.future_destroy = future_drop;
    api.future.read = checked_read; api.future.future_vtable = 1; api.future.state_vtable = 2; api.future.response_vtable = 3;
    api.original_vtable = (uintptr_t)&original_table; api.wrapper_vtable = wrapper[0];
    api.dispatch = native_send; api.destroy = native_delete; api.fatal = must_not_fail;
    api.acquire_transport = lease_acquire; api.transport_ready = lease_ready;
    api.drain_transport = lease_drain; api.release_transport = lease_release;
    allow_lease = 0; assert(!isac_sdk_http_service_prepare(&api, &original)); assert(!leases);
    allow_lease = 1; ready = 0; assert(!isac_sdk_http_service_prepare(&api, &original)); assert(!leases); ready = 1;
    service = isac_sdk_http_service_prepare(&api, &original); assert(service && leases == 1);
    admission = 0; assert(!isac_sdk_http_service_install(service, &installer, &event)); admission = 1;
    ++event.instruction; assert(!isac_sdk_http_service_install(service, &installer, &event)); --event.instruction;
    facade[10] = (uintptr_t)wrapper; assert(!isac_sdk_http_service_install(service, &installer, &event)); facade[10] = 0;
    ++wrapper[1]; assert(!isac_sdk_http_service_install(service, &installer, &event)); --wrapper[1];
    ++wrapper[0]; assert(!isac_sdk_http_service_install(service, &installer, &event)); --wrapper[0];
    ++original; assert(!isac_sdk_http_service_install(service, &installer, &event)); --original;
    allow_write = 0; assert(!isac_sdk_http_service_install(service, &installer, &event)); allow_write = 1;
    assert(wrapper[2] == (uintptr_t)&original && !facade[10]);
    isac_sdk_http_service_discard(service); assert(!leases && !originals_destroyed && !drained);

    service = isac_sdk_http_service_prepare(&api, &original); assert(service);
    assert(isac_sdk_http_service_install(service, &installer, &event));
    assert(wrapper[2] == (uintptr_t)service && !facade[10]);
    assert(!isac_sdk_http_service_install(service, &installer, &event));
    facade[10] = (uintptr_t)wrapper; /* Getter publishes AFTER installation. */
    if (argc == 2) {
        fatal_case = argv[1];
        if (strcmp(fatal_case, "drain") == 0) service_table(service)->destroy(service, 1u);
        if (strcmp(fatal_case, "result") == 0) ready = 0;
        service_table(service)->dispatch(service, &out, &r, &options);
        assert(!"fatal test returned");
    }
    assert(service_table(service)->dispatch(service, &out, &r, &options) == &out);
    assert(sends == 1 && !out.vtable && out.state == &queued && queued.body == 42);
    assert(clones == 1 && drops == 1 && memcmp(&r, &saved, sizeof(r)) == 0);
    /* Descriptor replacement affects requests, not our service instance. */
    ++descriptor_generation; r.method = ISAC_HTTP_GET;
    strcpy(r.url, "https://public-ubiservices.ubi.com/v1/applications/local/configuration");
    service_table(service)->dispatch(service, &out, &r, &options); assert(sends == 2);
    strcpy(r.url, "https://external.invalid/v1/applications/local/configuration");
    service_table(service)->dispatch(service, &out, &r, &options);
    assert(sends == 2 && failures == 1 && last_failure == ISAC_HTTP_BLOCKED_ORIGIN);
    r = saved; ready = 0;
    service_table(service)->dispatch(service, &out, &r, &options);
    assert(sends == 2 && last_failure == ISAC_HTTP_SEND_FAILED); ready = 1;
    corrupt_rewrite = 1;
    service_table(service)->dispatch(service, &out, &r, &options);
    assert(sends == 2 && last_failure == ISAC_HTTP_SEND_FAILED); corrupt_rewrite = 0;
    assert(clones == drops && leases == 1);
    service_table(service)->destroy(service, 1u); facade[10] = 0;
    assert(!leases && drained == 1 && originals_destroyed == 1);
    /* Fresh epoch: no stale wrapper/adapter reused. */
    wrapper[2] = (uintptr_t)&original;
    service = isac_sdk_http_service_prepare(&api, &original); assert(service);
    assert(isac_sdk_http_service_install(service, &installer, &event));
    service_table(service)->destroy(service, 0u);
    isac_sdk_http_service_discard(service); /* Caller owns non-deleted shell. */
    assert(!leases && drained == 2 && originals_destroyed == 2);
    /* Preallocate before the debugger hold; bind without an allocation at the
     * stop. Permanent kernel isolation is not released with the service. */
    api.transport_process_lifetime = 1; permanent_policy = 1;
    wrapper[2] = (uintptr_t)&original;
    service = isac_sdk_http_service_reserve(&api); assert(service);
    ++original; assert(!isac_sdk_http_service_bind(service, &original)); --original;
    assert(isac_sdk_http_service_bind(service, &original));
    assert(!isac_sdk_http_service_bind(service, &original));
    assert(isac_sdk_http_service_install(service, &installer, &event));
    service_table(service)->destroy(service, 1u);
    assert(!leases && drained == 2 && originals_destroyed == 3);
    puts("SDK service wiring: sender, publication, ownership and epoch tests passed");
    return 0;
}
