#include "sdk_http_native_request.h"

#include <string.h>

_Static_assert(sizeof(void *) == 8, "SDK pointer width");
_Static_assert(sizeof(isac_sdk_string) == 0x58, "SDK string size");
_Static_assert(sizeof(isac_sdk_url) == 0x2c8, "SDK URL size");
_Static_assert(sizeof(isac_sdk_request_vtable) == 0x18, "request vtable size");
_Static_assert(offsetof(isac_sdk_request_vtable, method) == 8, "method slot");
_Static_assert(offsetof(isac_sdk_request_vtable, clone) == 16, "clone slot");

static int read_at(const isac_sdk_request_api *api, uintptr_t base, size_t offset,
                   void *output, size_t size) {
    uintptr_t address;
    if (!api || !api->read || !base || offset > UINTPTR_MAX - base) return 0;
    address = base + offset;
    if (size > UINTPTR_MAX - address) return 0;
    return api->read(api->read_context, address, output, size);
}

static int semantic_method(unsigned int native, isac_http_method *out) {
    switch (native) {
        case 0: *out = ISAC_HTTP_GET; return 1;
        case 1: *out = ISAC_HTTP_POST; return 1;
        case 4: *out = ISAC_HTTP_DELETE; return 1;
        default: return 0;
    }
}

static const isac_sdk_request_class *request_class(
    const isac_sdk_request_api *api, const void *request) {
    uintptr_t address;
    isac_sdk_request_vtable actual;
    size_t i;
    if (!request || !read_at(api, (uintptr_t)request, 0, &address, sizeof(address))) return NULL;
    for (i = 0; i < 3; ++i) {
        const isac_sdk_request_class *c = &api->classes[i];
        isac_http_method unused;
        if (!c->address || c->address != address || !semantic_method(c->method_id, &unused)) continue;
        if (!c->entries.destroy || !c->entries.method || !c->entries.clone ||
            !read_at(api, address, 0, &actual, sizeof(actual))) return NULL;
        if (actual.destroy != c->entries.destroy || actual.method != c->entries.method ||
            actual.clone != c->entries.clone) return NULL;
        return c;
    }
    return NULL;
}

int isac_sdk_string_copy_utf8(const isac_sdk_request_api *api,
    const isac_sdk_string *string, char *output, size_t capacity, size_t *length) {
    uintptr_t referent, vbtable, base, chars;
    int32_t displacement;
    uint64_t size, reserved;
    char copy[ISAC_HTTP_URL_LIMIT + 1];
    if (!output || !length || !capacity ||
        !read_at(api, (uintptr_t)string, 0, &referent, sizeof(referent)) ||
        !read_at(api, referent, 0x10, &vbtable, sizeof(vbtable)) ||
        !read_at(api, vbtable, 4, &displacement, sizeof(displacement)) ||
        referent > UINTPTR_MAX - 0x10) return 0;
    base = referent + 0x10;
    if (displacement < 0) {
        uintptr_t distance = (uintptr_t)(-(int64_t)displacement);
        if (distance > base) return 0;
        base -= distance;
    } else {
        if ((uintptr_t)displacement > UINTPTR_MAX - base) return 0;
        base += (uintptr_t)displacement;
    }
    if (!read_at(api, base, 0x10, &size, sizeof(size)) ||
        !read_at(api, base, 0x18, &reserved, sizeof(reserved)) ||
        size > reserved || size > ISAC_HTTP_URL_LIMIT || size >= capacity) return 0;
    chars = base;
    if (reserved >= 16 && !read_at(api, base, 0, &chars, sizeof(chars))) return 0;
    if (!read_at(api, chars, 0, copy, (size_t)size + 1) || copy[size] != '\0' ||
        memchr(copy, '\0', (size_t)size)) return 0;
    memcpy(output, copy, (size_t)size + 1);
    *length = (size_t)size;
    return 1;
}

static int method_matches(const isac_sdk_request_class *c, const void *request,
                          isac_http_method *method) {
    return c && c->entries.method(request) == c->method_id &&
        semantic_method(c->method_id, method);
}

int isac_sdk_request_describe(const isac_sdk_request_api *api, const void *request,
    char *scratch, size_t capacity, isac_http_request_view *view) {
    const isac_sdk_request_class *c = request_class(api, request);
    isac_http_method method;
    isac_sdk_string formatted;
    size_t length;
    int ok;
    if (!view || !scratch || !capacity || !c || !api->url_format ||
        !api->string_destroy || !method_matches(c, request, &method) ||
        (uintptr_t)request > UINTPTR_MAX - 8) return 0;
    /* Formatter constructs its output in fresh storage (RDX), not assignment. */
    api->url_format((const isac_sdk_url *)((const unsigned char *)request + 8), &formatted);
    ok = isac_sdk_string_copy_utf8(api, &formatted, scratch, capacity, &length);
    api->string_destroy(&formatted);
    if (!ok) return 0;
    view->method = method;
    view->url = scratch;
    view->url_length = length;
    return 1;
}

void *isac_sdk_request_clone(const isac_sdk_request_api *api, const void *request) {
    const isac_sdk_request_class *c = request_class(api, request);
    isac_http_method method;
    void *copy;
    if (!method_matches(c, request, &method)) return NULL;
    copy = c->entries.clone(request);
    /* The verified native clone function is responsible for returning its own
     * initialized subtype. Do not destroy a contract-violating borrowed alias. */
    return copy == request ? NULL : copy;
}

int isac_sdk_request_destroy(const isac_sdk_request_api *api, void *owned_request) {
    const isac_sdk_request_class *c = request_class(api, owned_request);
    if (!c) return 0;
    c->entries.destroy(owned_request, 1u);
    return 1;
}

int isac_sdk_request_replace_url(const isac_sdk_request_api *api,
    void *owned_request, const char *url, size_t length) {
    const isac_sdk_request_class *c = request_class(api, owned_request);
    isac_http_method method;
    char canonical[ISAC_HTTP_URL_LIMIT + sizeof(ISAC_HTTP_LOCAL_ORIGIN)];
    char roundtrip[ISAC_HTTP_URL_LIMIT + 1];
    isac_sdk_string source, formatted;
    isac_sdk_url parsed;
    size_t formatted_length = 0;
    int ok;
    if (!c || !api->string_from_utf8 || !api->string_destroy || !api->url_parse ||
        !api->url_assign || !api->url_format || !api->url_destroy ||
        !method_matches(c, owned_request, &method) ||
        (uintptr_t)owned_request > UINTPTR_MAX - 8 ||
        isac_http_route(method, url, length, canonical, sizeof(canonical)) != ISAC_HTTP_OK ||
        strlen(canonical) != length || memcmp(canonical, url, length) != 0) return 0;
    /* No mutation of the clone until the parsed temporary round-trips exactly.
     * These SDK calls have no bool/error return. Do not invent error semantics
     * or pretend this C wrapper catches native exceptions/allocation faults. */
    api->string_from_utf8(&source, canonical);
    api->url_parse(&parsed, &source);
    api->url_format(&parsed, &formatted);
    ok = isac_sdk_string_copy_utf8(api, &formatted, roundtrip, sizeof(roundtrip), &formatted_length) &&
        formatted_length == length && memcmp(roundtrip, canonical, length) == 0;
    api->string_destroy(&formatted);
    if (ok) api->url_assign((isac_sdk_url *)((unsigned char *)owned_request + 8), &parsed);
    api->url_destroy(&parsed);
    api->string_destroy(&source);
    return ok;
}
