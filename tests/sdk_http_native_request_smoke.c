#include "../src/uplay_probe/sdk_http_native_request.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Synthetic objects/functions, never retail code. Fixtures exercise Windows
 * x64 call ABI, bounded reads, output argument order and reference lifetimes.
 * The mock URL stores one reference: it does NOT reproduce the native parser. */
typedef struct {
    uint64_t vtable;
    uint32_t refs, padding;
    const int32_t *vbtable;
    union { char small[16]; char *large; } text;
    uint64_t length, capacity;
    char *allocation;
} string_ref;
typedef struct {
    const isac_sdk_request_vtable *vtable;
    isac_sdk_url url;
    unsigned char remainder[0x350 - 8 - 0x2c8];
} request;
_Static_assert(offsetof(string_ref, text) == 0x18, "fixture vbtable offset");
_Static_assert(offsetof(request, url) == 8, "request URL offset");
_Static_assert(sizeof(request) == 0x350, "GET/POST/DELETE request size");

static const int32_t vbtable[2] = {0, 8};
static struct { uintptr_t start; size_t size; } ranges[256];
static size_t range_count;
static unsigned int refs_live, urls_live, strings_live, clones, deletes, assignments, formats, method_calls;
static int clone_fails, clone_aliases, wrong_method, bad_roundtrip, unreadable_format;
static uintptr_t denied;

static void track(const void *p, size_t size) {
    assert(range_count < sizeof(ranges) / sizeof(ranges[0]));
    ranges[range_count].start = (uintptr_t)p;
    ranges[range_count++].size = size;
}
static void untrack(const void *p) {
    size_t i;
    for (i = 0; i < range_count; ++i) if (ranges[i].start == (uintptr_t)p) {
        ranges[i] = ranges[--range_count]; return;
    }
    assert(!"untracked fixture pointer");
}
static int checked_read(void *context, uintptr_t address, void *output, size_t size) {
    size_t i;
    (void)context;
    if (!address || address == denied || size > UINTPTR_MAX - address) return 0;
    for (i = 0; i < range_count; ++i) {
        if (address >= ranges[i].start && address - ranges[i].start <= ranges[i].size &&
            size <= ranges[i].size - (address - ranges[i].start)) {
            memcpy(output, (void *)address, size); return 1;
        }
    }
    return 0;
}
static string_ref *ref_of(const isac_sdk_string *s) {
    string_ref *r; memcpy(&r, s->bytes, sizeof(r)); return r;
}
static const char *text_of(const isac_sdk_string *s) {
    string_ref *r = ref_of(s); return r->allocation ? r->allocation : r->text.small;
}
static void *(ISAC_SDK_CALL string_make)(isac_sdk_string *s, const char *text) {
    string_ref *r = calloc(1, sizeof(*r));
    assert(r);
    r->refs = 1; r->vbtable = vbtable; r->length = strlen(text);
    if (r->length < 16) {
        r->capacity = 15; strcpy(r->text.small, text);
    } else {
        r->capacity = r->length;
        r->allocation = malloc((size_t)r->length + 1); assert(r->allocation);
        strcpy(r->allocation, text); r->text.large = r->allocation;
        track(r->allocation, (size_t)r->length + 1);
    }
    memset(s, 0, sizeof(*s)); memcpy(s->bytes, &r, sizeof(r));
    track(r, sizeof(*r)); track(s, sizeof(*s)); ++refs_live; ++strings_live;
    return s;
}
static void release_ref(string_ref *r) {
    assert(r->refs);
    if (--r->refs) return;
    if (r->allocation) { untrack(r->allocation); free(r->allocation); }
    untrack(r); free(r); --refs_live;
}
static void (ISAC_SDK_CALL string_drop)(isac_sdk_string *s) {
    release_ref(ref_of(s)); untrack(s); memset(s, 0, sizeof(*s)); --strings_live;
}
static void *(ISAC_SDK_CALL url_parse)(isac_sdk_url *url, const isac_sdk_string *s) {
    memset(url, 0, sizeof(*url));
    string_make((isac_sdk_string *)url, text_of(s)); ++urls_live; return url;
}
static void *(ISAC_SDK_CALL url_assign)(isac_sdk_url *to, const isac_sdk_url *from) {
    string_ref *old = ref_of((const isac_sdk_string *)to);
    string_ref *next = ref_of((const isac_sdk_string *)from);
    ++next->refs; release_ref(old); memcpy(to->bytes, &next, sizeof(next));
    ++assignments; return to;
}
static isac_sdk_string *(ISAC_SDK_CALL url_format)(const isac_sdk_url *url, isac_sdk_string *out) {
    ++formats;
    string_make(out, bad_roundtrip ? "http://127.0.0.1:55003/not-the-route" : text_of((const isac_sdk_string *)url));
    if (unreadable_format) denied = (uintptr_t)out;
    return out;
}
static void (ISAC_SDK_CALL url_drop)(isac_sdk_url *url) {
    string_drop((isac_sdk_string *)url); --urls_live;
}

static isac_sdk_request_vtable tables[3];
static unsigned int (ISAC_SDK_CALL get_method)(const void *p) {
    const request *r = p; ++method_calls;
    if (wrong_method) return 2;
    return r->vtable == &tables[0] ? 0 : r->vtable == &tables[1] ? 1 : 4;
}
static void *(ISAC_SDK_CALL request_copy)(const void *p) {
    const request *original = p;
    request *r;
    if (clone_fails) return NULL;
    if (clone_aliases) return (void *)p;
    r = calloc(1, sizeof(*r)); assert(r);
    r->vtable = original->vtable;
    memcpy(r->remainder, original->remainder, sizeof(r->remainder));
    string_make((isac_sdk_string *)&r->url, text_of((const isac_sdk_string *)&original->url));
    ++urls_live; ++clones; track(r, sizeof(*r)); return r;
}
static void *(ISAC_SDK_CALL request_drop)(void *p, unsigned int flags) {
    request *r = p; assert(flags == 1);
    url_drop(&r->url); untrack(r); free(r); ++deletes;
    return NULL; /* Return unused: native deleting destructor may return this. */
}
static isac_sdk_request_api make_api(void) {
    isac_sdk_request_api api;
    size_t i;
    memset(&api, 0, sizeof(api));
    api.string_from_utf8 = string_make; api.string_destroy = string_drop;
    api.url_parse = url_parse; api.url_assign = url_assign;
    api.url_format = url_format; api.url_destroy = url_drop; api.read = checked_read;
    for (i = 0; i < 3; ++i) {
        tables[i].destroy = request_drop; tables[i].method = get_method; tables[i].clone = request_copy;
        track(&tables[i], sizeof(tables[i]));
        api.classes[i].address = (uintptr_t)&tables[i];
        api.classes[i].method_id = i == 2 ? 4 : (unsigned int)i;
        api.classes[i].entries = tables[i];
    }
    return api;
}
static request *make_request(unsigned int kind, const char *url) {
    request *r = malloc(sizeof(*r)); assert(r);
    r->vtable = &tables[kind];
    string_make((isac_sdk_string *)&r->url, url); ++urls_live;
    memset(r->remainder, 0xa5, sizeof(r->remainder)); track(r, sizeof(*r)); return r;
}

static void string_tests(isac_sdk_request_api *api) {
    const char *values[] = {"", "123456789012345", "1234567890123456", "a longer heap-backed string"};
    isac_sdk_string s;
    char buffer[128]; size_t n, i;
    for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        string_make(&s, values[i]); n = 999;
        assert(isac_sdk_string_copy_utf8(api, &s, buffer, sizeof(buffer), &n));
        assert(n == strlen(values[i]) && strcmp(buffer, values[i]) == 0);
        strcpy(buffer, "unchanged"); n = 999;
        assert(!isac_sdk_string_copy_utf8(api, &s, buffer, strlen(values[i]), &n));
        assert(n == 999 && strcmp(buffer, "unchanged") == 0);
        string_drop(&s);
    }
    string_make(&s, "short");
    ref_of(&s)->length = 4097;
    assert(!isac_sdk_string_copy_utf8(api, &s, buffer, sizeof(buffer), &n));
    ref_of(&s)->length = 5; ref_of(&s)->text.small[2] = 0;
    assert(!isac_sdk_string_copy_utf8(api, &s, buffer, sizeof(buffer), &n));
    ref_of(&s)->text.small[2] = 'o'; ref_of(&s)->text.small[5] = 'x';
    assert(!isac_sdk_string_copy_utf8(api, &s, buffer, sizeof(buffer), &n));
    ref_of(&s)->text.small[5] = 0;
    denied = (uintptr_t)ref_of(&s)->vbtable + 4;
    assert(!isac_sdk_string_copy_utf8(api, &s, buffer, sizeof(buffer), &n));
    denied = 0; string_drop(&s);
    assert(!isac_sdk_string_copy_utf8(api, (const isac_sdk_string *)(UINTPTR_MAX - 2), buffer, sizeof(buffer), &n));
    assert(!isac_sdk_string_copy_utf8(NULL, &s, buffer, sizeof(buffer), &n));
}

/* Real native helpers wired into the portable core, with ONLY send/failure/
 * context release mocked. Does not pretend these missing bindings are native. */
typedef struct { isac_sdk_request_api *api; unsigned int sends, failures, releases; } bridge;
typedef struct { isac_http_status status; char url[256]; } result;
static int describe(void *p, const void *r, char *s, size_t n, isac_http_request_view *v) {
    return isac_sdk_request_describe(((bridge *)p)->api, r, s, n, v);
}
static void *clone(void *p, const void *r) { return isac_sdk_request_clone(((bridge *)p)->api, r); }
static int replace(void *p, void *r, const char *url, size_t n) {
    return isac_sdk_request_replace_url(((bridge *)p)->api, r, url, n);
}
static void destroy(void *p, void *r) { assert(isac_sdk_request_destroy(((bridge *)p)->api, r)); }
static int send(void *p, void *o, const void *r, const void *options) {
    bridge *b = p; result *out = o; isac_http_request_view view;
    assert(options == b);
    assert(isac_sdk_request_describe(b->api, r, out->url, sizeof(out->url), &view));
    assert(strncmp(out->url, ISAC_HTTP_LOCAL_ORIGIN "/", sizeof(ISAC_HTTP_LOCAL_ORIGIN)) == 0);
    ++b->sends; out->status = ISAC_HTTP_OK; return 1;
}
static int fail(void *p, void *o, isac_http_status status) {
    ++((bridge *)p)->failures; ((result *)o)->status = status;
    return 1;
}
static void release(void *p) { ++((bridge *)p)->releases; }

int main(void) {
    isac_sdk_request_api api;
    isac_http_binding binding = {describe, clone, replace, send, destroy, fail, release};
    const char *production = "https://public-ubiservices.ubi.com/v3/profiles/sessions?q=a%2Fb";
    const char *local = ISAC_HTTP_LOCAL_ORIGIN "/v3/profiles/sessions?q=a%2Fb";
    request *r, *copy;
    char scratch[512]; isac_http_request_view view;
    unsigned int before;
    bridge b; result out; isac_http_adapter *adapter;
    track(vbtable, sizeof(vbtable)); api = make_api(); string_tests(&api);
    r = make_request(1, production); before = refs_live;
    assert(isac_sdk_request_describe(&api, r, scratch, sizeof(scratch), &view));
    assert(view.url == scratch && view.method == ISAC_HTTP_POST && strcmp(scratch, production) == 0);
    assert(refs_live == before);
    copy = isac_sdk_request_clone(&api, r); assert(copy && copy != r);
    assert(isac_sdk_request_replace_url(&api, copy, local, strlen(local)));
    assert(strcmp(text_of((isac_sdk_string *)&r->url), production) == 0);
    assert(strcmp(text_of((isac_sdk_string *)&copy->url), local) == 0);
    assert(memcmp(copy->remainder, r->remainder, sizeof(r->remainder)) == 0);
    before = assignments;
    assert(!isac_sdk_request_replace_url(&api, copy, production, strlen(production)));
    bad_roundtrip = 1;
    assert(!isac_sdk_request_replace_url(&api, copy, local, strlen(local)));
    bad_roundtrip = 0; unreadable_format = 1;
    assert(!isac_sdk_request_replace_url(&api, copy, local, strlen(local)));
    unreadable_format = 0; denied = 0;
    assert(assignments == before && strcmp(text_of((isac_sdk_string *)&copy->url), local) == 0);
    assert(isac_sdk_request_destroy(&api, copy));
    clone_fails = 1; assert(!isac_sdk_request_clone(&api, r)); clone_fails = 0;
    clone_aliases = 1; assert(!isac_sdk_request_clone(&api, r)); clone_aliases = 0;
    wrong_method = 1; assert(!isac_sdk_request_describe(&api, r, scratch, sizeof(scratch), &view)); wrong_method = 0;
    before = method_calls;
    tables[1].clone = NULL;
    assert(!isac_sdk_request_describe(&api, r, scratch, sizeof(scratch), &view));
    assert(!isac_sdk_request_clone(&api, r)); assert(!isac_sdk_request_destroy(&api, r));
    assert(method_calls == before); tables[1].clone = request_copy;
    r->vtable = (const isac_sdk_request_vtable *)(uintptr_t)1234;
    assert(!isac_sdk_request_clone(&api, r)); r->vtable = &tables[1];
    denied = (uintptr_t)r; assert(!isac_sdk_request_clone(&api, r)); denied = 0;

    memset(&b, 0, sizeof(b)); b.api = &api;
    adapter = isac_http_adapter_create(&binding, &b); assert(adapter);
    assert(isac_http_adapter_dispatch(adapter, &out, r, &b) == ISAC_HTTP_OK);
    assert(strcmp(out.url, local) == 0);
    bad_roundtrip = 1; /* Description now presents unsupported local route. */
    assert(isac_http_adapter_dispatch(adapter, &out, r, &b) == ISAC_HTTP_BLOCKED_ROUTE);
    bad_roundtrip = 0;
    assert(b.sends == 1 && b.failures == 1);
    assert(isac_sdk_request_destroy(&api, r));
    r = make_request(0, "https://public-ubiservices.ubi.com/v1/applications/test/configuration");
    assert(isac_http_adapter_dispatch(adapter, &out, r, &b) == ISAC_HTTP_OK);
    assert(isac_sdk_request_destroy(&api, r));
    r = make_request(2, production);
    assert(isac_sdk_request_describe(&api, r, scratch, sizeof(scratch), &view) && view.method == ISAC_HTTP_DELETE);
    assert(isac_http_adapter_dispatch(adapter, &out, r, &b) == ISAC_HTTP_OK);
    assert(isac_sdk_request_destroy(&api, r));
    isac_http_adapter_destroy(adapter); assert(b.releases == 1);
    assert(!refs_live && !strings_live && !urls_live);
    assert(range_count == 4 && deletes == clones + 3);
    puts("SDK native request bridge: x64 ABI fixtures, URL ownership and core integration passed");
    return 0;
}
