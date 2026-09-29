#include "../src/uplay_probe/sdk_http_native_result.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Synthetic Windows-x64 ABI callees. Model only observed layout/ref ownership;
 * these are not retail constructor, lock, scheduler or completion executions. */
#define FUTURE_TABLE 0x123400u
#define STATE_TABLE 0x123500u
#define RESPONSE_TABLE 0x123600u
typedef struct { unsigned int refs; char text[128]; } text_ref;
static struct { void *p; size_t length; } objects[128];
static size_t object_count;
static unsigned int strings, texts, states, responses, copies, completions, releases;
static unsigned int missing_label, missing_message, missing_state, missing_response;
static unsigned int wrong_vtable, wrong_state, wrong_code, wrong_detail, deny_read;
static int lock_marker;

static void put(void *p, size_t at, const void *value, size_t size) { memcpy((char *)p + at, value, size); }
static void put32(void *p, size_t at, uint32_t value) { put(p, at, &value, sizeof(value)); }
static void putptr(void *p, size_t at, uintptr_t value) { put(p, at, &value, sizeof(value)); }
static uint32_t u32(const void *p, size_t at) { uint32_t v; memcpy(&v, (const char *)p + at, sizeof(v)); return v; }
static text_ref *reference(const isac_sdk_string *s) { text_ref *r; memcpy(&r, s->bytes, sizeof(r)); return r; }
static void add_object(void *p, size_t length) {
    assert(object_count < sizeof(objects) / sizeof(objects[0]));
    objects[object_count].p = p; objects[object_count++].length = length;
}
static void remove_object(void *p) {
    size_t i;
    for (i = 0; i < object_count; ++i) if (objects[i].p == p) {
        objects[i] = objects[--object_count]; return;
    }
    assert(!"object released twice");
}
static int read_memory(void *unused, uintptr_t address, void *out, size_t length) {
    size_t i;
    (void)unused;
    if (deny_read || length > UINTPTR_MAX - address) return 0;
    for (i = 0; i < object_count; ++i) {
        uintptr_t base = (uintptr_t)objects[i].p;
        if (address >= base && address - base <= objects[i].length &&
            length <= objects[i].length - (address - base)) {
            memcpy(out, (void *)address, length); return 1;
        }
    }
    return 0;
}
static void *(ISAC_SDK_CALL string_make)(isac_sdk_string *s, const char *text) {
    text_ref *r = NULL;
    int absent = (missing_label && strcmp(text, "ProjectISAC::LocalHttpFailure") == 0) ||
        (missing_message && strncmp(text, "Project ISAC:", 13) == 0);
    memset(s, 0, sizeof(*s)); ++strings;
    if (!absent) {
        r = malloc(sizeof(*r)); assert(r && strlen(text) < sizeof(r->text));
        r->refs = 1; strcpy(r->text, text); ++texts;
    }
    memcpy(s->bytes, &r, sizeof(r)); return s;
}
static void release_text(text_ref *r) { if (r && --r->refs == 0) { free(r); --texts; } }
static void (ISAC_SDK_CALL string_drop)(isac_sdk_string *s) {
    release_text(reference(s)); memset(s, 0, sizeof(*s)); assert(strings); --strings;
}
static void string_copy(isac_sdk_string *to, const isac_sdk_string *from) {
    text_ref *r = reference(from); assert(r); ++r->refs;
    memset(to, 0, sizeof(*to)); memcpy(to->bytes, &r, sizeof(r)); ++strings;
}
static void string_assign(isac_sdk_string *to, const isac_sdk_string *from) {
    text_ref *r = reference(from); assert(r); ++r->refs;
    release_text(reference(to)); memcpy(to->bytes, &r, sizeof(r));
}
static void *(ISAC_SDK_CALL construct)(isac_sdk_http_future *f, const isac_sdk_string *label) {
    assert(strcmp(reference(label)->text, "ProjectISAC::LocalHttpFailure") == 0);
    memset(f, 0, sizeof(*f)); f->vtable = FUTURE_TABLE;
    if (!missing_state) {
        f->state = calloc(1, 0x130); assert(f->state); ++states; add_object(f->state, 0x130);
        putptr(f->state, 0, wrong_vtable ? 9 : STATE_TABLE); put32(f->state, 8, 1);
        string_copy((isac_sdk_string *)((char *)f->state + 0x10), label);
        string_make((isac_sdk_string *)((char *)f->state + 0x80), "N/A");
        putptr(f->state, 0xe0, (uintptr_t)&lock_marker);
    }
    if (!missing_response) {
        f->response = calloc(1, 0x98); assert(f->response); ++responses; add_object(f->response, 0x98);
        putptr(f->response, 0, RESPONSE_TABLE); put32(f->response, 8, 1);
    }
    return f;
}
static void (ISAC_SDK_CALL complete)(isac_sdk_http_future *f, const isac_sdk_error *error) {
    assert(f->vtable == FUTURE_TABLE && f->state && f->response);
    assert(u32(f->state, 0x68) == 0);
    assert(error->code == ISAC_SDK_LOCAL_RESOURCE_ERROR && error->detail == -1);
    assert(!error->padding && !error->reserved);
    assert(strncmp(reference(&error->message)->text, "Project ISAC:", 13) == 0);
    string_assign((isac_sdk_string *)((char *)f->state + 0x80), &error->message);
    put32(f->state, 0x78, wrong_code ? 0 : error->code);
    put32(f->state, 0xdc, wrong_detail ? 0 : (uint32_t)error->detail);
    put32(f->state, 0x68, wrong_state ? wrong_state - 1 : 3);
    ++completions;
}
static void *(ISAC_SDK_CALL copy_future)(isac_sdk_http_future *out, const isac_sdk_http_future *source) {
    assert(u32(source->state, 0x68) == 3); /* Nothing pending may be published. */
    *out = *source;
    put32(out->state, 8, u32(out->state, 8) + 1);
    put32(out->response, 8, u32(out->response, 8) + 1);
    ++copies; return out;
}
static void *(ISAC_SDK_CALL drop_future)(isac_sdk_http_future *f, unsigned int flags) {
    assert(flags == 0); /* All fixture wrapper storage is caller-owned. */
    if (f->response) {
        uint32_t count = u32(f->response, 8); assert(count);
        put32(f->response, 8, --count);
        if (!count) { remove_object(f->response); free(f->response); --responses; }
    }
    if (f->state) {
        uint32_t count = u32(f->state, 8); assert(count);
        put32(f->state, 8, --count);
        if (!count) {
            string_drop((isac_sdk_string *)((char *)f->state + 0x80));
            string_drop((isac_sdk_string *)((char *)f->state + 0x10));
            remove_object(f->state); free(f->state); --states;
        }
    }
    memset(f, 0, sizeof(*f)); ++releases; return f;
}
static isac_sdk_future_api api = {
    string_make, string_drop, construct, complete, copy_future, drop_future,
    read_memory, NULL, FUTURE_TABLE, STATE_TABLE, RESPONSE_TABLE
};
static void no_leaks(void) { assert(!strings && !texts && !states && !responses && !object_count); }

static void result_tests(void) {
    struct { uint64_t before; isac_sdk_http_future value; uint64_t after; } box;
    isac_sdk_http_future retained;
    isac_sdk_future_api incomplete = api;
    unsigned int reason;
    for (reason = ISAC_HTTP_INVALID_URL; reason <= ISAC_HTTP_BAD_ARGUMENT; ++reason) {
        box.before = 0x1122334455667788ull; box.after = 0x8877665544332211ull;
        memset(&box.value, 0xa5, sizeof(box.value));
        assert(isac_sdk_http_failure(&api, &box.value, (isac_http_status)reason));
        assert(box.before == 0x1122334455667788ull && box.after == 0x8877665544332211ull);
        assert(box.value.vtable == FUTURE_TABLE && u32(box.value.state, 0x68) == 3);
        assert(u32(box.value.state, 0x78) == ISAC_SDK_LOCAL_RESOURCE_ERROR);
        assert(u32(box.value.state, 0xdc) == UINT32_MAX);
        assert(u32(box.value.state, 8) == 1 && u32(box.value.response, 8) == 1);
        assert(strstr(reference((isac_sdk_string *)((char *)box.value.state + 0x80))->text, "Project ISAC:"));
        copy_future(&retained, &box.value);
        drop_future(&box.value, 0);
        assert(u32(retained.state, 0x68) == 3 && u32(retained.state, 8) == 1);
        drop_future(&retained, 0); no_leaks();
    }
    /* Cannot manufacture success, cancellation or an arbitrary native error. */
    assert(!isac_sdk_http_failure(&api, &box.value, ISAC_HTTP_OK));
    assert(!isac_sdk_http_failure(&api, &box.value, ISAC_HTTP_RESULT_FAILED));
    assert(!isac_sdk_http_failure(&api, &box.value, (isac_http_status)999));
    assert(!isac_sdk_http_failure(NULL, &box.value, ISAC_HTTP_SEND_FAILED));
    assert(!isac_sdk_http_failure(&api, NULL, ISAC_HTTP_SEND_FAILED));
    incomplete.future_complete = NULL;
    assert(!isac_sdk_http_failure(&incomplete, &box.value, ISAC_HTTP_SEND_FAILED));
    no_leaks();
    {
        unsigned int *faults[] = {&missing_label, &missing_message, &missing_state,
            &missing_response, &wrong_vtable, &wrong_state, &wrong_code, &wrong_detail, &deny_read};
        size_t i;
        for (i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i) {
            unsigned int copies_before = copies;
            unsigned char untouched[sizeof(box.value)];
            memset(untouched, 0xa5, sizeof(untouched)); memcpy(&box.value, untouched, sizeof(untouched));
            *faults[i] = 1;
            assert(!isac_sdk_http_failure(&api, &box.value, ISAC_HTTP_BLOCKED_ROUTE));
            *faults[i] = 0;
            assert(memcmp(&box.value, untouched, sizeof(untouched)) == 0);
            assert(copies == copies_before); no_leaks();
        }
        /* Success/cancel terminal states must not pass as failed results. */
        for (wrong_state = 3; wrong_state <= 5; wrong_state += 2) {
            assert(!isac_sdk_http_failure(&api, &box.value, ISAC_HTTP_BLOCKED_ROUTE)); no_leaks();
        }
        wrong_state = 0;
    }
}

/* Integrates the actual failure binding with the core; no mock failure callback.
 * Request description is a fixture; no native request/HTTP transport is run. */
static int describe(void *p, const void *r, char *scratch, size_t cap, isac_http_request_view *view) {
    const char *url = "https://public-ubiservices.ubi.com/v1/unsupported";
    (void)p; (void)r; assert(strlen(url) < cap); strcpy(scratch, url);
    view->method = ISAC_HTTP_GET; view->url = scratch; view->url_length = strlen(scratch); return 1;
}
static void *never_clone(void *p, const void *r) { (void)p; (void)r; assert(0); return NULL; }
static int never_replace(void *p, void *r, const char *s, size_t n) { (void)p; (void)r; (void)s; (void)n; assert(0); return 0; }
static int never_send(void *p, void *o, const void *r, const void *opts) { (void)p; (void)o; (void)r; (void)opts; assert(0); return 0; }
static void never_destroy(void *p, void *r) { (void)p; (void)r; assert(0); }
static int fail_result(void *p, void *o, isac_http_status reason) { return isac_sdk_http_failure(p, o, reason); }
static void release_context(void *p) { assert(p == &api); }
static void core_tests(void) {
    isac_http_binding binding = {describe, never_clone, never_replace, never_send, never_destroy, fail_result, release_context};
    isac_http_adapter *adapter = isac_http_adapter_create(&binding, &api);
    isac_sdk_http_future out;
    unsigned char expected[sizeof(out)];
    int request = 1;
    assert(adapter);
    assert(isac_http_adapter_dispatch(adapter, &out, &request, NULL) == ISAC_HTTP_BLOCKED_ROUTE);
    assert(u32(out.state, 0x68) == 3); drop_future(&out, 0); no_leaks();
    memset(expected, 0x5a, sizeof(expected)); memcpy(&out, expected, sizeof(out));
    wrong_state = 1;
    assert(isac_http_adapter_dispatch(adapter, &out, &request, NULL) == ISAC_HTTP_RESULT_FAILED);
    assert(memcmp(&out, expected, sizeof(out)) == 0);
    wrong_state = 0; no_leaks(); isac_http_adapter_destroy(adapter);
}
int main(void) {
    result_tests(); core_tests();
    assert(completions && copies && releases);
    puts("SDK native failure result: terminal state, ownership and adapter integration passed");
    return 0;
}
