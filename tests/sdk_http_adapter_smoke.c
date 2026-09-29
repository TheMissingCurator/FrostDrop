#include "../src/uplay_probe/sdk_http_adapter.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SESSION "https://public-ubiservices.ubi.com/v3/profiles/sessions"
#define CONFIG "https://public-ubiservices.ubi.com/v1/applications/abc-123/configuration"
#define LOCAL_SESSION ISAC_HTTP_LOCAL_ORIGIN "/v3/profiles/sessions"

static void policy_tests(void) {
    struct test_case { isac_http_method method; const char *url; isac_http_status status; };
    const struct test_case cases[] = {
        {ISAC_HTTP_POST, SESSION, ISAC_HTTP_OK},
        {ISAC_HTTP_DELETE, SESSION, ISAC_HTTP_OK},
        {ISAC_HTTP_GET, CONFIG, ISAC_HTTP_OK},
        {ISAC_HTTP_POST, LOCAL_SESSION, ISAC_HTTP_OK},
        {ISAC_HTTP_GET, ISAC_HTTP_LOCAL_ORIGIN "/v1/applications/abc-123/configuration", ISAC_HTTP_OK},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com:443/v001/profiles/sessions?q=a%2Fb&next=https://outside.invalid", ISAC_HTTP_OK},
        {ISAC_HTTP_GET, SESSION, ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, CONFIG, ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_OTHER, SESSION, ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_DELETE, CONFIG, ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com/v1000/profiles/sessions", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com/v/profiles/sessions", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, SESSION "/", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, SESSION ";x", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, SESSION "#fragment", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, SESSION "?q=%", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, SESSION "?q=%2", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, SESSION "?q=%2g", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, SESSION "?q=hello world", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, SESSION "?q=\r\nHost:outside", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, SESSION "?q=\\outside", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com/%763/profiles/sessions", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com/v3/../profiles/sessions", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_GET, "https://public-ubiservices.ubi.com/v1/applications//configuration", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_GET, "https://public-ubiservices.ubi.com/v1/applications/a_b/configuration", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_GET, "https://public-ubiservices.ubi.com/v1/applications/a%2Fb/configuration", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_GET, "https://public-ubiservices.ubi.com/v1/remotelog", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com", ISAC_HTTP_BLOCKED_ROUTE},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com.evil/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "https://evilpublic-ubiservices.ubi.com/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com@evil/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "https://user:pass@public-ubiservices.ubi.com/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com./v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "https://PUBLIC-UBISERVICES.UBI.COM/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "https://uat-public-ubiservices.ubi.com/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "http://public-ubiservices.ubi.com/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "https://public-ubiservices.ubi.com:444/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "http://127.0.0.1:55004/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "http://localhost:55003/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "http://[::1]:55003/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "http://2130706433:55003/v3/profiles/sessions", ISAC_HTTP_BLOCKED_ORIGIN},
        {ISAC_HTTP_POST, "/v3/profiles/sessions", ISAC_HTTP_INVALID_URL},
        {ISAC_HTTP_POST, "", ISAC_HTTP_INVALID_URL}
    };
    char output[ISAC_HTTP_URL_LIMIT + 64], again[sizeof(output)];
    char huge[ISAC_HTTP_URL_LIMIT + 2], app[256];
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        strcpy(output, "untouched");
        assert(isac_http_route(cases[i].method, cases[i].url, strlen(cases[i].url),
            output, sizeof(output)) == cases[i].status);
        if (cases[i].status == ISAC_HTTP_OK) {
            assert(strncmp(output, ISAC_HTTP_LOCAL_ORIGIN "/", sizeof(ISAC_HTTP_LOCAL_ORIGIN)) == 0);
            assert(isac_http_route(cases[i].method, output, strlen(output), again, sizeof(again)) == ISAC_HTTP_OK);
            assert(strcmp(output, again) == 0); /* Already-local is idempotent. */
        } else assert(strcmp(output, "untouched") == 0);
    }
    assert(isac_http_route(ISAC_HTTP_POST, SESSION "?q=a%2Fb&x=secret", strlen(SESSION "?q=a%2Fb&x=secret"), output, sizeof(output)) == ISAC_HTTP_OK);
    assert(strcmp(output, LOCAL_SESSION "?q=a%2Fb&x=secret") == 0);
    strcpy(output, "untouched");
    assert(isac_http_route(ISAC_HTTP_POST, SESSION, strlen(SESSION), output, sizeof(LOCAL_SESSION) - 1) == ISAC_HTTP_BUFFER_SMALL);
    assert(strcmp(output, "untouched") == 0);
    assert(isac_http_route(ISAC_HTTP_POST, SESSION, strlen(SESSION), output, sizeof(LOCAL_SESSION)) == ISAC_HTTP_OK);
    assert(isac_http_route(ISAC_HTTP_POST, SESSION, strlen(SESSION), output, 0) == ISAC_HTTP_BUFFER_SMALL);
    assert(isac_http_route(ISAC_HTTP_POST, NULL, 1, output, sizeof(output)) == ISAC_HTTP_BAD_ARGUMENT);
    assert(isac_http_route(ISAC_HTTP_POST, SESSION, strlen(SESSION), NULL, 0) == ISAC_HTTP_BAD_ARGUMENT);
    /* Includes a terminating NUL in the length-delimited input. */
    assert(isac_http_route(ISAC_HTTP_POST, SESSION, sizeof(SESSION), output, sizeof(output)) == ISAC_HTTP_INVALID_URL);
    memset(huge, 'a', sizeof(huge));
    memcpy(huge, SESSION "?q=", strlen(SESSION "?q="));
    assert(isac_http_route(ISAC_HTTP_POST, huge, ISAC_HTTP_URL_LIMIT, output, sizeof(output)) == ISAC_HTTP_OK);
    assert(isac_http_route(ISAC_HTTP_POST, huge, ISAC_HTTP_URL_LIMIT + 1, output, sizeof(output)) == ISAC_HTTP_INVALID_URL);
    for (i = 64; i <= 65; ++i) {
        size_t start = strlen("https://public-ubiservices.ubi.com/v1/applications/");
        strcpy(app, "https://public-ubiservices.ubi.com/v1/applications/");
        memset(app + start, 'a', i);
        strcpy(app + start + i, "/configuration");
        assert(isac_http_route(ISAC_HTTP_GET, app, strlen(app), output, sizeof(output)) ==
            (i == 64 ? ISAC_HTTP_OK : ISAC_HTTP_BLOCKED_ROUTE));
    }
    /* Deterministic bounded malformed-input sweep; sanitizer exercises parser
     * bounds with non-NUL-terminated buffers and small output capacities. */
    {
        unsigned int seed = 12345;
        char bytes[128];
        for (i = 0; i < 10000; ++i) {
            size_t j, length = i % sizeof(bytes);
            for (j = 0; j < length; ++j) {
                seed = seed * 1664525u + 1013904223u;
                bytes[j] = (char)(seed >> 24);
            }
            (void)isac_http_route(ISAC_HTTP_POST, bytes, length, output, i % sizeof(output));
        }
    }
}

typedef struct {
    isac_http_method method;
    char url[ISAC_HTTP_URL_LIMIT + 1];
    char body[64], headers[64];
    unsigned int subtype, flags;
} request;

typedef struct {
    unsigned int clones, drops, sends, failures, releases;
    int fail_describe, fail_clone, alias_clone, fail_replace, fail_send;
    const void *expected_options;
} context;

typedef struct {
    request *queued; /* Send's own copy, never the adapter's temporary clone. */
    isac_http_status status;
} result;

static int describe(void *opaque, const void *borrowed, char *scratch,
                    size_t capacity, isac_http_request_view *view) {
    context *c = opaque;
    const request *r = borrowed;
    if (c->fail_describe) return 0;
    assert(strlen(r->url) < capacity);
    strcpy(scratch, r->url);
    view->method = r->method;
    view->url = scratch;
    view->url_length = strlen(r->url);
    return 1;
}

static void *clone_request(void *opaque, const void *borrowed) {
    context *c = opaque;
    request *copy;
    if (c->alias_clone) return (void *)borrowed;
    if (c->fail_clone) return NULL;
    copy = malloc(sizeof(*copy));
    assert(copy);
    memcpy(copy, borrowed, sizeof(*copy));
    ++c->clones;
    return copy;
}

static int replace_url(void *opaque, void *owned, const char *url, size_t length) {
    context *c = opaque;
    request *r = owned;
    if (c->fail_replace) return 0;
    assert(length < sizeof(r->url));
    memcpy(r->url, url, length);
    r->url[length] = '\0';
    return 1;
}

static int send_local(void *opaque, void *destination, const void *owned, const void *options) {
    context *c = opaque;
    const request *r = owned;
    result *out = destination;
    assert(options == c->expected_options);
    assert(strncmp(r->url, ISAC_HTTP_LOCAL_ORIGIN "/", sizeof(ISAC_HTTP_LOCAL_ORIGIN)) == 0);
    ++c->sends;
    if (c->fail_send) return 0;
    assert(!out->queued);
    out->queued = malloc(sizeof(*out->queued));
    assert(out->queued);
    memcpy(out->queued, r, sizeof(*r));
    out->status = ISAC_HTTP_OK;
    return 1;
}

static void drop(void *opaque, void *owned) {
    context *c = opaque;
    ++c->drops;
    free(owned);
}

static int fail(void *opaque, void *destination, isac_http_status reason) {
    context *c = opaque;
    result *out = destination;
    assert(!out->queued);
    ++c->failures;
    out->status = reason;
    return 1;
}

static void release(void *opaque) {
    context *c = opaque;
    ++c->releases;
    assert(c->clones == c->drops);
}

static const isac_http_binding binding = {
    describe, clone_request, replace_url, send_local, drop, fail, release
};

static void adapter_tests(void) {
    context c = {0}, next = {0};
    request r = {ISAC_HTTP_POST, SESSION, "body-secret", "header-secret", 123, 456};
    request saved = r;
    result out = {NULL, ISAC_HTTP_BAD_ARGUMENT};
    int options = 789;
    isac_http_adapter *a, *b;
    isac_http_binding incomplete = binding;
    incomplete.fail = NULL;
    assert(!isac_http_adapter_create(&incomplete, &c));
    assert(!isac_http_adapter_create(NULL, &c));
    assert(c.releases == 0); /* Failed construction does not take ownership. */
    a = isac_http_adapter_create(&binding, &c);
    assert(a);
    c.expected_options = &options;
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_OK);
    assert(c.clones == 1 && c.drops == 1 && c.sends == 1 && c.failures == 0);
    assert(memcmp(&r, &saved, sizeof(r)) == 0);
    assert(out.queued && strcmp(out.queued->url, LOCAL_SESSION) == 0);
    assert(strcmp(out.queued->body, saved.body) == 0);
    assert(strcmp(out.queued->headers, saved.headers) == 0);
    assert(out.queued->subtype == 123 && out.queued->flags == 456);
    assert(out.queued->method == saved.method);
    free(out.queued);
    out.queued = NULL;

    /* Newly materialized requests after descriptor replacement use the same
     * adapter: no remembered descriptor address or first-URL-only behavior. */
    r.method = ISAC_HTTP_GET;
    strcpy(r.url, CONFIG);
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_OK);
    free(out.queued); out.queued = NULL;
    strcpy(r.url, ISAC_HTTP_LOCAL_ORIGIN "/v1/applications/changed/configuration");
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_OK);
    assert(strcmp(out.queued->url, r.url) == 0);
    free(out.queued); out.queued = NULL;
    strcpy(r.url, "https://outside.invalid/v1/applications/changed/configuration");
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_BLOCKED_ORIGIN);
    assert(out.status == ISAC_HTTP_BLOCKED_ORIGIN && c.sends == 3 && c.clones == 3);
    r = saved;
    c.fail_describe = 1;
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_DESCRIBE_FAILED);
    c.fail_describe = 0; c.fail_clone = 1;
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_CLONE_FAILED);
    c.fail_clone = 0; c.alias_clone = 1;
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_CLONE_FAILED);
    c.alias_clone = 0; c.fail_replace = 1;
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_REBUILD_FAILED);
    c.fail_replace = 0; c.fail_send = 1;
    assert(isac_http_adapter_dispatch(a, &out, &r, &options) == ISAC_HTTP_SEND_FAILED);
    c.fail_send = 0;
    assert(c.clones == c.drops && c.failures == 6 && c.sends == 4);
    assert(memcmp(&r, &saved, sizeof(r)) == 0);
    assert(isac_http_adapter_dispatch(a, &out, NULL, &options) == ISAC_HTTP_BAD_ARGUMENT);
    assert(c.failures == 7 && out.status == ISAC_HTTP_BAD_ARGUMENT);
    assert(isac_http_adapter_dispatch(NULL, &out, &r, &options) == ISAC_HTTP_BAD_ARGUMENT);
    assert(isac_http_adapter_dispatch(a, NULL, &r, &options) == ISAC_HTTP_BAD_ARGUMENT);
    assert(c.failures == 7);

    /* Independent instance/epoch and binding copied by value. No singleton. */
    incomplete = binding;
    b = isac_http_adapter_create(&incomplete, &next);
    incomplete.send_local = NULL;
    assert(b);
    assert(isac_http_adapter_dispatch(b, &out, &r, NULL) == ISAC_HTTP_OK);
    isac_http_adapter_destroy(a);
    isac_http_adapter_destroy(b);
    assert(c.releases == 1 && next.releases == 1);
    /* Mock transport retains its own request independently of the adapter. */
    assert(strcmp(out.queued->url, LOCAL_SESSION) == 0);
    free(out.queued);
    isac_http_adapter_destroy(NULL);
}

int main(void) {
    policy_tests();
    adapter_tests();
    puts("SDK HTTP adapter core: policy, ownership, failures and lifecycle passed");
    return 0;
}
