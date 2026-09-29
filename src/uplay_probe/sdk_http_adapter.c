#include "sdk_http_adapter.h"

#include <stdlib.h>
#include <string.h>

struct isac_http_adapter {
    isac_http_binding binding;
    void *context;
};

static int equals(const char *value, size_t size, const char *literal) {
    return size == strlen(literal) && memcmp(value, literal, size) == 0;
}

static int is_hex(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F');
}

static int is_app_id(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') || c == '-';
}

static int supported_path(isac_http_method method, const char *path, size_t size) {
    size_t i = 2, digits = 0, start;
    const char applications[] = "/applications/";
    if (size < 4 || path[0] != '/' || path[1] != 'v') return 0;
    while (i < size && path[i] >= '0' && path[i] <= '9') {
        ++i;
        ++digits;
    }
    if (digits < 1 || digits > 3) return 0;
    if (equals(path + i, size - i, "/profiles/sessions"))
        return method == ISAC_HTTP_POST || method == ISAC_HTTP_DELETE;
    if (method != ISAC_HTTP_GET || size - i < sizeof(applications) - 1 ||
        memcmp(path + i, applications, sizeof(applications) - 1) != 0) return 0;
    i += sizeof(applications) - 1;
    start = i;
    while (i < size && is_app_id((unsigned char)path[i])) ++i;
    return i - start >= 1 && i - start <= 64 &&
        equals(path + i, size - i, "/configuration");
}

isac_http_status isac_http_route(isac_http_method method,
    const char *url, size_t length, char *output, size_t capacity) {
    size_t i, origin_end, path_end, suffix_length;
    const char local[] = ISAC_HTTP_LOCAL_ORIGIN;
    if (!url || !output) return ISAC_HTTP_BAD_ARGUMENT;
    if (!length || length > ISAC_HTTP_URL_LIMIT) return ISAC_HTTP_INVALID_URL;
    /* ASCII canonical URLs only. Path escapes are excluded by route grammar;
     * query escapes are preserved verbatim but must be well formed. Reject
     * literal control bytes, fragments and backslash parser ambiguities. */
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)url[i];
        if (c <= 0x20 || c >= 0x7f || c == '#' || c == '\\')
            return ISAC_HTTP_INVALID_URL;
        if (c == '%') {
            if (length - i < 3 || !is_hex((unsigned char)url[i + 1]) ||
                !is_hex((unsigned char)url[i + 2])) return ISAC_HTTP_INVALID_URL;
            i += 2;
        }
    }
    /* Find the first slash after the literal scheme separator. */
    for (i = 0; i + 2 < length; ++i)
        if (url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/') break;
    if (i + 2 >= length) return ISAC_HTTP_INVALID_URL;
    origin_end = i + 3;
    while (origin_end < length && url[origin_end] != '/') ++origin_end;
    if (!equals(url, origin_end, "https://public-ubiservices.ubi.com") &&
        !equals(url, origin_end, "https://public-ubiservices.ubi.com:443") &&
        !equals(url, origin_end, local)) return ISAC_HTTP_BLOCKED_ORIGIN;
    path_end = origin_end;
    while (path_end < length && url[path_end] != '?') ++path_end;
    if (!supported_path(method, url + origin_end, path_end - origin_end))
        return ISAC_HTTP_BLOCKED_ROUTE;
    suffix_length = length - origin_end;
    /* Checked length <= 4096, so this addition cannot wrap size_t. */
    if (capacity < sizeof(local) + suffix_length) return ISAC_HTTP_BUFFER_SMALL;
    memcpy(output, local, sizeof(local) - 1);
    memcpy(output + sizeof(local) - 1, url + origin_end, suffix_length);
    output[sizeof(local) - 1 + suffix_length] = '\0';
    return ISAC_HTTP_OK;
}

isac_http_adapter *isac_http_adapter_create(const isac_http_binding *binding, void *context) {
    isac_http_adapter *adapter;
    if (!binding || !binding->describe || !binding->clone || !binding->replace_url ||
        !binding->send_local || !binding->destroy_request || !binding->fail ||
        !binding->release_context) return NULL;
    adapter = (isac_http_adapter *)malloc(sizeof(*adapter));
    if (!adapter) return NULL;
    adapter->binding = *binding;
    adapter->context = context;
    return adapter;
}

isac_http_status isac_http_adapter_dispatch(isac_http_adapter *adapter,
    void *output, const void *request, const void *options) {
    char destination[ISAC_HTTP_URL_LIMIT + sizeof(ISAC_HTTP_LOCAL_ORIGIN)];
    char source[ISAC_HTTP_URL_LIMIT + 1];
    isac_http_request_view view = {ISAC_HTTP_OTHER, NULL, 0};
    isac_http_status status;
    void *copy = NULL;
    const isac_http_binding *binding;
    if (!adapter || !output) return ISAC_HTTP_BAD_ARGUMENT;
    binding = &adapter->binding;
    if (!request) {
        status = ISAC_HTTP_BAD_ARGUMENT;
    } else if (!binding->describe(adapter->context, request, source, sizeof(source), &view)) {
        status = ISAC_HTTP_DESCRIBE_FAILED;
    } else {
        status = isac_http_route(view.method, view.url, view.url_length,
            destination, sizeof(destination));
        if (status == ISAC_HTTP_OK) {
            copy = binding->clone(adapter->context, request);
            if (!copy || copy == request) {
                /* Never destroy an alias to the caller's borrowed request. */
                copy = NULL;
                status = ISAC_HTTP_CLONE_FAILED;
            } else if (!binding->replace_url(adapter->context, copy,
                           destination, strlen(destination))) {
                status = ISAC_HTTP_REBUILD_FAILED;
            } else if (!binding->send_local(adapter->context, output, copy, options)) {
                status = ISAC_HTTP_SEND_FAILED;
            }
        }
    }
    if (copy) binding->destroy_request(adapter->context, copy);
    if (status != ISAC_HTTP_OK && !binding->fail(adapter->context, output, status))
        return ISAC_HTTP_RESULT_FAILED;
    return status;
}

void isac_http_adapter_destroy(isac_http_adapter *adapter) {
    if (adapter) {
        adapter->binding.release_context(adapter->context);
        free(adapter);
    }
}
