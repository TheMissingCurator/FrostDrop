#include "sdk_http_native_result.h"
#include <string.h>

_Static_assert(sizeof(isac_sdk_http_future) == 0x18, "HTTP future size");
_Static_assert(offsetof(isac_sdk_http_future, state) == 8, "future state");
_Static_assert(offsetof(isac_sdk_http_future, response) == 16, "future response");
_Static_assert(sizeof(isac_sdk_error) == 0x68, "SDK error size");
_Static_assert(offsetof(isac_sdk_error, message) == 8, "error message");
_Static_assert(offsetof(isac_sdk_error, detail) == 0x64, "error detail");

static const char *reason_text(isac_http_status reason) {
    switch (reason) {
        case ISAC_HTTP_INVALID_URL: return "Project ISAC: invalid local HTTP URL";
        case ISAC_HTTP_BLOCKED_ORIGIN: return "Project ISAC: external HTTP origin blocked";
        case ISAC_HTTP_BLOCKED_ROUTE: return "Project ISAC: unsupported local HTTP route";
        case ISAC_HTTP_BUFFER_SMALL: return "Project ISAC: HTTP URL capacity exceeded";
        case ISAC_HTTP_DESCRIBE_FAILED: return "Project ISAC: HTTP request description failed";
        case ISAC_HTTP_CLONE_FAILED: return "Project ISAC: HTTP request clone failed";
        case ISAC_HTTP_REBUILD_FAILED: return "Project ISAC: HTTP URL reconstruction failed";
        case ISAC_HTTP_SEND_FAILED: return "Project ISAC: local HTTP transport unavailable";
        case ISAC_HTTP_BAD_ARGUMENT: return "Project ISAC: invalid HTTP adapter argument";
        default: return NULL; /* Never turn OK/RESULT_FAILED/unknown into success. */
    }
}

static int read_at(const isac_sdk_future_api *api, const void *p, size_t offset,
                   void *out, size_t length) {
    uintptr_t base = (uintptr_t)p;
    if (!base || offset > UINTPTR_MAX - base || length > UINTPTR_MAX - (base + offset)) return 0;
    return api->read(api->read_context, base + offset, out, length);
}

static int owned_object(const isac_sdk_future_api *api, const void *p, uintptr_t expected) {
    uintptr_t table;
    int32_t count;
    return read_at(api, p, 0, &table, sizeof(table)) && table == expected &&
        read_at(api, p, 8, &count, sizeof(count)) && count > 0;
}

static int future_shape(const isac_sdk_future_api *api, const isac_sdk_http_future *future,
                        uint32_t expected_state) {
    uint32_t state;
    uintptr_t lock;
    return future->vtable == api->future_vtable &&
        owned_object(api, future->state, api->state_vtable) &&
        owned_object(api, future->response, api->response_vtable) &&
        read_at(api, future->state, 0xe0, &lock, sizeof(lock)) && lock &&
        read_at(api, future->state, 0x68, &state, sizeof(state)) && state == expected_state;
}

static int has_string_reference(const isac_sdk_string *string) {
    uintptr_t reference;
    memcpy(&reference, string->bytes, sizeof(reference));
    return reference != 0;
}

int isac_sdk_http_failure(const isac_sdk_future_api *api,
    isac_sdk_http_future *output, isac_http_status reason) {
    const char *message = reason_text(reason);
    isac_sdk_string label;
    isac_sdk_http_future pending;
    isac_sdk_error error = {0};
    uint32_t code;
    int32_t detail;
    int complete = 0;
    if (!api || !output || !message || !api->string_from_utf8 || !api->string_destroy ||
        !api->future_construct || !api->future_complete || !api->future_copy ||
        !api->future_destroy || !api->read || !api->future_vtable ||
        !api->state_vtable || !api->response_vtable) return 0;

    api->string_from_utf8(&label, "ProjectISAC::LocalHttpFailure");
    if (!has_string_reference(&label)) {
        api->string_destroy(&label);
        return 0;
    }
    /* Native ctor creates both owned allocations, including synchronization and
     * a real default HTTP response. Its returned pointer is not a status bool. */
    api->future_construct(&pending, &label);
    api->string_destroy(&label);
    if (future_shape(api, &pending, 0u)) {
        error.code = ISAC_SDK_LOCAL_RESOURCE_ERROR;
        error.detail = -1;
        api->string_from_utf8(&error.message, message);
        if (has_string_reference(&error.message)) {
            /* Synchronized native completion: do not write the state fields. */
            api->future_complete(&pending, &error);
            complete = future_shape(api, &pending, 3u) &&
                read_at(api, pending.state, 0x78, &code, sizeof(code)) && code == error.code &&
                read_at(api, pending.state, 0xdc, &detail, sizeof(detail)) && detail == error.detail;
        }
        api->string_destroy(&error.message);
    }
    /* Copy construction retains both references BEFORE stack temporary release.
     * Publish only a verified terminal failure; never a pending/null future. */
    if (complete) api->future_copy(output, &pending);
    api->future_destroy(&pending, 0u); /* Release members, not stack storage. */
    return complete;
}
