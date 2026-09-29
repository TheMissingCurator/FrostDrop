#ifndef ISAC_SDK_HTTP_ADAPTER_H
#define ISAC_SDK_HTTP_ADAPTER_H

#include <stddef.h>

/* Portable adapter core, NOT a retail SDK vtable/layout. No live installer.
 * A verified native binding must translate every callback below. In particular,
 * these method values are semantic labels, not reverse-engineered ABI values.
 */
#define ISAC_HTTP_URL_LIMIT 4096u
#define ISAC_HTTP_LOCAL_ORIGIN "http://127.0.0.1:55003"

typedef enum {
    ISAC_HTTP_GET, ISAC_HTTP_POST, ISAC_HTTP_DELETE, ISAC_HTTP_OTHER
} isac_http_method;

typedef enum {
    ISAC_HTTP_OK,
    ISAC_HTTP_INVALID_URL,
    ISAC_HTTP_BLOCKED_ORIGIN,
    ISAC_HTTP_BLOCKED_ROUTE,
    ISAC_HTTP_BUFFER_SMALL,
    ISAC_HTTP_DESCRIBE_FAILED,
    ISAC_HTTP_CLONE_FAILED,
    ISAC_HTTP_REBUILD_FAILED,
    ISAC_HTTP_SEND_FAILED,
    ISAC_HTTP_BAD_ARGUMENT,
    ISAC_HTTP_RESULT_FAILED /* No valid output: native boundary must stop. */
} isac_http_status;

/* Exact supported production/local origins and backend route grammar only.
 * url is length-delimited; embedded NULs are rejected. Output is NUL-terminated
 * on success and untouched on failure. Input/output storage must not overlap.
 * No DNS, logging, fallback, credentials processing or networking occurs here.
 */
isac_http_status isac_http_route(isac_http_method method,
    const char *url, size_t length, char *output, size_t capacity);

typedef struct {
    isac_http_method method;
    const char *url;
    size_t url_length;
} isac_http_request_view;

typedef struct {
    /* Copy the formatted typed URL into per-dispatch scratch and point view.url
     * there (or use other storage valid through dispatch). No shared scratch,
     * retained stack pointers, request mutation or secret logging. */
    int (*describe)(void *context, const void *request, char *scratch,
        size_t capacity, isac_http_request_view *view);
    /* Independent owned clone: preserve subtype, method, headers/body/flags.
     * Must not return request itself. Clone owns any retained SDK references. */
    void *(*clone)(void *context, const void *request);
    /* Parse a fresh typed URL, replace clone's old value with correct SDK
     * ownership. On failure the clone must remain safe to destroy. The URL
     * argument is borrowed only for this call; never retain its stack pointer. */
    int (*replace_url)(void *context, void *clone, const char *url, size_t length);
    /* Must verify loopback-only transport and disable/block external redirects.
     * Success publishes a normal SDK async result to output and takes any
     * references required after return. Failure publishes nothing, retains
     * nothing, and has no pending work. Request/options are borrowed for call.
     * A raw retail send is NOT a verified implementation of this contract yet. */
    int (*send_local)(void *context, void *output, const void *clone, const void *options);
    void (*destroy_request)(void *context, void *clone);
    /* Construct a completed failed async result in FRESH output storage.
     * Return 1 only with a valid output. Return 0 with output untouched if
     * construction/verification fails. Never publish a pending/null placeholder.
     * RESULT_FAILED is fatal to dispatch: a native boundary must not resume
     * its caller with uninitialized output or try an external fallback. */
    int (*fail)(void *context, void *output, isac_http_status reason);
    /* Destroy original service/context exactly once at adapter teardown. */
    void (*release_context)(void *context);
} isac_http_binding;

typedef struct isac_http_adapter isac_http_adapter;

/* Copies binding. Transfers ownership of context ONLY on successful creation.
 * Allocated by this module; never pass it to an SDK deleting destructor.
 * Not safe to cast to a native interface or publish in wrapper+0x10.
 */
isac_http_adapter *isac_http_adapter_create(const isac_http_binding *binding, void *context);

/* Requires a live adapter and fresh, uninitialized output storage. With those present,
 * all rejected requests complete through fail(), including NULL request.
 * Options/output identities are passed through, never copied or retained here.
 * Core has no mutable dispatch state. Concurrent calls require thread-safe
 * binding callbacks. Owner must exclude teardown until all calls have returned.
 */
isac_http_status isac_http_adapter_dispatch(isac_http_adapter *adapter,
    void *output, const void *request, const void *options);

/* Owner must quiesce dispatch first; native service must handle queued work's
 * lifetime. Frees adapter, so it must not be reused. NULL is permitted. */
void isac_http_adapter_destroy(isac_http_adapter *adapter);

#endif
