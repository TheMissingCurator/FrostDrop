#ifndef ISAC_SDK_HTTP_NATIVE_RESULT_H
#define ISAC_SDK_HTTP_NATIVE_RESULT_H

#include "sdk_http_native_request.h"

/* Observed HTTP future wrapper returned by dispatch (not a single pointer). */
typedef struct {
    uintptr_t vtable;
    void *state;
    void *response;
} isac_sdk_http_future;

/* Error layout consumed by 0x21e3640 -> 0x21e3720. The completion routine
 * reads code, message and detail. Reserved fields are zeroed, not interpreted. */
typedef struct {
    uint32_t code, padding;
    isac_sdk_string message;
    uint32_t reserved;
    int32_t detail;
} isac_sdk_error;

/* Observed on RemoteLogger's missing-resource early failure. Reused as the
 * adapter's local resource-unavailable classification; NOT a claim that this
 * is an official SDK enum name or a Win32/HTTP error number. */
#define ISAC_SDK_LOCAL_RESOURCE_ERROR 0x0f01u

typedef struct {
    void *(ISAC_SDK_CALL *string_from_utf8)(isac_sdk_string *, const char *);
    void (ISAC_SDK_CALL *string_destroy)(isac_sdk_string *);
    void *(ISAC_SDK_CALL *future_construct)(isac_sdk_http_future *, const isac_sdk_string *label);
    void (ISAC_SDK_CALL *future_complete)(isac_sdk_http_future *, const isac_sdk_error *);
    void *(ISAC_SDK_CALL *future_copy)(isac_sdk_http_future *, const isac_sdk_http_future *);
    void *(ISAC_SDK_CALL *future_destroy)(isac_sdk_http_future *, unsigned int flags);
    int (*read)(void *context, uintptr_t address, void *output, size_t length);
    void *read_context;
    uintptr_t future_vtable, state_vtable, response_vtable;
} isac_sdk_future_api;

/* API pointers and runtime vtable addresses must be independently verified.
 * No resolver/installer is provided; this module is not linked into the probe.
 * output MUST be fresh uninitialized SDK return storage, not an existing future.
 * 1: output owns a completed failure and must later be destroyed by the SDK.
 * 0: output untouched, all normally constructed temporaries destroyed. A native
 * boundary must stop on 0; it cannot return to the game with uninitialized output.
 * No networking, queuing, payload copying or credential logging.
 * Normal-return safety only: native exceptions/allocation faults are NOT caught.
 */
int isac_sdk_http_failure(const isac_sdk_future_api *api,
    isac_sdk_http_future *output, isac_http_status reason);

#endif
